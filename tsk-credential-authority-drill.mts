import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';

import { generateTumblerMap } from './packages/core/dist/index.js';
import {
  NodePostgresTransactor, PgHaTumblerMapStore, PgTskCredentialReceiverCheckpoint,
  StreamHeadVerificationUnavailableError,
  TSK_CREDENTIAL_AUTHORITY_SCHEMA, TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA,
  assertSourceFenceReady, installLeaseGrant,
  assertCredentialAuthorityReady, provisionSchemaVersion, signLeaseGrant,
} from './packages/server/dist/index.js';
import { Pool } from 'pg';

const urlA = process.env.TSK_TEST_POSTGRES_URL_A ?? process.env.TSK_TEST_POSTGRES_URL;
const urlB = process.env.TSK_TEST_POSTGRES_URL_B;
if (!urlA || !urlB) throw new Error('TSK_TEST_POSTGRES_URL_A/_B are required (this drill never skips)');
const SID = `tsk-credential-${Date.now()}`, EPOCH = 1;
const sourceKeys = generateKeyPairSync('ed25519'), guardKeys = generateKeyPairSync('ed25519');
const leaseResolver = { resolve: (keyId: string) => keyId === 'guard-1' ? guardKeys.publicKey : null };
let verifierUnavailable = false;
const headVerifier = { verify: async (head: { keyId: string; alg: string; headDigest: string; signature: string }) => {
  if (verifierUnavailable) throw new StreamHeadVerificationUnavailableError('test key service unavailable');
  if (head.keyId !== 'source-1' || head.alg !== 'ed25519' ||
      !verify(null, Buffer.from(head.headDigest, 'hex'), sourceKeys.publicKey,
        Buffer.from(head.signature, 'base64url'))) throw new Error('invalid head signature');
} };
const signer = { keyId: 'source-1', alg: 'ed25519' as const,
  sign: async (headDigest: string) => sign(null, Buffer.from(headDigest, 'hex'), sourceKeys.privateKey)
    .toString('base64url') };

async function reset(pool: Pool) {
  await pool.query(`DROP TABLE IF EXISTS
    tsk_credential_replica_maps,tsk_credential_maps,tsk_source_lease_history,tsk_source_lease,
    tsk_outbox_stream_halted,tsk_outbox_quarantine,tsk_outbox_applied,tsk_hotp_consumed,
    tsk_outbox_publisher_lease,tsk_outbox_rows,tsk_outbox_receiver_checkpoint,
    tsk_outbox_source_checkpoint,tsk_outbox_fence,tsk_outbox_meta CASCADE`);
}
async function provision(pool: Pool, receiver: boolean) {
  const db = new NodePostgresTransactor(pool as never, { maxSerializationRetries: 2 });
  await pool.query(TSK_OUTBOX_PG_SCHEMA);
  const ready = await provisionSchemaVersion(db, 'public');
  await pool.query(TSK_CREDENTIAL_AUTHORITY_SCHEMA);
  const credentialReady = await assertCredentialAuthorityReady(db, 'public');
  if (!receiver) await pool.query(TSK_SOURCE_LEASE_SCHEMA);
  await db.transaction(async (exec) => {
    await exec.query('INSERT INTO tsk_outbox_fence(stream_id,fence_token) VALUES($1,$2)', [SID, EPOCH]);
    await exec.query("INSERT INTO tsk_outbox_source_checkpoint(stream_id,source_epoch,sequence,head_digest) VALUES($1,'e1',0,'')", [SID]);
    await exec.query("INSERT INTO tsk_outbox_receiver_checkpoint(stream_id,source_epoch,sequence,head_digest) VALUES($1,'e1',0,'')", [SID]);
  });
  return { db, ready, credentialReady };
}

async function main() {
  const a = new Pool({ connectionString: urlA }), b = new Pool({ connectionString: urlB });
  try {
    await reset(a); await reset(b);
    const pa = await provision(a, false), pb = await provision(b, true);
    const lease = signLeaseGrant('guard-1', guardKeys.privateKey, {
      streamId: SID, leaseEpoch: EPOCH, leaseStatus: 'active', holderNodeId: 'site-a',
      leaseId: 'lease-a', commandId: 'grant-a-1', leaseExpiresAtMs: Date.now() + 300_000,
      leaseGrantSeq: 1, prevGrantDigest: null,
    });
    await pa.db.transaction((exec) => installLeaseGrant(exec, leaseResolver, lease));
    const fenceReady = await assertSourceFenceReady(pa.db, 'public', leaseResolver, {
      streamId: SID, holderNodeId: lease.holderNodeId, leaseId: lease.leaseId,
      grantDigest: lease.grantDigest,
    });
    const source = new PgHaTumblerMapStore(pa.db, pa.ready, pa.credentialReady, {
      streamId: SID, sourceEpoch: EPOCH, signer,
    }, { resolver: leaseResolver, controlToASkewBoundMs: 0, ready: fenceReady });
    const map = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
    map.label = 'agent:test'; map.status = 'active';
    const hotp = map.segments.find((segment) => segment.type === 'hotp')!;
    await source.set(map.clientId, map);
    await source.updateCounters(map.clientId, new Map([[hotp.segmentId, 1]]));
    const consumed = await Promise.all([
      source.consumeCounter(map.clientId, hotp.segmentId, 1),
      source.consumeCounter(map.clientId, hotp.segmentId, 1),
    ]);
    assert.deepEqual(consumed.sort(), [false, true]);
    const current = (await source.get(map.clientId))!;
    assert.equal((await source.commitValidation(map.clientId, {
      counterMatches: current.segments.filter((segment) => segment.type === 'hotp')
        .map((segment) => ({ segmentId: segment.segmentId, matchedCounter: segment.counter ?? 0 })),
      usedAt: Date.now(),
    })).ok, true);
    const replacement = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
    replacement.label = 'agent:test'; replacement.status = 'active';
    assert.equal(await source.replaceCredential(map.clientId, replacement), true);
    await source.delete(replacement.clientId);
    const rows = (await a.query(`SELECT stream_id,source_epoch,sequence,fence_token::text,op_digest,
      mutation,head_prev,head_digest,head_key_id,head_alg,head_sig
      FROM tsk_outbox_rows WHERE stream_id=$1 ORDER BY sequence`, [SID])).rows;
    assert.equal(rows.length, 7);
    assert.equal(JSON.stringify(rows).includes(map.sharedSecret), false);
    assert.deepEqual(rows.map((row) => Number(row.sequence)), [1, 2, 3, 4, 5, 6, 7]);
    assert.equal((await source.get(map.clientId))!.status, 'revoked');
    assert.equal(await source.get(replacement.clientId), null);
    const receiver = new PgTskCredentialReceiverCheckpoint(pb.db, SID, headVerifier,
      pb.ready, pb.credentialReady);
    const inputs = rows.map((row) => ({
      record: { contractVersion: '1' as const, streamId: row.stream_id, sourceEpoch: row.source_epoch,
        sequence: Number(row.sequence), fenceToken: row.fence_token, opDigest: row.op_digest,
        mutation: row.mutation },
      head: { streamId: SID, sequence: Number(row.sequence), prevHeadDigest: row.head_prev,
        opDigest: row.op_digest, keyId: row.head_key_id, alg: row.head_alg,
        headDigest: row.head_digest, signature: row.head_sig },
    }));
    assert.equal(await receiver.verifyAndApplyDelivered(inputs[1]!.record, inputs[1]!.head), 'reject-gap');
    const tamperedFirst = structuredClone(inputs[0]!);
    tamperedFirst.record.mutation.publicMap.label = 'attacker';
    assert.equal(await receiver.verifyAndApplyDelivered(tamperedFirst.record, tamperedFirst.head), 'reject-fork');
    verifierUnavailable = true;
    await assert.rejects(receiver.verifyAndApplyDelivered(inputs[0]!.record, inputs[0]!.head),
      StreamHeadVerificationUnavailableError);
    verifierUnavailable = false;
    await b.query(`INSERT INTO tsk_credential_replica_maps
      (stream_id,client_id,public_map,public_map_digest,secret_digest,source_epoch,sequence,revision)
      VALUES($1,$2,'{}','${'0'.repeat(64)}','${'1'.repeat(64)}','e1',1,9)`,
    [SID, map.clientId]);
    assert.equal(await receiver.verifyAndApplyDelivered(inputs[0]!.record, inputs[0]!.head), 'reject-fork');
    await b.query('DELETE FROM tsk_credential_replica_maps WHERE stream_id=$1', [SID]);
    const decisions = [];
    for (const input of inputs) decisions.push(await receiver.verifyAndApplyDelivered(input.record, input.head));
    assert.deepEqual(decisions, Array(7).fill('applied'));
    assert.equal(await receiver.verifyAndApplyDelivered(inputs[0]!.record, inputs[0]!.head), 'duplicate-ok');
    const replayedAtWrongEpoch = structuredClone(inputs[0]!);
    replayedAtWrongEpoch.record.sourceEpoch = 'evil-epoch';
    assert.equal(await receiver.verifyAndApplyDelivered(
      replayedAtWrongEpoch.record, replayedAtWrongEpoch.head,
    ), 'reject-fork');
    const replica = (await b.query(
      'SELECT public_map FROM tsk_credential_replica_maps WHERE stream_id=$1 AND client_id=$2',
      [SID, map.clientId],
    )).rows[0].public_map;
    assert.equal(replica.sharedSecret, undefined); assert.equal(replica.status, 'revoked');
    const revoked = signLeaseGrant('guard-1', guardKeys.privateKey, {
      streamId: lease.streamId, leaseEpoch: lease.leaseEpoch, leaseStatus: 'revoked',
      holderNodeId: lease.holderNodeId, leaseId: lease.leaseId, commandId: 'revoke-a-2',
      leaseExpiresAtMs: lease.leaseExpiresAtMs, leaseGrantSeq: 2,
      prevGrantDigest: lease.grantDigest,
    });
    await pa.db.transaction((exec) => installLeaseGrant(exec, leaseResolver, revoked));
    await assert.rejects(source.set(map.clientId, map), /revoked|grant digest/i);
    assert.equal(Number((await a.query(
      'SELECT count(*)::int n FROM tsk_outbox_rows WHERE stream_id=$1', [SID],
    )).rows[0].n), 7);
    const oversized = structuredClone(map);
    oversized.label = 'x'.repeat(300_000);
    await assert.rejects(source.set(oversized.clientId, oversized), /exceeds (?:262144 bytes|CANON_MAX_STRING_BYTES)/);
    await a.query('ALTER TABLE tsk_credential_maps ADD COLUMN drifted boolean');
    await assert.rejects(source.list(), /attestation failed/);
    await a.query('ALTER TABLE tsk_credential_maps DROP COLUMN drifted');
    console.log(JSON.stringify({ checks: 16, records: 7, duplicateEffects: 0,
      staleWritesAdmitted: 0, secretBearingReplicaRecords: 0 }));
  } finally { await a.end(); await b.end(); }
}
await main();
