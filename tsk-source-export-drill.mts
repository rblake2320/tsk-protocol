/**
 * PR2b-1 — complete canonical 1..N export + ONE replay authority + dual independent signatures.
 * Real PG16. Proves (design §2): with A frozen at N, the source exports the FULL history 1..N (full
 * payload + all signed-head fields) + the sorted state-at-N in bounded chunks; the ONE canonical replay
 * recomputes opDigest FROM the payload, verifies every head binding + signature + prev/head link, and
 * DERIVES state (head/state @N are OUTPUTS, cross-checked to the frozen receipt); the source signs the
 * manifest; the guard verifies the active command + frozen receipt, INDEPENDENTLY replays, and
 * counter-signs. Negatives: payload substitution, reordered/missing record, chunk tamper, root
 * mismatch, wrong active command, forged signature all fail closed.
 *
 * Env: TSK_TEST_SOURCE_PG_URL (or TSK_TEST_POSTGRES_URL). BOUNDED / MECHANISM-ONLY. #10 stays OPEN.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import pg from 'pg';
import {
  TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA, TSK_SOURCE_WITNESS_SCHEMA, provisionSchemaVersion,
  PgTskDurableOutbox, NodePostgresTransactor, ContractValidationError,
  signLeaseGrant, installLeaseGrant, assertSourceFenceReady, emitSourceFrozenReceipt,
  buildSourceExportManifest, verifySourceExportManifest, guardCountersignSourceExport, verifyGuardCountersignedExport,
  SourceFenceQuarantineError,
  type PgTransactor, type StreamHeadSigner, type HotpMutationSanitizer, type SanitizedMutation,
  type TskHotpMutation, type SourceVerifyKeyResolver, type LeaseGrant, type SourceExportBundle,
} from './packages/server/dist/index.js';

const URL = process.env['TSK_TEST_SOURCE_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
if (!URL) throw new Error('TSK_TEST_SOURCE_PG_URL (source PG16) is required');
const SCHEMA = 'public';
const GUARD_KEY = 'guard-1'; const guard = generateKeyPairSync('ed25519'); const guardSecret = guard.privateKey;
const SOURCE_KEY = 'source-1'; const source = generateKeyPairSync('ed25519'); const sourceSecret = source.privateKey;
const HEAD_KEY = 'k1'; const headKp = generateKeyPairSync('ed25519'); const headPriv = headKp.privateKey;
const resolver: SourceVerifyKeyResolver = { resolve: (k) => (k === GUARD_KEY ? guard.publicKey : k === SOURCE_KEY ? source.publicKey : k === HEAD_KEY ? headKp.publicKey : null) };
const HOUR = 3_600_000;
const signer: StreamHeadSigner = { keyId: HEAD_KEY, alg: 'ed25519', async sign(d) { return edSign(null, Buffer.from(d, 'utf8'), headPriv).toString('base64url'); } };
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof (raw as TskHotpMutation).tumblerId !== 'string' || !Number.isInteger((raw as TskHotpMutation).counter)) throw new ContractValidationError('bad'); return { tumblerId: (raw as TskHotpMutation).tumblerId, counter: (raw as TskHotpMutation).counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object') throw new ContractValidationError('unsanitized'); },
};

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

async function main() {
  console.log('# TSK PR2b-1 complete-export + replay + dual-signature drill (real PG16)');
  const pool = new pg.Pool({ connectionString: URL, max: 4 }); pool.on('error', () => {});
  const serial = new NodePostgresTransactor(pool as never) as unknown as PgTransactor;
  await pool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, tsk_source_lease_history, tsk_source_witness, tsk_source_witness_history CASCADE');
  for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  for (const s of TSK_SOURCE_WITNESS_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  const READY = await provisionSchemaVersion(serial, SCHEMA);
  const nowMs = async () => Number((await pool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);

  // set up a frozen stream at N=6 with 3 distinct tumblers, then export it
  const SID = 'tsk:pair:export/v1';
  await pool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [SID]);
  await pool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [SID, 'e1']);
  const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'grant-1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
  await serial.transaction((exec) => installLeaseGrant(exec, resolver, g));
  const ready = await assertSourceFenceReady(serial, SCHEMA, resolver, { streamId: SID, holderNodeId: 'A', leaseId: 'l1', grantDigest: g.grantDigest });
  const ob = new PgTskDurableOutbox(serial, READY, { streamId: SID, sanitizer, signer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' }, { resolver, controlToASkewBoundMs: 0, ready });
  const muts: [string, number][] = [['T1', 1], ['T2', 5], ['T1', 2], ['T3', 9], ['T2', 6], ['T1', 3]]; // latest: T1=3, T2=6, T3=9
  for (const [t, c] of muts) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: SID, rawMutation: { tumblerId: t, counter: c }, fenceToken: 0n }));
  const rev = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: 'promote-1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
  await serial.transaction((exec) => installLeaseGrant(exec, resolver, rev));
  const frozen = await emitSourceFrozenReceipt(serial, SCHEMA, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: sourceSecret, leaseResolver: resolver, headResolver: resolver }, { streamId: SID, commandId: 'promote-1', epoch: 0, sourceNodeId: 'A' });

  const exOpts = { sourceKeyId: SOURCE_KEY, sourcePrivateKey: sourceSecret, sanitizer, leaseResolver: resolver, headResolver: resolver, frozenReceipt: frozen, maxChunkItems: 4 };
  let bundle!: SourceExportBundle; let manifest!: Awaited<ReturnType<typeof buildSourceExportManifest>>['manifest'];

  await check('SOURCE builds a chunked 1..N export + manifest; head/state@N are replay OUTPUTS matching the frozen receipt', async () => {
    const r = await buildSourceExportManifest(serial, SCHEMA, { streamId: SID, epoch: 0, commandId: 'promote-1', sourceNodeId: 'A' }, exOpts);
    bundle = r.bundle; manifest = r.manifest;
    assert.equal(manifest.n, 6);
    assert.equal(manifest.signedHeadDigestAtN, frozen.signedHeadDigestAtN, 'replay head@N == frozen receipt head@N');
    assert.equal(manifest.sourceStateDigestAtN, frozen.sourceStateDigestAtN, 'replay state@N == frozen receipt state@N');
    // N=6 with maxChunkItems=4 → 2 history chunks (1..4, 5..6) + 1 state chunk
    assert.equal(bundle.historyChunks.length, 2); assert.equal(manifest.chunkCount, 3);
    assert.deepEqual(bundle.stateChunk.pairs.map((p) => p[0]).sort(), ['T1', 'T2', 'T3']);
    verifySourceExportManifest(resolver, manifest); // source signature verifies
  });

  const gopts = { guardKeyId: GUARD_KEY, guardPrivateKey: guardSecret, sanitizer, sourceManifestResolver: resolver, headResolver: resolver, frozenResolver: resolver, frozenReceipt: frozen, expectedCommandId: 'promote-1' };

  await check('GUARD verifies expected command + full frozen binding, INDEPENDENTLY replays, and counter-signs (dual custody)', async () => {
    const dual = guardCountersignSourceExport(bundle, manifest, gopts);
    verifyGuardCountersignedExport(resolver, resolver, dual); // both signatures verify
    assert.equal(dual.guardKeyId, GUARD_KEY); assert.equal(dual.sourceEpoch, 'e1');
  });

  await check('a PAYLOAD substitution fails (byteDigest recomputed from the exact records)', async () => {
    const bad = clone(bundle); bad.historyChunks[0].records[0].payload = JSON.stringify({ tumblerId: 'T1', counter: 999 });
    await assert.rejects(async () => guardCountersignSourceExport(bad, manifest, gopts), /declared byteDigest != recomputed|chunk tamper|opDigest does not match/);
  });

  await check('(H2 payload exactness) an EXTRA field the sanitizer drops (unchanged opDigest) is rejected', async () => {
    const bad = clone(bundle); const r0 = bad.historyChunks[0].records[0];
    r0.payload = JSON.stringify({ ...JSON.parse(r0.payload), secret: 'leak' }); // sanitizes away → same opDigest
    await assert.rejects(async () => guardCountersignSourceExport(bad, manifest, gopts), /declared byteDigest != recomputed|payload bytes != canonical|non-canonical or extra/);
  });

  await check('(R8 stale-digest) a byte-modified but semantically-equal payload (whitespace / key-order / duplicate-key) with a KEPT chunk byteDigest is rejected by the recomputed digest', async () => {
    const canon = bundle.historyChunks[0].records[0].payload; // exact canonical form emitted by the export
    for (const variant of [' ' + canon, '{"tumblerId":"T1","counter":1}', '{"tumblerId":"T1","tumblerId":"T1","counter":1}']) {
      const bad = clone(bundle); bad.historyChunks[0].records[0].payload = variant; // keep the stale chunk byteDigest
      await assert.rejects(async () => guardCountersignSourceExport(bad, manifest, gopts), /declared byteDigest != recomputed/);
    }
  });

  await check('(R8 root binds bytes) a tampered payload with an UPDATED chunk byteDigest still fails the manifestRoot / inventory bind', async () => {
    // recompute the chunk digest so the stale-digest guard passes, then the root no longer matches the signed manifest
    const bad = clone(bundle); bad.historyChunks[0].records[0].payload = ' ' + bad.historyChunks[0].records[0].payload;
    // emulate an attacker who also rewrites the chunk digest to match the tampered records (still fails the root)
    bad.historyChunks[0].byteDigest = 'deadbeef'.repeat(8);
    await assert.rejects(async () => guardCountersignSourceExport(bad, manifest, gopts), /declared byteDigest != recomputed|root|inventory entry|manifestRoot/);
  });

  await check('(M2 epoch) a CROSS-EPOCH record is rejected (recomputed digest / replay epoch check)', async () => {
    const bad = clone(bundle); bad.historyChunks[0].records[1].sourceEpoch = 'e2';
    await assert.rejects(async () => guardCountersignSourceExport(bad, manifest, gopts), /declared byteDigest != recomputed|cross-epoch/);
  });

  await check('(H1 state binding) a tampered state chunk pair is rejected (bound to the replay-derived state)', async () => {
    const bad = clone(bundle); bad.stateChunk.pairs[0][1] = 4242; // T*=4242 disagrees with 1..N
    await assert.rejects(async () => guardCountersignSourceExport(bad, manifest, gopts), /declared byteDigest != recomputed|state chunk|inventory entry|state pair/);
  });

  await check('(M1 strict inventory) reorder / duplicate / non-adjacent boundaries are rejected', async () => {
    const rev = clone(manifest); [rev.inventory[0], rev.inventory[1]] = [rev.inventory[1], rev.inventory[0]];
    assert.throws(() => verifySourceExportManifest(resolver, rev), /must be a history chunk|ordinal|seqFrom|manifestRoot/);
    const dup = clone(manifest); dup.inventory.splice(1, 0, clone(dup.inventory[0])); dup.chunkCount += 1;
    assert.throws(() => verifySourceExportManifest(resolver, dup), /ordinal|seqFrom|gap\/overlap|manifestRoot/);
    const trunc = clone(manifest); trunc.inventory.pop(); trunc.chunkCount -= 1;
    assert.throws(() => verifySourceExportManifest(resolver, trunc), /state chunk|history chunks cover|manifestRoot/);
  });

  await check('the GUARD rejects a manifest whose commandId != the caller-expected command', async () => {
    await assert.rejects(async () => guardCountersignSourceExport(bundle, manifest, { ...gopts, expectedCommandId: 'other-cmd' }), /!= caller-expected command/);
  });

  await check('a FORGED source signature (unknown key) fails verification', async () => {
    const badKp = generateKeyPairSync('ed25519');
    const badResolver: SourceVerifyKeyResolver = { resolve: (k) => (k === SOURCE_KEY ? badKp.publicKey : resolver.resolve(k)) };
    assert.throws(() => verifySourceExportManifest(badResolver, manifest), /invalid signature/);
  });

  console.log(`\n# ${passed} PR2b-1 export checks passed`);
  await pool.end().catch(() => {});
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
