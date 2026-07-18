/**
 * PR2b-2 (§3) — receiver B: isolated staging, strict replay/verify, ONE atomic finalize.
 * Real PG16 x2 (independent A and B instances, distinct system_identifier). Proves: A freezes at N and
 * builds a guard-countersigned export; B verifies BOTH signatures + the frozen binding + the bundle
 * root + INDEPENDENTLY replays 1..N + materializes state-at-N + asserts B's system_identifier is
 * distinct from A/control; then constructs + signs the BFinalizedReceipt and installs it atomically
 * (checkpoint/head/state + pointer flip + stored receipt). Negatives: not-distinct B, tampered guard
 * sig, wrong expected command, idempotent re-finalize, refusal to re-flip a different generation.
 *
 * Env: TSK_TEST_SOURCE_PG_URL_A (A) + TSK_TEST_RECEIVER_PG_URL_B (B). #10 stays OPEN.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import pg from 'pg';
import {
  TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA, TSK_SOURCE_WITNESS_SCHEMA, TSK_RECEIVER_SCHEMA, TSK_RECEIVER_TABLES, provisionSchemaVersion,
  PgTskDurableOutbox, NodePostgresTransactor, ContractValidationError,
  signLeaseGrant, installLeaseGrant, assertSourceFenceReady, emitSourceFrozenReceipt,
  buildSourceExportManifest, guardCountersignSourceExport,
  stageAndFinalizeReceiverGeneration, verifyBFinalizedReceipt, readReceiverPointer, SourceFenceQuarantineError,
  type PgTransactor, type StreamHeadSigner, type HotpMutationSanitizer, type SanitizedMutation,
  type TskHotpMutation, type SourceVerifyKeyResolver, type SourceExportBundle, type GuardCountersignedExport,
} from './packages/server/dist/index.js';

const A_URL = process.env['TSK_TEST_SOURCE_PG_URL_A'] ?? process.env['TSK_TEST_SOURCE_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
const B_URL = process.env['TSK_TEST_RECEIVER_PG_URL_B'] ?? process.env['TSK_TEST_POSTGRES_URL_B'];
if (!A_URL || !B_URL) throw new Error('TSK_TEST_SOURCE_PG_URL_A + TSK_TEST_RECEIVER_PG_URL_B are required (independent instances)');
const SCHEMA = 'public';
const GUARD_KEY = 'guard-1'; const guard = generateKeyPairSync('ed25519'); const guardSecret = guard.privateKey;
const SOURCE_KEY = 'source-1'; const source = generateKeyPairSync('ed25519'); const sourceSecret = source.privateKey;
const HEAD_KEY = 'k1'; const headKp = generateKeyPairSync('ed25519'); const headPriv = headKp.privateKey;
const B_KEY = 'b-1'; const bKp = generateKeyPairSync('ed25519'); const bSecret = bKp.privateKey;
const resolver: SourceVerifyKeyResolver = { resolve: (k) => (k === GUARD_KEY ? guard.publicKey : k === SOURCE_KEY ? source.publicKey : k === HEAD_KEY ? headKp.publicKey : k === B_KEY ? bKp.publicKey : null) };
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
  console.log('# TSK PR2b-2 receiver-B stage/replay/verify + atomic finalize drill (real A-PG + B-PG)');
  const aPool = new pg.Pool({ connectionString: A_URL, max: 4 }); aPool.on('error', () => {});
  const bPool = new pg.Pool({ connectionString: B_URL, max: 4 }); bPool.on('error', () => {});
  const aTx = new NodePostgresTransactor(aPool as never) as unknown as PgTransactor;
  const bTx = new NodePostgresTransactor(bPool as never) as unknown as PgTransactor;
  await aPool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, tsk_source_lease_history, tsk_source_witness, tsk_source_witness_history CASCADE');
  for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  for (const s of TSK_SOURCE_WITNESS_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  const READY = await provisionSchemaVersion(aTx, SCHEMA);
  await bPool.query(`DROP TABLE IF EXISTS ${TSK_RECEIVER_TABLES.join(', ')} CASCADE`);
  for (const s of TSK_RECEIVER_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await bPool.query(s);

  const aSysId = String((await aPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  const bSysId = String((await bPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  assert.notEqual(aSysId, bSysId, 'A and B must be independent instances');
  const nowMs = async () => Number((await aPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);

  // A: grow a stream to N=6 (T1=3, T2=6, T3=9), revoke, freeze, export, guard-countersign
  const SID = 'tsk:pair:recv/v1';
  await aPool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [SID]);
  await aPool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [SID, 'e1']);
  const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'grant-1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
  await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
  const ready = await assertSourceFenceReady(aTx, SCHEMA, resolver, { streamId: SID, holderNodeId: 'A', leaseId: 'l1', grantDigest: g.grantDigest });
  const ob = new PgTskDurableOutbox(aTx, READY, { streamId: SID, sanitizer, signer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' }, { resolver, controlToASkewBoundMs: 0, ready });
  for (const [t, c] of [['T1', 1], ['T2', 5], ['T1', 2], ['T3', 9], ['T2', 6], ['T1', 3]] as [string, number][]) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: SID, rawMutation: { tumblerId: t, counter: c }, fenceToken: 0n }));
  const rev = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: 'promote-1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
  await aTx.transaction((exec) => installLeaseGrant(exec, resolver, rev));
  const frozen = await emitSourceFrozenReceipt(aTx, SCHEMA, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: sourceSecret, leaseResolver: resolver, headResolver: resolver }, { streamId: SID, commandId: 'promote-1', epoch: 0, sourceNodeId: 'A' });
  const built = await buildSourceExportManifest(aTx, SCHEMA, { streamId: SID, epoch: 0, commandId: 'promote-1', sourceNodeId: 'A' }, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: sourceSecret, sanitizer, leaseResolver: resolver, headResolver: resolver, frozenReceipt: frozen, maxChunkItems: 4 });
  const bundle: SourceExportBundle = built.bundle;
  const dual: GuardCountersignedExport = guardCountersignSourceExport(bundle, built.manifest, { guardKeyId: GUARD_KEY, guardPrivateKey: guardSecret, sanitizer, sourceManifestResolver: resolver, headResolver: resolver, frozenResolver: resolver, frozenReceipt: frozen, expectedCommandId: 'promote-1' });

  const ropts = { sanitizer, sourceResolver: resolver, guardResolver: resolver, headResolver: resolver, frozenResolver: resolver, bVerifyResolver: resolver, frozenReceipt: frozen, expectedCommandId: 'promote-1', bKeyId: B_KEY, bPrivateKey: bSecret, distinctFromSystemIds: [aSysId] };

  await check('B stages + INDEPENDENTLY replays + atomically finalizes; BFinalizedReceipt binds the manifest', async () => {
    const receipt = await stageAndFinalizeReceiverGeneration(bTx, SCHEMA, 'gen-1', bundle, dual, ropts);
    verifyBFinalizedReceipt(resolver, receipt);
    assert.equal(receipt.n, 6); assert.equal(receipt.generationId, 'gen-1'); assert.equal(receipt.bSystemId, bSysId);
    assert.equal(receipt.manifestDigest, dual.canonicalDigest); assert.equal(receipt.manifestRoot, dual.manifestRoot);
    assert.equal(receipt.signedHeadDigestAtN, frozen.signedHeadDigestAtN); assert.equal(receipt.sourceStateDigestAtN, frozen.sourceStateDigestAtN);
  });

  await check('the installed pointer + materialized state@N are readable and verified', async () => {
    const ptr = await bTx.transaction((exec) => readReceiverPointer(exec, resolver, SID));
    assert.ok(ptr); assert.equal(ptr!.checkpointSeq, 6); assert.equal(ptr!.headDigest, frozen.signedHeadDigestAtN);
    const st = (await bPool.query('SELECT tumbler_id, hotp_counter FROM tsk_receiver_state WHERE stream_id=$1 AND generation_id=$2 ORDER BY tumbler_id', [SID, 'gen-1'])).rows;
    assert.deepEqual(st.map((r) => [String(r.tumbler_id), Number(r.hotp_counter)]), [['T1', 3], ['T2', 6], ['T3', 9]]);
  });

  await check('re-finalize the SAME generation is idempotent (returns the stored receipt; no double-flip)', async () => {
    const again = await stageAndFinalizeReceiverGeneration(bTx, SCHEMA, 'gen-1', bundle, dual, ropts);
    verifyBFinalizedReceipt(resolver, again);
    const cnt = Number((await bPool.query('SELECT count(*)::int n FROM tsk_receiver_generation WHERE stream_id=$1', [SID])).rows[0].n);
    assert.equal(cnt, 1, 'no duplicate generation installed');
  });

  await check('B REFUSES to flip a DIFFERENT generation once a stream is installed', async () => {
    await assert.rejects(() => stageAndFinalizeReceiverGeneration(bTx, SCHEMA, 'gen-2', bundle, dual, ropts), /already at a DIFFERENT generation|refusing to re-flip/);
  });

  await check('B REJECTS a bundle whose system_identifier is NOT distinct from A/control', async () => {
    await assert.rejects(() => stageAndFinalizeReceiverGeneration(bTx, SCHEMA, 'gen-x', bundle, dual, { ...ropts, distinctFromSystemIds: [aSysId, bSysId] }), /NOT distinct/);
  });

  await check('B REJECTS a tampered GUARD signature and a wrong expected command', async () => {
    const badGuard = clone(dual); badGuard.guardSignature = 'AAAA';
    await assert.rejects(() => stageAndFinalizeReceiverGeneration(bTx, SCHEMA, 'gen-y', bundle, badGuard, ropts), /invalid signature|guard/);
    await assert.rejects(() => stageAndFinalizeReceiverGeneration(bTx, SCHEMA, 'gen-z', bundle, dual, { ...ropts, expectedCommandId: 'other' }), /!= caller-expected command/);
  });

  console.log(`\n# ${passed} PR2b-2 receiver checks passed`);
  await aPool.end().catch(() => {}); await bPool.end().catch(() => {});
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
