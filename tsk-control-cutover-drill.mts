/**
 * PR2b-3 (§4) — CONTROL cutover ordering: signed PREPARING → SOURCE_FENCED → FENCED → IMPORTING → READY.
 * Three INDEPENDENT PG16 instances (A source, B receiver, control authority — distinct system_identifiers)
 * + real Redis. A freezes at N and builds a guard-countersigned export; B stages+finalizes into a signed
 * BFinalizedReceipt. Control then drives the cutover head:
 *   • bindSourceFenced  — ed25519-verifies A's SourceFrozenReceipt and BINDS its digest/N/head@N/state@N
 *                          into the signed cutover head BEFORE declaring FENCED (the ordering gate).
 *   • advanceEpoch      — the PR2a Redis+witness fence (revoked control lease + elapsed grant + Redis claim).
 *   • markImporting     — opens the import window ONLY if a SOURCE_FENCED freeze was durably bound.
 *   • markReady         — ed25519-verifies B's BFinalizedReceipt, binds it to the EXACT frozen N, and PROVES
 *                          B.system_identifier is DISTINCT from BOTH the signed source id (B != source) AND
 *                          control's OWN pg_control_system id (B != control — the capability §4 was deferred
 *                          to hold). A READY head EXISTS only if control proved B != control against itself.
 * Negatives + hardening: foreign freeze; the ORDERING gate is a SINGLE CHOKEPOINT at advanceEpoch (a
 * PREPARING cutover that never bound SOURCE_FENCED cannot be FENCED); B == control (a valid receipt
 * finalized ON the control instance — passes §3's B!=source but is refused here); tampered + wrong-command
 * receipts; (H1) caller-mutation-after-bind is decoupled from the stored signed evidence; (H3) an idempotent
 * retry with a different receipt is refused. #10 stays OPEN (no HA/production claim; single Redis/instance).
 *
 * Env: TSK_TEST_SOURCE_PG_URL_A (A) + TSK_TEST_RECEIVER_PG_URL_B (B) + TSK_TEST_CONTROL_PG_URL (control) +
 *      TSK_TEST_REDIS_URL (real Redis). All three PG URLs MUST be independent instances.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import pg from 'pg';
import { Redis } from 'ioredis';
import {
  TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA, TSK_SOURCE_WITNESS_SCHEMA, TSK_RECEIVER_SCHEMA, TSK_RECEIVER_TABLES, provisionSchemaVersion,
  PgTskDurableOutbox, NodePostgresTransactor, ContractValidationError,
  signLeaseGrant, installLeaseGrant, assertSourceFenceReady, emitSourceFrozenReceipt,
  buildSourceExportManifest, guardCountersignSourceExport,
  assertReceiverReady, stageAndFinalizeReceiverGeneration, verifyBFinalizedReceipt,
  HA_CONTROL_PG_SCHEMA, HA_CONTROL_TABLES, HaControlFencing, GuardSigner, RedisFencingStore,
  FenceAuthorityQuarantineError, provisionControlSchema,
  type PgTransactor, type StreamHeadSigner, type HotpMutationSanitizer, type SanitizedMutation,
  type TskHotpMutation, type SourceVerifyKeyResolver, type SourceExportBundle, type GuardCountersignedExport,
  type GuardKeyResolver, type HaControlPolicy, type BFinalizedReceipt, type SourceFrozenReceipt,
} from './packages/server/dist/index.js';

const A_URL = process.env['TSK_TEST_SOURCE_PG_URL_A'] ?? process.env['TSK_TEST_SOURCE_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
const B_URL = process.env['TSK_TEST_RECEIVER_PG_URL_B'] ?? process.env['TSK_TEST_POSTGRES_URL_B'];
const CTRL_URL = process.env['TSK_TEST_CONTROL_PG_URL'];
const REDIS_URL = process.env['TSK_TEST_REDIS_URL'] ?? process.env['TSK_REDIS_URL'] ?? '';
if (!A_URL || !B_URL || !CTRL_URL) throw new Error('TSK_TEST_SOURCE_PG_URL_A + TSK_TEST_RECEIVER_PG_URL_B + TSK_TEST_CONTROL_PG_URL are required (three independent instances)');
if (!REDIS_URL) throw new Error('TSK_TEST_REDIS_URL (real Redis) is required — mechanism-only, not a fault-tolerant topology');

const SCHEMA = 'public';
const HOUR = 3_600_000;
// source/receiver custody: ed25519 (verifiers hold PUBLIC keys only)
const GUARD_KEY = 'guard-1'; const guard = generateKeyPairSync('ed25519'); const guardSecret = guard.privateKey;
const SOURCE_KEY = 'source-1'; const source = generateKeyPairSync('ed25519'); const sourceSecret = source.privateKey;
const HEAD_KEY = 'k1'; const headKp = generateKeyPairSync('ed25519'); const headPriv = headKp.privateKey;
const B_KEY = 'b-1'; const bKp = generateKeyPairSync('ed25519'); const bSecret = bKp.privateKey;
const resolver: SourceVerifyKeyResolver = { resolve: (k) => (k === GUARD_KEY ? guard.publicKey : k === SOURCE_KEY ? source.publicKey : k === HEAD_KEY ? headKp.publicKey : k === B_KEY ? bKp.publicKey : null) };
// control custody: HMAC guard signer (PR2a), independent of the ed25519 source/receiver custody
const CTRL_KEY = 'ctrl-1'; const ctrlSecret = Buffer.alloc(32, 0x2b);
const ctrlResolver: GuardKeyResolver = { resolve: (kid) => (kid === CTRL_KEY ? ctrlSecret : null) };
const ctrlSigner = new GuardSigner(CTRL_KEY, ctrlSecret);
const POLICY: HaControlPolicy = { minClaimRemainingMs: 5_000 };

const signer: StreamHeadSigner = { keyId: HEAD_KEY, alg: 'ed25519', async sign(d) { return edSign(null, Buffer.from(d, 'utf8'), headPriv).toString('base64url'); } };
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof (raw as TskHotpMutation).tumblerId !== 'string' || !Number.isInteger((raw as TskHotpMutation).counter)) throw new ContractValidationError('bad'); return { tumblerId: (raw as TskHotpMutation).tumblerId, counter: (raw as TskHotpMutation).counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object') throw new ContractValidationError('unsanitized'); },
};
let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

// Build a frozen source stream on A, export it, guard-countersign, and finalize on the given receiver
// pool → a signed BFinalizedReceipt. Returns the freeze + bundle + dual + the B-signed receipt.
async function buildStream(aTx: PgTransactor, aPool: pg.Pool, recvTx: PgTransactor, sid: string, cmd: string, mutations: [string, number][]) {
  const READY = await provisionSchemaVersion(aTx, SCHEMA);
  const nowMs = async () => Number((await aPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  await aPool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0) ON CONFLICT (stream_id) DO NOTHING', [sid]);
  await aPool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0) ON CONFLICT (stream_id) DO NOTHING', [sid, 'e1']);
  const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'grant-' + cmd, leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
  await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
  const ready = await assertSourceFenceReady(aTx, SCHEMA, resolver, { streamId: sid, holderNodeId: 'A', leaseId: 'l1', grantDigest: g.grantDigest });
  const ob = new PgTskDurableOutbox(aTx, READY, { streamId: sid, sanitizer, signer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' }, { resolver, controlToASkewBoundMs: 0, ready });
  for (const [t, c] of mutations) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: t, counter: c }, fenceToken: 0n }));
  const rev = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: cmd, leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
  await aTx.transaction((exec) => installLeaseGrant(exec, resolver, rev));
  const frozen = await emitSourceFrozenReceipt(aTx, SCHEMA, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: sourceSecret, leaseResolver: resolver, headResolver: resolver }, { streamId: sid, commandId: cmd, epoch: 0, sourceNodeId: 'A' });
  const built = await buildSourceExportManifest(aTx, SCHEMA, { streamId: sid, epoch: 0, commandId: cmd, sourceNodeId: 'A' }, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: sourceSecret, sanitizer, leaseResolver: resolver, headResolver: resolver, frozenReceipt: frozen, maxChunkItems: 4 });
  const bundle: SourceExportBundle = built.bundle;
  const dual: GuardCountersignedExport = guardCountersignSourceExport(bundle, built.manifest, { guardKeyId: GUARD_KEY, guardPrivateKey: guardSecret, sanitizer, sourceManifestResolver: resolver, headResolver: resolver, frozenResolver: resolver, frozenReceipt: frozen, expectedCommandId: cmd });
  const ropts = { sanitizer, sourceResolver: resolver, guardResolver: resolver, headResolver: resolver, frozenResolver: resolver, bVerifyResolver: resolver, frozenReceipt: frozen, expectedCommandId: cmd, bKeyId: B_KEY, bPrivateKey: bSecret };
  const receipt = await stageAndFinalizeReceiverGeneration(recvTx, SCHEMA, await assertReceiverReady(recvTx, SCHEMA), 'gen-' + cmd, bundle, dual, ropts);
  verifyBFinalizedReceipt(resolver, receipt);
  return { frozen, bundle, dual, ropts, receipt };
}

async function main() {
  console.log('# TSK PR2b-3 control-cutover ordering drill (independent A + B + control PG16 + real Redis)');
  const aPool = new pg.Pool({ connectionString: A_URL, max: 4 }); aPool.on('error', () => {});
  const bPool = new pg.Pool({ connectionString: B_URL, max: 4 }); bPool.on('error', () => {});
  const cPool = new pg.Pool({ connectionString: CTRL_URL, max: 6 }); cPool.on('error', () => {});
  const aTx = new NodePostgresTransactor(aPool as never) as unknown as PgTransactor;
  const bTx = new NodePostgresTransactor(bPool as never) as unknown as PgTransactor;
  const cTx = new NodePostgresTransactor(cPool as never) as unknown as PgTransactor;
  const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 2, lazyConnect: false });
  await redis.flushdb();

  // A (source) fresh schema
  await aPool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, tsk_source_lease_history, tsk_source_witness, tsk_source_witness_history CASCADE');
  for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  for (const s of TSK_SOURCE_WITNESS_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  // B (receiver) fresh catalog
  await bPool.query(`DROP TABLE IF EXISTS ${TSK_RECEIVER_TABLES.join(', ')} CASCADE`);
  for (const s of TSK_RECEIVER_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await bPool.query(s);
  // control: BOTH the HA control catalog AND the receiver catalog (so we can finalize a B==control receipt)
  await cPool.query(`DROP TABLE IF EXISTS ${HA_CONTROL_TABLES.join(', ')} CASCADE`);
  for (const s of HA_CONTROL_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await cPool.query(s);
  await cPool.query(`DROP TABLE IF EXISTS ${TSK_RECEIVER_TABLES.join(', ')} CASCADE`);
  for (const s of TSK_RECEIVER_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await cPool.query(s);

  const aSysId = String((await aPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  const bSysId = String((await bPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  const cSysId = String((await cPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  assert.equal(new Set([aSysId, bSysId, cSysId]).size, 3, 'A, B, and control MUST be three independent instances');

  const ctlReady = await provisionControlSchema(cTx as never, SCHEMA);
  const ctl = new HaControlFencing(cTx as never, ctrlSigner, ctrlResolver, ctlReady, POLICY);
  const ctrlNowMs = async () => Number((await cPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  const storeFor = (sid: string) => new RedisFencingStore(redis, 'tsk:fence:' + sid);

  // Mint a REAL ed25519 SourceFrozenReceipt at a GIVEN source lease epoch (genesis N=0) — used to build a
  // cross-epoch (foreign-epoch) freeze that must NOT bind to a target whose target-1 differs.
  const genesisFreezeAtEpoch = async (sid: string, cmd: string, leaseEpoch: number): Promise<SourceFrozenReceipt> => {
    await aPool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0) ON CONFLICT (stream_id) DO NOTHING', [sid]);
    await aPool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0) ON CONFLICT (stream_id) DO NOTHING', [sid, 'e1']);
    const now = Number((await aPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
    const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'g-' + cmd, leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
    await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
    const rev = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: cmd, leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
    await aTx.transaction((exec) => installLeaseGrant(exec, resolver, rev));
    return emitSourceFrozenReceipt(aTx, SCHEMA, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: sourceSecret, leaseResolver: resolver, headResolver: resolver }, { streamId: sid, commandId: cmd, epoch: leaseEpoch, sourceNodeId: 'A' });
  };

  // ── happy path: full signed ordering with both receipts bound ────────────────
  const SID = 'tsk:pair:cutover/v1'; const CMD = 'promote-1';
  const s1 = await buildStream(aTx, aPool, bTx, SID, CMD, [['T1', 1], ['T2', 5], ['T1', 2], ['T3', 9], ['T2', 6], ['T1', 3]]);
  assert.equal(s1.receipt.n, 6); assert.equal(s1.receipt.bSystemId, bSysId); assert.equal(s1.receipt.sourceSystemId, aSysId);
  // A VALID B-signed receipt finalized ON the control instance: same freeze/manifest, but bSystemId == control.
  // §3's receiver finalize only enforces B != source, so control != source lets this through; §4 must catch it.
  const ctrlReceipt = await stageAndFinalizeReceiverGeneration(cTx, SCHEMA, await assertReceiverReady(cTx, SCHEMA), 'gen-onctrl', s1.bundle, s1.dual, s1.ropts);
  verifyBFinalizedReceipt(resolver, ctrlReceipt);
  assert.equal(ctrlReceipt.bSystemId, cSysId); assert.equal(ctrlReceipt.frozenReceiptDigest, s1.frozen.receiptDigest);

  await check('PREPARING → SOURCE_FENCED binds the ed25519 frozen receipt (digest/N/head@N/state@N) into the signed cutover head', async () => {
    await ctl.provision(SID, 'g-' + CMD);
    const past = (await ctrlNowMs()) - 5_000;
    await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'a-' + CMD });
    await ctl.beginPromotionIntent(SID, CMD, 1);
    const sf = await ctl.bindSourceFenced(SID, CMD, 1, s1.frozen, resolver);
    assert.equal(sf.phase, 'SOURCE_FENCED'); assert.equal(sf.commandId, CMD); assert.equal(sf.epoch, 1);
    const ev = JSON.parse(sf.evidence!);
    assert.equal(ev.frozenReceiptDigest, s1.frozen.receiptDigest); assert.equal(ev.n, s1.frozen.n);
    assert.equal(ev.headAtN, s1.frozen.signedHeadDigestAtN); assert.equal(ev.stateAtN, s1.frozen.sourceStateDigestAtN);
    // idempotent for the EXACT bound receipt
    assert.equal((await ctl.bindSourceFenced(SID, CMD, 1, s1.frozen, resolver)).phase, 'SOURCE_FENCED');
    // (H1) mutate the caller receipt AFTER binding — the stored signed evidence is decoupled (snapshot), unchanged
    const mut = s1.frozen as unknown as Record<string, unknown>; const savedN = mut.n; mut.n = 4242;
    assert.equal(JSON.parse((await ctl.cutover(SID))!.evidence!).n, savedN, 'stored SOURCE_FENCED evidence is decoupled from caller mutation');
    mut.n = savedN;
  });

  await check('SOURCE_FENCED → FENCED via the PR2a Redis+witness fence (revoked control lease + elapsed grant + Redis claim)', async () => {
    const past = (await ctrlNowMs()) - 5_000;
    await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: past, grantCommandId: 'r-' + CMD });
    const res = await ctl.advanceEpoch(SID, CMD, 1, 'Bnode', storeFor(SID), { safetyMarginMs: 0, claimExpiresAtMs: (await ctrlNowMs()) + HOUR });
    assert.equal(res.epoch, 1); assert.equal(res.fenceToken, '1'); assert.equal(res.idempotent, false);
    assert.equal((await ctl.witness(SID))?.epoch, 1);
  });

  await check('FENCED → IMPORTING (allowed: a SOURCE_FENCED freeze is durably bound for this command/epoch)', async () => {
    const im = await ctl.markImporting(SID, CMD, 1);
    assert.equal(im.phase, 'IMPORTING'); assert.equal(im.commandId, CMD);
    assert.equal((await ctl.markImporting(SID, CMD, 1)).phase, 'IMPORTING'); // idempotent
  });

  await check('IMPORTING refuses a B==control receipt (finalized ON control: passes §3 B!=source, refused here) — the §4 capability', async () => {
    await assert.rejects(() => ctl.markReady(SID, CMD, 1, ctrlReceipt, resolver), /B system_identifier == control/);
    assert.equal((await ctl.cutover(SID))?.phase, 'IMPORTING', 'refusal did not advance the head');
  });

  await check('IMPORTING refuses a tampered receipt (ed25519 gate) and a wrong-command receipt', async () => {
    const tampered = clone(s1.receipt); tampered.bSystemId = '999';
    await assert.rejects(() => ctl.markReady(SID, CMD, 1, tampered as BFinalizedReceipt, resolver), /digest mismatch|signature|verif/i);
    // epoch is a SIGNED-bound field: a forged cross-epoch B receipt can't pass verification (B-receipt epoch vector)
    const tamperedEp = clone(s1.receipt); tamperedEp.epoch = 99;
    await assert.rejects(() => ctl.markReady(SID, CMD, 1, tamperedEp as BFinalizedReceipt, resolver), /digest mismatch|signature|verif/i);
    await assert.rejects(() => ctl.markReady(SID, 'other-cmd', 1, s1.receipt, resolver), /no matching IMPORTING|commandId/);
  });

  await check('IMPORTING → READY: B receipt ed25519-verified, bound to the frozen N, and B distinct from BOTH source and control', async () => {
    const rd = await ctl.markReady(SID, CMD, 1, s1.receipt, resolver);
    assert.equal(rd.phase, 'READY'); assert.equal(rd.commandId, CMD); assert.equal(rd.epoch, 1);
    const ev = JSON.parse(rd.evidence!);
    assert.equal(ev.bReceiptDigest, s1.receipt.receiptDigest);
    assert.equal(ev.frozenReceiptDigest, s1.frozen.receiptDigest, 'READY binds the EXACT SOURCE_FENCED freeze');
    assert.equal(ev.bSystemId, bSysId); assert.equal(ev.sourceSystemId, aSysId); assert.equal(ev.controlSystemId, cSysId);
    assert.notEqual(ev.bSystemId, ev.sourceSystemId); assert.notEqual(ev.bSystemId, ev.controlSystemId);
    assert.equal(s1.receipt.epoch, 0); assert.equal(s1.frozen.epoch, 0); // freeze + B receipt at source epoch target-1 (=0)
    assert.equal((await ctl.markReady(SID, CMD, 1, s1.receipt, resolver)).phase, 'READY'); // idempotent for the ratified receipt
    // (H3) a READY retry with a DIFFERENT receipt (the B==control one, same freeze) is refused — never silently OK
    await assert.rejects(() => ctl.markReady(SID, CMD, 1, ctrlReceipt, resolver), /B system_identifier == control/);
    // (H1) mutate the caller receipt AFTER READY — the stored signed evidence is decoupled (snapshot), unchanged
    const mut = s1.receipt as unknown as Record<string, unknown>; const savedB = mut.bSystemId; mut.bSystemId = 'zzz';
    assert.equal(JSON.parse((await ctl.cutover(SID))!.evidence!).bSystemId, savedB, 'stored READY evidence is decoupled from caller mutation');
    mut.bSystemId = savedB;
  });

  // ── negative: foreign freeze cannot be bound to a cutover ─────────────────────
  await check('bindSourceFenced REJECTS a frozen receipt for a different stream/command (no cross-stream splice)', async () => {
    const SIDX = 'tsk:pair:foreign/v1';
    const other = await buildStream(aTx, aPool, bTx, 'tsk:pair:other/v1', 'promote-x', [['Z', 7]]);
    await ctl.provision(SIDX, 'g-foreign');
    const past = (await ctrlNowMs()) - 5_000;
    await ctl.writeLease({ streamId: SIDX, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'a-foreign' });
    await ctl.beginPromotionIntent(SIDX, 'promote-foreign', 1);
    await assert.rejects(() => ctl.bindSourceFenced(SIDX, 'promote-foreign', 1, other.frozen, resolver), /frozen receipt (streamId|commandId) != cutover/);
  });

  // ── negative: a freeze at the WRONG source epoch cannot bind (cross-epoch splice) ─
  await check('bindSourceFenced REJECTS a freeze whose epoch != targetEpoch-1 (foreign-epoch freeze)', async () => {
    const SIDE = 'tsk:pair:epoch/v1';
    const frE1 = await genesisFreezeAtEpoch(SIDE, 'promote-epoch', 1); // frozen at source epoch 1
    await ctl.provision(SIDE, 'g-epoch');
    const past = (await ctrlNowMs()) - 5_000;
    await ctl.writeLease({ streamId: SIDE, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'a-epoch' });
    await ctl.beginPromotionIntent(SIDE, 'promote-epoch', 1); // target 1 → target-1 = 0, but the freeze is epoch 1
    await assert.rejects(() => ctl.bindSourceFenced(SIDE, 'promote-epoch', 1, frE1, resolver), /epoch 1 != targetEpoch-1|cross-epoch/);
  });

  // ── negative: the ORDERING gate is enforced AT advanceEpoch (single chokepoint) ─
  await check('advanceEpoch REFUSES to FENCE a PREPARING cutover that never bound SOURCE_FENCED (FENCED unreachable without a freeze)', async () => {
    const SIDN = 'tsk:pair:nofreeze/v1'; const CMDN = 'promote-nofreeze';
    await ctl.provision(SIDN, 'g-' + CMDN);
    const past = (await ctrlNowMs()) - 5_000;
    await ctl.writeLease({ streamId: SIDN, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'a-' + CMDN });
    await ctl.beginPromotionIntent(SIDN, CMDN, 1);
    await ctl.writeLease({ streamId: SIDN, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: past, grantCommandId: 'r-' + CMDN });
    const claimExp = (await ctrlNowMs()) + HOUR;
    await assert.rejects(() => ctl.advanceEpoch(SIDN, CMDN, 1, 'Bnode', storeFor(SIDN), { safetyMarginMs: 0, claimExpiresAtMs: claimExp }), /no matching SOURCE_FENCED intent/);
    assert.equal((await ctl.cutover(SIDN))?.phase, 'PREPARING', 'still PREPARING — the fence never fired without a bound freeze');
  });

  console.log(`\n# ${passed} PR2b-3 control-cutover ordering checks passed`);
  await aPool.end(); await bPool.end(); await cPool.end(); await redis.quit();
}

main().catch((e) => { console.error(e); process.exit(1); });
