/**
 * PR2c acceptance (#10) — GOVERNED B source-authority activation: B originates N+1 while old A is denied.
 *
 * The full cutover is driven to ACTIVE, then control.activateSource() mints B's UNFORGEABLE source capability
 * (a GUARD-signed ed25519 lease at the PROMOTED epoch, bound to the ratified ACTIVE head + BFinalizedReceipt +
 * exact epoch). B installs that governed lease on its own PG, seeds its source checkpoint to the verified
 * (N, head@N), attests + mints its SourceFenceReadyToken, and appends sequence N+1 through the REAL fenced
 * outbox — chaining from head@N. Meanwhile the OLD A, at the prior epoch with a revoked lease, is DENIED.
 *
 * Env: TSK_TEST_SOURCE_PG_URL_A + TSK_TEST_RECEIVER_PG_URL_B + TSK_TEST_CONTROL_PG_URL + TSK_TEST_REDIS_URL.
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
  HA_CONTROL_PG_SCHEMA, HA_CONTROL_TABLES, HaControlFencing, GuardSigner, RedisFencingStore, provisionControlSchema, verifyLeaseGrant,
  type PgTransactor, type StreamHeadSigner, type HotpMutationSanitizer, type SanitizedMutation,
  type TskHotpMutation, type SourceVerifyKeyResolver, type SourceExportBundle, type GuardCountersignedExport,
  type GuardKeyResolver, type HaControlPolicy, type FenceProof,
} from './packages/server/dist/index.js';

const A_URL = process.env['TSK_TEST_SOURCE_PG_URL_A'];
const B_URL = process.env['TSK_TEST_RECEIVER_PG_URL_B'];
const CTRL_URL = process.env['TSK_TEST_CONTROL_PG_URL'];
const REDIS_URL = process.env['TSK_TEST_REDIS_URL'] ?? '';
if (!A_URL || !B_URL || !CTRL_URL || !REDIS_URL) throw new Error('need A + B + control PG URLs + Redis URL (independent instances)');

const SCHEMA = 'public'; const HOUR = 3_600_000;
const GUARD_KEY = 'guard-1'; const guard = generateKeyPairSync('ed25519');
const SOURCE_KEY = 'source-1'; const source = generateKeyPairSync('ed25519');
const HEAD_KEY = 'k1'; const headKp = generateKeyPairSync('ed25519');
const BHEAD_KEY = 'kb'; const bHeadKp = generateKeyPairSync('ed25519'); // B signs its OWN new heads
const B_KEY = 'b-1'; const bKp = generateKeyPairSync('ed25519');
const resolver: SourceVerifyKeyResolver = { resolve: (k) => (k === GUARD_KEY ? guard.publicKey : k === SOURCE_KEY ? source.publicKey : k === HEAD_KEY ? headKp.publicKey : k === BHEAD_KEY ? bHeadKp.publicKey : k === B_KEY ? bKp.publicKey : null) };
const CTRL_KEY = 'ctrl-1'; const ctrlSecret = Buffer.alloc(32, 0x2b);
const ctrlResolver: GuardKeyResolver = { resolve: (kid) => (kid === CTRL_KEY ? ctrlSecret : null) };
const POLICY: HaControlPolicy = { minClaimRemainingMs: 5_000 };
const mkSigner = (kid: string, priv: Parameters<typeof edSign>[2]): StreamHeadSigner => ({ keyId: kid, alg: 'ed25519', async sign(d) { return edSign(null, Buffer.from(d, 'utf8'), priv).toString('base64url'); } });
const signer = mkSigner(HEAD_KEY, headKp.privateKey);
const bSigner = mkSigner(BHEAD_KEY, bHeadKp.privateKey);
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof (raw as TskHotpMutation).tumblerId !== 'string' || !Number.isInteger((raw as TskHotpMutation).counter)) throw new ContractValidationError('bad'); return { tumblerId: (raw as TskHotpMutation).tumblerId, counter: (raw as TskHotpMutation).counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object') throw new ContractValidationError('unsanitized'); },
};
let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK PR2c governed B source-authority activation (B originates N+1; old A denied)');
  const aPool = new pg.Pool({ connectionString: A_URL, max: 4 }); aPool.on('error', () => {});
  const bPool = new pg.Pool({ connectionString: B_URL, max: 4 }); bPool.on('error', () => {});
  const cPool = new pg.Pool({ connectionString: CTRL_URL, max: 6 }); cPool.on('error', () => {});
  const aTx = new NodePostgresTransactor(aPool as never) as unknown as PgTransactor;
  const bTx = new NodePostgresTransactor(bPool as never) as unknown as PgTransactor;
  const cTx = new NodePostgresTransactor(cPool as never) as unknown as PgTransactor;
  const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 2, lazyConnect: false }); redis.on('error', () => {});
  await redis.flushdb();

  const OUTBOX_DROP = 'DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, tsk_source_lease_history, tsk_source_witness, tsk_source_witness_history CASCADE';
  const installSource = async (pool: pg.Pool) => {
    await pool.query(OUTBOX_DROP);
    for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
    for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
    for (const s of TSK_SOURCE_WITNESS_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  };
  await installSource(aPool);
  // B is BOTH a receiver (staged generation) AND, after activation, a source (outbox) — install both catalogs.
  await bPool.query(`DROP TABLE IF EXISTS ${TSK_RECEIVER_TABLES.join(', ')} CASCADE`);
  for (const s of TSK_RECEIVER_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await bPool.query(s);
  await installSource(bPool);
  await cPool.query(`DROP TABLE IF EXISTS ${HA_CONTROL_TABLES.join(', ')} CASCADE`);
  for (const s of HA_CONTROL_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await cPool.query(s);

  const aSysId = String((await aPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  const bSysId = String((await bPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  const cSysId = String((await cPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  assert.equal(new Set([aSysId, bSysId, cSysId]).size, 3, 'A, B, control independent');

  const SID = 'tsk:pair:bactivate/v1'; const CMD = 'promote-1'; const TARGET = 1; const SRC_EPOCH = 'e1';
  // ── A builds 1..N, freezes, exports; B stages+finalizes the generation (state@N) ──
  const READY = await provisionSchemaVersion(aTx, SCHEMA);
  const nowA = async () => Number((await aPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  await aPool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [SID]);
  await aPool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [SID, SRC_EPOCH]);
  const g = signLeaseGrant(GUARD_KEY, guard.privateKey, { streamId: SID, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'grant-1', leaseExpiresAtMs: (await nowA()) + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
  await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
  const aReady = await assertSourceFenceReady(aTx, SCHEMA, resolver, { streamId: SID, holderNodeId: 'A', leaseId: 'l1', grantDigest: g.grantDigest });
  const aOb = new PgTskDurableOutbox(aTx, READY, { streamId: SID, sanitizer, signer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' }, { resolver, controlToASkewBoundMs: 0, ready: aReady });
  for (const [t, c] of [['T1', 1], ['T2', 5], ['T1', 2], ['T3', 9]] as [string, number][]) await aOb.withOutboxTx((wtx) => aOb.appendInTx(wtx, { streamId: SID, rawMutation: { tumblerId: t, counter: c }, fenceToken: 0n }));
  const N = 4;
  const rev = signLeaseGrant(GUARD_KEY, guard.privateKey, { streamId: SID, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: CMD, leaseExpiresAtMs: (await nowA()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
  await aTx.transaction((exec) => installLeaseGrant(exec, resolver, rev));
  const frozen = await emitSourceFrozenReceipt(aTx, SCHEMA, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: source.privateKey, leaseResolver: resolver, headResolver: resolver }, { streamId: SID, commandId: CMD, epoch: 0, sourceNodeId: 'A' });
  assert.equal(frozen.n, N);
  const built = await buildSourceExportManifest(aTx, SCHEMA, { streamId: SID, epoch: 0, commandId: CMD, sourceNodeId: 'A' }, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: source.privateKey, sanitizer, leaseResolver: resolver, headResolver: resolver, frozenReceipt: frozen, maxChunkItems: 4 });
  const bundle: SourceExportBundle = built.bundle;
  const dual: GuardCountersignedExport = guardCountersignSourceExport(bundle, built.manifest, { guardKeyId: GUARD_KEY, guardPrivateKey: guard.privateKey, sanitizer, sourceManifestResolver: resolver, headResolver: resolver, frozenResolver: resolver, frozenReceipt: frozen, expectedCommandId: CMD });
  const ropts = { sanitizer, sourceResolver: resolver, guardResolver: resolver, headResolver: resolver, frozenResolver: resolver, bVerifyResolver: resolver, frozenReceipt: frozen, expectedCommandId: CMD, bKeyId: B_KEY, bPrivateKey: bKp.privateKey };
  const bReceipt = await stageAndFinalizeReceiverGeneration(bTx, SCHEMA, await assertReceiverReady(bTx, SCHEMA), 'gen-1', bundle, dual, ropts);
  verifyBFinalizedReceipt(resolver, bReceipt);
  const headAtN = bReceipt.signedHeadDigestAtN;

  // ── control drives the cutover to ACTIVE ──
  const ctlReady = await provisionControlSchema(cTx as never, SCHEMA);
  const ctl = new HaControlFencing(cTx as never, new GuardSigner(CTRL_KEY, ctrlSecret), ctrlResolver, ctlReady, POLICY);
  const ctlNow = async () => Number((await cPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  await ctl.provision(SID, 'g-bact');
  await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: (await ctlNow()) - 5_000, grantCommandId: 'a1' });
  await ctl.beginPromotionIntent(SID, CMD, TARGET);
  await ctl.bindSourceFenced(SID, CMD, TARGET, frozen, resolver);
  await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: (await ctlNow()) - 5_000, grantCommandId: 'a2' });
  const store = new RedisFencingStore(redis, 'tsk:fence:' + SID);
  const proof: FenceProof = { safetyMarginMs: 0, claimExpiresAtMs: (await ctlNow()) + HOUR };
  await ctl.advanceEpoch(SID, CMD, TARGET, 'Bnode', store, proof);
  await ctl.markImporting(SID, CMD, TARGET);
  await ctl.markReady(SID, CMD, TARGET, bReceipt, resolver);
  await ctl.activate(SID, CMD, TARGET);

  let bGrant: Awaited<ReturnType<typeof ctl.activateSource>>;
  await check('activateSource mints a GUARD-signed governed B lease at the PROMOTED epoch, bound to the ACTIVE head + BFinalizedReceipt', async () => {
    bGrant = await ctl.activateSource(SID, CMD, TARGET, bReceipt, resolver, { guardKeyId: GUARD_KEY, guardPrivateKey: guard.privateKey, holderNodeId: 'B', leaseId: 'lb', leaseExpiresAtMs: (await ctlNow()) + HOUR });
    verifyLeaseGrant(resolver, bGrant); // B independently verifies with the guard PUBLIC key (unforgeable)
    assert.equal(bGrant.leaseEpoch, TARGET); assert.equal(bGrant.holderNodeId, 'B'); assert.equal(bGrant.leaseStatus, 'active'); assert.equal(bGrant.commandId, CMD);
    // a receipt that was NOT ratified into the ACTIVE head is refused
    const bogus = { ...bReceipt, n: 999 };
    const exp = (await ctlNow()) + HOUR;
    await assert.rejects(() => ctl.activateSource(SID, CMD, TARGET, bogus as typeof bReceipt, resolver, { guardKeyId: GUARD_KEY, guardPrivateKey: guard.privateKey, holderNodeId: 'B', leaseId: 'lb', leaseExpiresAtMs: exp }), /verif|not the one ratified|digest mismatch/i);
  });

  await check('B installs the governed lease, seeds its checkpoint to (N, head@N), and ORIGINATES sequence N+1 through the fenced outbox', async () => {
    // B becomes the source: fence epoch = the promoted epoch; checkpoint continues from the verified (N, head@N).
    await bPool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,$2)', [SID, TARGET]);
    await bPool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence, head_digest) VALUES ($1,$2,$3,$4)', [SID, SRC_EPOCH, N, headAtN]);
    await bTx.transaction((exec) => installLeaseGrant(exec, resolver, bGrant));
    const bReadySrc = await assertSourceFenceReady(bTx, SCHEMA, resolver, { streamId: SID, holderNodeId: 'B', leaseId: 'lb', grantDigest: bGrant.grantDigest });
    const bREADY = await provisionSchemaVersion(bTx, SCHEMA);
    const bOb = new PgTskDurableOutbox(bTx, bREADY, { streamId: SID, sanitizer, signer: bSigner, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' }, { resolver, controlToASkewBoundMs: 0, ready: bReadySrc });
    const res = await bOb.withOutboxTx((wtx) => bOb.appendInTx(wtx, { streamId: SID, rawMutation: { tumblerId: 'T9', counter: 1 }, fenceToken: BigInt(TARGET) }));
    assert.equal(res.head.sequence, N + 1, 'B appended the NEXT sequence (N+1)');
    assert.equal(res.head.prevHeadDigest, headAtN, 'B chained N+1 from the verified head@N');
    const row = (await bPool.query('SELECT sequence, fence_token, head_prev FROM tsk_outbox_rows WHERE stream_id=$1 ORDER BY sequence DESC LIMIT 1', [SID])).rows[0];
    assert.equal(Number(row.sequence), N + 1); assert.equal(Number(row.fence_token), TARGET); assert.equal(String(row.head_prev), headAtN);
  });

  await check('the OLD A, at the prior epoch with a revoked lease, is DENIED — no split-brain source', async () => {
    // A's outbox still points at epoch 0 with a REVOKED lease; the in-tx source-fence gate refuses the append.
    await assert.rejects(() => aOb.withOutboxTx((wtx) => aOb.appendInTx(wtx, { streamId: SID, rawMutation: { tumblerId: 'T1', counter: 3 }, fenceToken: 0n })), /revoked|not writable|lease|fence/i);
    const aMax = Number((await aPool.query('SELECT COALESCE(MAX(sequence),0) AS n FROM tsk_outbox_rows WHERE stream_id=$1', [SID])).rows[0].n);
    assert.equal(aMax, N, 'A wrote nothing past N — the old source is fenced');
  });

  console.log(`\n# ${passed} PR2c B-source-activation checks passed`);
  await aPool.end(); await bPool.end(); await cPool.end(); await redis.quit();
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
