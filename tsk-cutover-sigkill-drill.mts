/**
 * PR2c acceptance (#10) — child-process SIGKILL / restart matrix over the FULL control cutover.
 *
 * Real independent PG16 (A source @A, B receiver @B, control @control) + real Redis. The parent builds
 * the real signed receipts and drives the cutover; for EACH transition
 * (bindSourceFenced → advanceEpoch → markImporting → markReady → activate) it spawns a CHILD process
 * (tsk-cutover-worker.mts) that performs ONLY that transition and:
 *   • CRASH=before-commit → the child dies by a REAL SIGKILL inside the tx, before COMMIT → the parent
 *     asserts the cutover phase is UNCHANGED (PostgreSQL rolled the tx back — no partial/torn state);
 *   • CRASH=after-commit  → the child COMMITs then SIGKILLs → a FRESH child re-runs the SAME transition →
 *     the parent asserts it resumed IDEMPOTENTLY (phase advanced exactly once, byte-identical evidence).
 * The final phase is ACTIVE (B is the live authority). Per-fault RPO/RTO reported.
 *
 * Env: TSK_TEST_SOURCE_PG_URL_A + TSK_TEST_RECEIVER_PG_URL_B + TSK_TEST_CONTROL_PG_URL + TSK_TEST_REDIS_URL.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import pg from 'pg';
import { Redis } from 'ioredis';
import {
  TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA, TSK_SOURCE_WITNESS_SCHEMA, TSK_RECEIVER_SCHEMA, TSK_RECEIVER_TABLES, provisionSchemaVersion,
  PgTskDurableOutbox, NodePostgresTransactor, ContractValidationError,
  signLeaseGrant, installLeaseGrant, assertSourceFenceReady, emitSourceFrozenReceipt,
  buildSourceExportManifest, guardCountersignSourceExport,
  assertReceiverReady, stageAndFinalizeReceiverGeneration, verifyBFinalizedReceipt,
  HA_CONTROL_PG_SCHEMA, HA_CONTROL_TABLES, HaControlFencing, GuardSigner, provisionControlSchema,
  type PgTransactor, type StreamHeadSigner, type HotpMutationSanitizer, type SanitizedMutation,
  type TskHotpMutation, type SourceVerifyKeyResolver, type SourceExportBundle, type GuardCountersignedExport,
  type GuardKeyResolver, type HaControlPolicy,
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
const B_KEY = 'b-1'; const bKp = generateKeyPairSync('ed25519');
const resolver: SourceVerifyKeyResolver = { resolve: (k) => (k === GUARD_KEY ? guard.publicKey : k === SOURCE_KEY ? source.publicKey : k === HEAD_KEY ? headKp.publicKey : k === B_KEY ? bKp.publicKey : null) };
const CTRL_KEY = 'ctrl-1'; const ctrlSecret = Buffer.alloc(32, 0x2b);
const ctrlResolver: GuardKeyResolver = { resolve: (kid) => (kid === CTRL_KEY ? ctrlSecret : null) };
const ctrlSigner = new GuardSigner(CTRL_KEY, ctrlSecret);
const POLICY: HaControlPolicy = { minClaimRemainingMs: 5_000 };
const signer: StreamHeadSigner = { keyId: HEAD_KEY, alg: 'ed25519', async sign(d) { return edSign(null, Buffer.from(d, 'utf8'), headKp.privateKey).toString('base64url'); } };
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof (raw as TskHotpMutation).tumblerId !== 'string' || !Number.isInteger((raw as TskHotpMutation).counter)) throw new ContractValidationError('bad'); return { tumblerId: (raw as TskHotpMutation).tumblerId, counter: (raw as TskHotpMutation).counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object') throw new ContractValidationError('unsanitized'); },
};
let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }
const now = () => Number(process.hrtime.bigint() / 1_000_000n);

interface WorkerRun { code: number | null; signal: string | null; out: string }
function runWorker(handoffPath: string, transition: string, crash: string, crashTxIndex = 1): Promise<WorkerRun> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', 'tsk-cutover-worker.mts', handoffPath], {
      env: { ...process.env, TRANSITION: transition, CRASH: crash, CRASH_TX_INDEX: String(crashTxIndex) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d) => { out += String(d); });
    child.stderr.on('data', (d) => { out += String(d); });
    child.on('close', (code, signal) => resolve({ code, signal, out }));
  });
}

async function main() {
  console.log('# TSK PR2c child-process SIGKILL/restart matrix over the full control cutover');
  const aPool = new pg.Pool({ connectionString: A_URL, max: 4 }); aPool.on('error', () => {});
  const bPool = new pg.Pool({ connectionString: B_URL, max: 4 }); bPool.on('error', () => {});
  const cPool = new pg.Pool({ connectionString: CTRL_URL, max: 6 }); cPool.on('error', () => {});
  const aTx = new NodePostgresTransactor(aPool as never) as unknown as PgTransactor;
  const bTx = new NodePostgresTransactor(bPool as never) as unknown as PgTransactor;
  const cTx = new NodePostgresTransactor(cPool as never) as unknown as PgTransactor;
  const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 2, lazyConnect: false }); redis.on('error', () => {});
  await redis.flushdb();

  // fresh schemas
  await aPool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, tsk_source_lease_history, tsk_source_witness, tsk_source_witness_history CASCADE');
  for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  for (const s of TSK_SOURCE_WITNESS_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  await bPool.query(`DROP TABLE IF EXISTS ${TSK_RECEIVER_TABLES.join(', ')} CASCADE`);
  for (const s of TSK_RECEIVER_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await bPool.query(s);
  await cPool.query(`DROP TABLE IF EXISTS ${HA_CONTROL_TABLES.join(', ')} CASCADE`);
  for (const s of HA_CONTROL_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await cPool.query(s);

  const aSysId = String((await aPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  const bSysId = String((await bPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  const cSysId = String((await cPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  assert.equal(new Set([aSysId, bSysId, cSysId]).size, 3, 'A, B, control independent');

  const SID = 'tsk:pair:sigkill/v1'; const CMD = 'promote-1'; const TARGET = 1;
  // ── build the real receipts on A + finalize on B (once) ──
  const READY = await provisionSchemaVersion(aTx, SCHEMA);
  const nowA = async () => Number((await aPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  await aPool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [SID]);
  await aPool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [SID, 'e1']);
  const g = signLeaseGrant(GUARD_KEY, guard.privateKey, { streamId: SID, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'grant-1', leaseExpiresAtMs: (await nowA()) + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
  await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
  const sready = await assertSourceFenceReady(aTx, SCHEMA, resolver, { streamId: SID, holderNodeId: 'A', leaseId: 'l1', grantDigest: g.grantDigest });
  const ob = new PgTskDurableOutbox(aTx, READY, { streamId: SID, sanitizer, signer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' }, { resolver, controlToASkewBoundMs: 0, ready: sready });
  for (const [t, c] of [['T1', 1], ['T2', 5], ['T1', 2], ['T3', 9]] as [string, number][]) await ob.withOutboxTx((wtx) => ob.appendInTx(wtx, { streamId: SID, rawMutation: { tumblerId: t, counter: c }, fenceToken: 0n }));
  const rev = signLeaseGrant(GUARD_KEY, guard.privateKey, { streamId: SID, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: CMD, leaseExpiresAtMs: (await nowA()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
  await aTx.transaction((exec) => installLeaseGrant(exec, resolver, rev));
  const frozen = await emitSourceFrozenReceipt(aTx, SCHEMA, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: source.privateKey, leaseResolver: resolver, headResolver: resolver }, { streamId: SID, commandId: CMD, epoch: 0, sourceNodeId: 'A' });
  const built = await buildSourceExportManifest(aTx, SCHEMA, { streamId: SID, epoch: 0, commandId: CMD, sourceNodeId: 'A' }, { sourceKeyId: SOURCE_KEY, sourcePrivateKey: source.privateKey, sanitizer, leaseResolver: resolver, headResolver: resolver, frozenReceipt: frozen, maxChunkItems: 4 });
  const bundle: SourceExportBundle = built.bundle;
  const dual: GuardCountersignedExport = guardCountersignSourceExport(bundle, built.manifest, { guardKeyId: GUARD_KEY, guardPrivateKey: guard.privateKey, sanitizer, sourceManifestResolver: resolver, headResolver: resolver, frozenResolver: resolver, frozenReceipt: frozen, expectedCommandId: CMD });
  const ropts = { sanitizer, sourceResolver: resolver, guardResolver: resolver, headResolver: resolver, frozenResolver: resolver, bVerifyResolver: resolver, frozenReceipt: frozen, expectedCommandId: CMD, bKeyId: B_KEY, bPrivateKey: bKp.privateKey };
  const bReceipt = await stageAndFinalizeReceiverGeneration(bTx, SCHEMA, await assertReceiverReady(bTx, SCHEMA), 'gen-1', bundle, dual, ropts);
  verifyBFinalizedReceipt(resolver, bReceipt);

  // ── control setup: provision + active lease + intent (parent owns the non-target setup) ──
  const ctlReady = await provisionControlSchema(cTx as never, SCHEMA);
  const ctl = new HaControlFencing(cTx as never, ctrlSigner, ctrlResolver, ctlReady, POLICY);
  const ctlNow = async () => Number((await cPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  await ctl.provision(SID, 'g-sigkill');
  await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: (await ctlNow()) - 5_000, grantCommandId: 'a1' });
  await ctl.beginPromotionIntent(SID, CMD, TARGET);

  // handoff for the child workers (public keys only; control HMAC secret shared for symmetric custody).
  const pubKeys: Record<string, string> = {
    [GUARD_KEY]: guard.publicKey.export({ type: 'spki', format: 'pem' }) as string,
    [SOURCE_KEY]: source.publicKey.export({ type: 'spki', format: 'pem' }) as string,
    [HEAD_KEY]: headKp.publicKey.export({ type: 'spki', format: 'pem' }) as string,
    [B_KEY]: bKp.publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
  const handoffPath = './tsk-sigkill-handoff.json';
  const claimExpiresAtMs = Date.now() + HOUR; // STABLE across workers so an advanceEpoch re-claim reads back byte-identical
  writeFileSync(handoffPath, JSON.stringify({ SID, CMD, TARGET, ctrlKeyId: CTRL_KEY, ctrlSecretHex: ctrlSecret.toString('hex'), pubKeys, frozen, bReceipt, ctrlUrl: CTRL_URL, redisUrl: REDIS_URL, claimExpiresAtMs }));

  const phase = async () => (await ctl.cutover(SID))?.phase ?? null;
  const evidence = async () => (await ctl.cutover(SID))?.evidence ?? null;
  const crashed = (r: WorkerRun) => !r.out.includes('WORKER_DONE') && (r.out.includes('WORKER_CRASH') );

  let rtoTotal = 0;
  // transition, before-phase, after-phase, crashTxIndex (advance crashes on its 2nd tx = after the Redis claim)
  const MATRIX: [string, string, string, number][] = [
    ['bind', 'PREPARING', 'SOURCE_FENCED', 1],
    ['advance', 'SOURCE_FENCED', 'FENCED', 2],
    ['import', 'FENCED', 'IMPORTING', 1],
    ['ready', 'IMPORTING', 'READY', 1],
    ['activate', 'READY', 'ACTIVE', 1],
  ];

  for (const [transition, before, after, txIdx] of MATRIX) {
    // before advanceEpoch, the parent must have installed the REVOKED control lease (freeze proof).
    if (transition === 'advance') await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: (await ctlNow()) - 5_000, grantCommandId: 'a2' });

    await check(`${transition}: SIGKILL BEFORE COMMIT rolls back — phase stays ${before}`, async () => {
      assert.equal(await phase(), before);
      const r = await runWorker(handoffPath, transition, 'before-commit', txIdx);
      assert.ok(crashed(r), `child should have crashed before commit; got: ${r.out.slice(-200)}`);
      assert.equal(await phase(), before, 'the killed tx left NO partial state — phase unchanged');
    });

    await check(`${transition}: SIGKILL AFTER COMMIT then a fresh child RESUMES idempotently — phase ${after}, exactly once`, async () => {
      const r1 = await runWorker(handoffPath, transition, 'after-commit', txIdx);
      assert.ok(crashed(r1), `child should have crashed after commit; got: ${r1.out.slice(-200)}`);
      assert.equal(await phase(), after, 'the committed transition is durable across the crash');
      const evAfter = await evidence();
      const t0 = now();
      const r2 = await runWorker(handoffPath, transition, 'none', txIdx); // resume
      rtoTotal += now() - t0;
      assert.ok(r2.out.includes('WORKER_DONE'), `resume should complete; got: ${r2.out.slice(-200)}`);
      assert.equal(await phase(), after, 'idempotent resume — phase advanced EXACTLY once');
      assert.equal(await evidence(), evAfter, 'idempotent resume produced byte-identical signed evidence');
    });
  }

  await check('the promotion reached ACTIVE — B is the live authority after the full crash matrix', async () => {
    assert.equal(await phase(), 'ACTIVE');
    const ev = JSON.parse((await evidence())!);
    assert.equal(ev.k, 'active/v1'); assert.equal(ev.bSystemId, bSysId); assert.equal(ev.sourceSystemId, aSysId); assert.equal(ev.controlSystemId, cSysId);
  });

  console.log('\n# ── measured per-fault RPO / RTO (child-process SIGKILL) ──');
  console.log('  fault: SIGKILL of the cutover worker at EACH phase (before-commit ×5, after-commit ×5)');
  console.log('  RPO  : 0  (before-commit → PG rollback, no torn state; after-commit → durable, idempotent resume)');
  console.log(`  RTO  : ${Math.round(rtoTotal / MATRIX.length)} ms avg  (fresh child spawn → phase re-converged), ${rtoTotal} ms total over ${MATRIX.length} phases`);
  console.log(`\n# ${passed} PR2c SIGKILL-matrix checks passed`);

  rmSync(handoffPath, { force: true }); // the handoff carries key material — never leave it on disk
  await aPool.end(); await bPool.end(); await cPool.end(); await redis.quit();
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
