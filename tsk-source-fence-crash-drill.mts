/**
 * PR2b-0 (M5) — deterministic crash-point drills across real A-PG + control-PG + Redis.
 * A crash is modeled deterministically as a tx that throws mid-transaction (PG rolls it back — the
 * exact crash-equivalent for a single tx) or as a step skipped then resumed. Proves fail-closed +
 * idempotent resume with NO partial authority at each saga point, and the decisive property: a
 * writer that passes a Redis pre-check still loses in-tx once the PG lease is revoked.
 *
 * Env: TSK_TEST_SOURCE_PG_URL_A (source A), TSK_TEST_CONTROL_PG_URL (control), TSK_TEST_REDIS_URL.
 * BOUNDED / MECHANISM-ONLY. #10 stays OPEN. B (receiver) is the PR14 PG @5433 — honestly asserted
 * distinct here, NOT run (its import is PR2b-4+). Child-process SIGKILL matrix is PR2c.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import pg from 'pg';
import { Redis } from 'ioredis';
import {
  TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA, TSK_SOURCE_WITNESS_SCHEMA, TSK_SOURCE_WITNESS_TABLES,
  provisionSchemaVersion, PgTskDurableOutbox, NodePostgresTransactor, RedisFencingStore, ContractValidationError,
  signLeaseGrant, installLeaseGrant, readSourceLease, emitSourceFrozenReceipt, verifySourceFrozenReceipt,
  advanceSourceWitness, readSourceWitness, SourceFenceQuarantineError,
  type PgTransactor, type StreamHeadSigner, type HotpMutationSanitizer, type SanitizedMutation, type TskHotpMutation, type SourceVerifyKeyResolver,
} from './packages/server/dist/index.js';

const A_URL = process.env['TSK_TEST_SOURCE_PG_URL_A'] ?? process.env['TSK_TEST_POSTGRES_URL'];
const C_URL = process.env['TSK_TEST_CONTROL_PG_URL'];
const R_URL: string = process.env['TSK_TEST_REDIS_URL'] ?? process.env['TSK_REDIS_URL'] ?? '';
if (!A_URL || !C_URL || !R_URL) throw new Error('TSK_TEST_SOURCE_PG_URL_A + TSK_TEST_CONTROL_PG_URL + TSK_TEST_REDIS_URL are required');

const GUARD_KEY = 'guard-1'; const guard = generateKeyPairSync('ed25519'); const guardSecret = guard.privateKey;
const SOURCE_KEY = 'source-1'; const source = generateKeyPairSync('ed25519'); const sourceSecret = source.privateKey; // independent custody
const resolver: SourceVerifyKeyResolver = { resolve: (k) => (k === GUARD_KEY ? guard.publicKey : k === SOURCE_KEY ? source.publicKey : null) };
const HOUR = 3_600_000;
const { privateKey } = generateKeyPairSync('ed25519');
const signer: StreamHeadSigner = { keyId: 'k1', alg: 'ed25519', async sign(d) { return edSign(null, Buffer.from(d, 'utf8'), privateKey).toString('base64url'); } };
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof raw.tumblerId !== 'string' || !Number.isInteger(raw.counter)) throw new ContractValidationError('bad'); return { tumblerId: raw.tumblerId, counter: raw.counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object') throw new ContractValidationError('unsanitized'); },
};
class Crash extends Error {}

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK PR2b-0 M5 deterministic crash drill (real A-PG + control-PG + Redis)');
  const aPool = new pg.Pool({ connectionString: A_URL, max: 4 }); aPool.on('error', () => {});
  const cPool = new pg.Pool({ connectionString: C_URL, max: 4 }); cPool.on('error', () => {});
  const redis = new Redis(R_URL, { maxRetriesPerRequest: 2 }); await redis.flushdb();
  const aTx = new NodePostgresTransactor(aPool as never) as unknown as PgTransactor;
  const cTx = new NodePostgresTransactor(cPool as never) as unknown as PgTransactor;

  await aPool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, tsk_source_lease_history CASCADE');
  for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  const READY = await provisionSchemaVersion(aTx, 'public');
  await cPool.query(`DROP TABLE IF EXISTS ${TSK_SOURCE_WITNESS_TABLES.join(', ')} CASCADE`);
  for (const s of TSK_SOURCE_WITNESS_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await cPool.query(s);

  const sysId = async (p: pg.Pool) => String((await p.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  const nowMs = async () => Number((await aPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  const seqOf = async (sid: string) => Number((await aPool.query('SELECT sequence FROM tsk_outbox_source_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence);
  const grant = async (sid: string, over: Record<string, unknown> = {}) => signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'g1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 1, prevGrantDigest: null, ...over } as never);
  const gate = { resolver, controlToASkewBoundMs: 0 };
  const mkOutbox = (sid: string) => new PgTskDurableOutbox(aTx, READY, { streamId: sid, sanitizer, signer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation', sourceLeaseGate: gate });
  async function provision(sid: string) { await aPool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [sid]); await aPool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [sid, 'e1']); }

  await check('topology: A-PG and control-PG are independent instances (distinct system_identifier); B declared @5433', async () => {
    assert.notEqual(await sysId(aPool), await sysId(cPool), 'A and control must be independent PG instances');
    // honest: B (receiver) is the PR14 PG @5433 with its own distinct system_identifier; not run here (import is PR2b-4+).
  });

  await check('CRASH grant install: mid-tx crash rolls back (no lease); retry installs; post-commit re-install is idempotent', async () => {
    const sid = 'tsk:crash:grant/v1'; await provision(sid);
    const g = await grant(sid);
    await assert.rejects(() => aTx.transaction(async (exec) => { await installLeaseGrant(exec, resolver, g); throw new Crash('mid-install'); }), Crash);
    assert.equal(await aTx.transaction((exec) => readSourceLease(exec, resolver, sid)), null, 'no partial lease after crash');
    await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g)); // resume
    assert.equal((await aTx.transaction((exec) => readSourceLease(exec, resolver, sid)))?.leaseGrantSeq, 1);
    await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g)); // idempotent re-install (same command)
    assert.equal(Number((await aPool.query('SELECT count(*)::int n FROM tsk_source_lease_history WHERE stream_id=$1', [sid])).rows[0].n), 1, 'no duplicate history on re-install');
  });

  await check('CRASH append: mid-tx crash rolls back (seq unchanged); retry advances the seq', async () => {
    const sid = 'tsk:crash:append/v1'; await provision(sid); const gg = await grant(sid); await aTx.transaction((exec) => installLeaseGrant(exec, resolver, gg));
    const ob = mkOutbox(sid);
    await assert.rejects(() => ob.withOutboxTx(async (tx) => { await ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 1 }, fenceToken: 0n }); throw new Crash('mid-append'); }), Crash);
    assert.equal(await seqOf(sid), 0, 'no row committed after append crash');
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 1 }, fenceToken: 0n })); // resume
    assert.equal(await seqOf(sid), 1);
  });

  await check('CRASH revoke→before receipt: revoke commits; receipt is re-emittable idempotently on resume', async () => {
    const sid = 'tsk:crash:freeze/v1'; await provision(sid);
    const g = await grant(sid); await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
    const ob = mkOutbox(sid); await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 9 }, fenceToken: 0n }));
    const rev = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: 'r1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
    await aTx.transaction((exec) => installLeaseGrant(exec, resolver, rev)); // revoke commits; "crash" before receipt
    const r1 = await aTx.transaction((exec) => emitSourceFrozenReceipt(exec, resolver, SOURCE_KEY, sourceSecret, { streamId: sid, commandId: 'promote-1', epoch: 0, sourceNodeId: 'A' })); // resume
    const r2 = await aTx.transaction((exec) => emitSourceFrozenReceipt(exec, resolver, SOURCE_KEY, sourceSecret, { streamId: sid, commandId: 'promote-1', epoch: 0, sourceNodeId: 'A' })); // re-emit
    assert.equal(r1.receiptDigest, r2.receiptDigest, 'frozen receipt is deterministic/idempotent on resume');
    verifySourceFrozenReceipt(resolver, r1); assert.equal(r1.n, 1);
  });

  await check('CRASH witness advance: mid-tx crash rolls back (witness unchanged); retry advances; re-advance same high-water is idempotent', async () => {
    const sid = 'tsk:crash:witness/v1';
    await assert.rejects(() => cTx.transaction(async (exec) => { await advanceSourceWitness(exec, resolver, GUARD_KEY, guardSecret, { streamId: sid, sourceSystemId: 'sysA', grantSeq: 1, sourceSeq: 3, headDigest: 'a'.repeat(64) }); throw new Crash('mid-advance'); }), Crash);
    assert.equal(await cTx.transaction((exec) => readSourceWitness(exec, resolver, sid)), null, 'no partial witness after crash');
    await cTx.transaction((exec) => advanceSourceWitness(exec, resolver, GUARD_KEY, guardSecret, { streamId: sid, sourceSystemId: 'sysA', grantSeq: 1, sourceSeq: 3, headDigest: 'a'.repeat(64) })); // resume
    await cTx.transaction((exec) => advanceSourceWitness(exec, resolver, GUARD_KEY, guardSecret, { streamId: sid, sourceSystemId: 'sysA', grantSeq: 1, sourceSeq: 3, headDigest: 'a'.repeat(64) })); // idempotent re-advance
    const w = await cTx.transaction((exec) => readSourceWitness(exec, resolver, sid));
    assert.equal(w?.witnessSeq, 1, 'no duplicate witness seq on idempotent re-advance');
  });

  await check('DECISIVE: a writer passes a Redis pre-check but LOSES in-tx once the PG lease is revoked', async () => {
    const sid = 'tsk:crash:redis/v1'; await provision(sid);
    const g = await grant(sid); await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
    const store = new RedisFencingStore(redis, `tsk:fence:${sid}`);
    assert.equal(await store.claim({ nodeId: 'A', fenceEpoch: 1, expiresAt: (await nowMs()) + HOUR, commandId: 'c' }), true, 'Redis grants the claim');
    const ob = mkOutbox(sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 1 }, fenceToken: 0n })); // ok while lease active
    const rev = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: 'r1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
    await aTx.transaction((exec) => installLeaseGrant(exec, resolver, rev));
    assert.ok((await store.current())?.active, 'Redis still shows the claim active');
    const before = await seqOf(sid);
    await assert.rejects(() => ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 2 }, fenceToken: 0n })), SourceFenceQuarantineError);
    assert.equal(await seqOf(sid), before, 'the PG in-tx gate is the authority — Redis pre-check does not matter');
  });

  console.log(`\n# ${passed} PR2b-0 M5 deterministic-crash checks passed`);
  await aPool.end().catch(() => {}); await cPool.end().catch(() => {}); redis.disconnect();
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
