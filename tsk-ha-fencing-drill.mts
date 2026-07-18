/**
 * PR2a — HA fencing FOUNDATION drill (control DB + REAL Redis). Validates HaControlFencing
 * against a REAL PostgreSQL 16 control DB and a REAL Redis (ioredis + production RedisFencingStore):
 * pinned full-catalog schema attestation + drift + stale-token, the signed control-DB provisioning
 * saga (NO Redis genesis — Erratum-R4), the SIGNED epoch witness, the monotonic command-bound lease
 * with holder/leaseId immutability (kills the same-epoch holder pivot), replay-over-head / tamper /
 * rotation defenses, the exhaustive Redis-vs-witness authority policy (null/W0, null/W>0, R<W,
 * R>W), the control-clock fence-advance with a strict signed evidence payload + freeze-under-
 * PREPARING + min-TTL budget + idempotent retry that reconciles Redis, and a BARRIER-controlled
 * two-transactor concurrent-intent race proven overlapping via pg_locks.
 *
 * BOUNDED / MECHANISM-ONLY — NO split-brain/HA/uptime claim. #10 stays OPEN. Multi-epoch cutover
 * completion (FENCED→…→ACTIVE import/attest), the in-tx SOURCE fence, a 3-node Redis Sentinel/
 * quorum, the child-process SIGKILL crash matrix, and measured RPO/RTO remain later PR2b/PR2c.
 */
import assert from 'node:assert/strict';
import pg from 'pg';
import { Redis } from 'ioredis';
import {
  HA_CONTROL_PG_SCHEMA, HA_CONTROL_TABLES, HA_CONTROL_MANIFEST_DIGEST, HaControlFencing, GuardSigner,
  NodePostgresTransactor, RedisFencingStore, FenceAuthorityQuarantineError,
  provisionControlSchema, assertControlSchemaReady, assertRedisAuthority, reconcileFencedRedis,
  type GuardKeyResolver, type FenceProof, type ControlSchemaReadyToken, type FenceEvidence, type HaControlPolicy,
} from './packages/server/dist/index.js';

const PG_URL = process.env['TSK_TEST_CONTROL_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
if (!PG_URL) throw new Error('TSK_TEST_CONTROL_PG_URL (control PG16) is required');
const REDIS_URL: string = process.env['TSK_TEST_REDIS_URL'] ?? process.env['TSK_REDIS_URL'] ?? '';
if (!REDIS_URL) throw new Error('TSK_TEST_REDIS_URL (real Redis) is required — mechanism-only, not a fault-tolerant topology');

const GUARD_KEY = 'guard-1';
const guardSecret = Buffer.alloc(32, 0x2b);
const resolver: GuardKeyResolver = { resolve: (kid) => (kid === GUARD_KEY ? guardSecret : null) };
const revokedResolver: GuardKeyResolver = { resolve: () => null };
const signer = new GuardSigner(GUARD_KEY, guardSecret);
const HOUR = 3_600_000;
const POLICY: HaControlPolicy = { minClaimRemainingMs: 5_000 }; // strictly-positive deployment budget (R5-M1)
const rec = (nodeId: string, fenceEpoch: number, commandId: string, expiresAt = 1) => ({ nodeId, fenceEpoch, expiresAt, commandId, active: true });
const evi = (over: Partial<FenceEvidence>): FenceEvidence => ({ holderNodeId: 'A', grantSeq: 1, grantDigest: '0'.repeat(64), maxExpiryMs: 0, controlNowMs: 0, safetyMarginMs: 0, redisNodeId: 'B', redisEpoch: 1, redisExpiresMs: 1000, redisClaimDigest: '0'.repeat(64), witnessFrom: 0, witnessTo: 1, proofMode: 'lease-expiry-control-clock', ...over });

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK PR2a HA fencing-foundation drill (real control PG16 + real Redis)');
  const pool = new pg.Pool({ connectionString: PG_URL, max: 8 }); pool.on('error', () => {});
  const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 2, lazyConnect: false });
  await redis.flushdb();
  await pool.query(`DROP TABLE IF EXISTS ${HA_CONTROL_TABLES.join(', ')} CASCADE`);
  for (const s of HA_CONTROL_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  const tx = new NodePostgresTransactor(pool as never);
  const storeFor = (sid: string) => new RedisFencingStore(redis, `tsk:fence:${sid}`);
  const nowMs = async () => Number((await pool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  const histCount = async (t: string, sid: string) => Number((await pool.query(`SELECT count(*)::int AS n FROM ${t} WHERE stream_id=$1`, [sid])).rows[0].n);

  const ready: ControlSchemaReadyToken = await provisionControlSchema(tx as never, 'public');
  const ctl = new HaControlFencing(tx as never, signer, resolver, ready, POLICY);

  // ── schema attestation (pinned, not TOFU) + drift + stale-token ─────────────
  await check('attestation: forged/foreign readiness token rejected', async () => {
    assert.throws(() => new HaControlFencing(tx as never, signer, resolver, Object.freeze({}) as unknown as ControlSchemaReadyToken, POLICY), /forged or foreign token/);
  });
  await check('attestation: catalog drift + a stale token cannot be re-minted (fail closed vs pinned)', async () => {
    await pool.query('ALTER TABLE tsk_ha_lease_head ADD COLUMN drift_col int');
    await assert.rejects(() => assertControlSchemaReady(tx as never, 'public'), /attestation failed/); // no fresh capability against a drifted schema
    await pool.query('ALTER TABLE tsk_ha_lease_head DROP COLUMN drift_col');
    await assertControlSchemaReady(tx as never, 'public'); // clean again == pinned
  });

  // ── signed control-DB provisioning saga (NO Redis genesis — Erratum-R4) ──────
  const SID = 'tsk:pair:pr2a/v1';
  await check('provisioning saga: 3 signed steps + signed witness genesis; witness epoch-0 provisioned; NO Redis record', async () => {
    const st = await ctl.provision(SID, 'genesis-abc');
    assert.equal(st.state, 'provisioned'); assert.equal(st.stateSeq, 3);
    assert.equal(await histCount('tsk_ha_provisioning_history', SID), 3);
    assert.equal(await histCount('tsk_ha_epoch_witness_history', SID), 2);
    const w = await ctl.witness(SID); assert.equal(w?.epoch, 0); assert.equal(w?.state, 'provisioned');
    assert.equal(await storeFor(SID).current(), null, 'no Redis record at genesis (witness floor 0)');
  });
  await check('provisioning idempotent + conflicting genesis marker rejected', async () => {
    assert.equal((await ctl.provision(SID, 'genesis-abc')).stateSeq, 3);
    assert.equal(await histCount('tsk_ha_provisioning_history', SID), 3);
    await assert.rejects(() => ctl.provision(SID, 'DIFFERENT'), /genesis marker conflict/);
  });

  // ── monotonic, command-bound, holder-immutable lease ────────────────────────
  await check('lease grant->renew->revoke monotonic; grantCommandId idempotent (same tuple, no seq)', async () => {
    const now = await nowMs();
    assert.equal((await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 30_000, grantCommandId: 'gc1' })).grantSeq, 1);
    assert.equal((await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 60_000, grantCommandId: 'gc2' })).grantSeq, 2);
    assert.equal((await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 60_000, grantCommandId: 'gc2' })).grantSeq, 2, 'idempotent same-command retry, no seq+1');
    assert.equal((await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: now + 60_000, grantCommandId: 'gc3' })).status, 'revoked');
    assert.equal(await histCount('tsk_ha_lease_history', SID), 3);
  });
  await check('lease rejects: command-id tuple mismatch, holder pivot, wrong epoch, shortened expiry, unprovisioned, int ranges', async () => {
    const now = await nowMs();
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 99_000, grantCommandId: 'gc3' }), /reused with a different lease tuple/);
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'EVIL', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 60_000, grantCommandId: 'gcX' }), /holder\/leaseId is immutable within an epoch/);
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 1, status: 'active', grantedMaxExpiryMs: now + 1000, grantCommandId: 'gy' }), /must equal the current witness epoch/);
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: 1, grantCommandId: 'gz' }), /shorten the monotonic fence horizon/);
    await assert.rejects(() => ctl.writeLease({ streamId: 'tsk:unprov/v1', leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now, grantCommandId: 'g' }), FenceAuthorityQuarantineError);
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: Number.POSITIVE_INFINITY, grantCommandId: 'g' }), /grantedMaxExpiryMs must be a safe integer/);
  });

  // ── H10 replay-over-head + tamper + rotation ────────────────────────────────
  await check('H10: replaying an older valid lease row over the head is rejected (head != latest history)', async () => {
    const SIDr = 'tsk:pair:replay/v1';
    await ctl.provision(SIDr, 'g-replay');
    const now = await nowMs();
    await ctl.writeLease({ streamId: SIDr, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 1000, grantCommandId: 'r1' });
    await ctl.writeLease({ streamId: SIDr, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 2000, grantCommandId: 'r2' });
    await pool.query('DELETE FROM tsk_ha_lease_head WHERE stream_id=$1', [SIDr]);
    await pool.query(`INSERT INTO tsk_ha_lease_head SELECT * FROM (SELECT stream_id, lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_ha_lease_history WHERE stream_id=$1 AND grant_seq=1) x`, [SIDr]);
    await assert.rejects(() => ctl.lease(SIDr), /head is not the latest history row/);
  });
  await check('tamper + rotation/revocation fail closed', async () => {
    await pool.query("UPDATE tsk_ha_lease_head SET guard_signature='AAAA' WHERE stream_id=$1", [SID]);
    await assert.rejects(() => ctl.lease(SID), /guard signature/);
    await pool.query('DELETE FROM tsk_ha_lease_head WHERE stream_id=$1', [SID]);
    await pool.query(`INSERT INTO tsk_ha_lease_head SELECT * FROM (SELECT stream_id, lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_ha_lease_history WHERE stream_id=$1 AND grant_seq=3) x`, [SID]);
    const ctlRevoked = new HaControlFencing(tx as never, signer, revokedResolver, ready, POLICY);
    await assert.rejects(() => ctlRevoked.lease(SID), /unknown or revoked guard keyId/);
  });

  // ── exhaustive Redis-vs-witness authority policy (pure, deterministic) ───────
  await check('Redis authority policy: null/W0 ok, null/W>0 denied, R<W rollback, R>W non-matching denied, R>W exact-intent ok', async () => {
    assert.doesNotThrow(() => assertRedisAuthority(null, 0, 'c', 1));                       // null/W0 = genesis
    assert.throws(() => assertRedisAuthority(null, 1, 'c', 2), FenceAuthorityQuarantineError); // null/W>0 = loss
    assert.throws(() => assertRedisAuthority(rec('B', 1, 'c'), 2, 'c', 3), FenceAuthorityQuarantineError); // R<W rollback
    assert.throws(() => assertRedisAuthority(rec('B', 5, 'other'), 2, 'c', 3), FenceAuthorityQuarantineError); // R>W not our intent
    assert.doesNotThrow(() => assertRedisAuthority(rec('B', 3, 'c'), 2, 'c', 3));            // R>W == exact active intent
    assert.doesNotThrow(() => assertRedisAuthority(rec('B', 2, 'c'), 2, 'c', 3));            // R==W
  });
  await check('FENCED-retry reconcile (R5-H2/R7-HIGH2): requires EXACT signed epoch+tuple; ANY other epoch (higher OR lower) quarantines — no witness-integer trust', async () => {
    const e = evi({ witnessTo: 1, redisNodeId: 'B', redisExpiresMs: 1000, redisClaimDigest: '0'.repeat(64) });
    assert.throws(() => reconcileFencedRedis(null, e, 'c'), FenceAuthorityQuarantineError);                                   // lost
    assert.throws(() => reconcileFencedRedis(rec('B', 1, 'c', 1000), evi({ witnessTo: 2 }), 'c'), FenceAuthorityQuarantineError); // R < fenced (rollback)
    assert.throws(() => reconcileFencedRedis(rec('X', 1, 'c', 1000), e, 'c'), FenceAuthorityQuarantineError);                 // wrong node
    assert.throws(() => reconcileFencedRedis(rec('B', 1, 'other', 1000), e, 'c'), FenceAuthorityQuarantineError);             // wrong command
    assert.throws(() => reconcileFencedRedis({ ...rec('B', 1, 'c', 1000), active: false }, e, 'c'), FenceAuthorityQuarantineError); // inactive
    assert.throws(() => reconcileFencedRedis(rec('B', 1, 'c', 999), e, 'c'), FenceAuthorityQuarantineError);                  // altered expiry
    assert.throws(() => reconcileFencedRedis(rec('B', 1, 'c', 1000), e, 'c'), FenceAuthorityQuarantineError);                 // digest mismatch
    // R7-HIGH2: a forged INACTIVE EVIL tuple at a LATER epoch is NOT blessed by any witness integer
    assert.throws(() => reconcileFencedRedis({ ...rec('EVIL', 2, 'c', 1000), active: false }, e, 'c'), FenceAuthorityQuarantineError);
    assert.throws(() => reconcileFencedRedis(rec('B', 2, 'c', 1000), e, 'c'), FenceAuthorityQuarantineError); // any epoch != signed fenced epoch
  });
  await check('R7-HIGH1: live per-tx attestation rejects a MUTATION after a post-mint DDL drift', async () => {
    await pool.query('ALTER TABLE tsk_ha_provisioning ADD COLUMN drift2 int');
    const dn = await nowMs();
    await assert.rejects(() => ctl.provision('tsk:drift/v1', 'g-drift'), /attestation failed/);
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: dn + 1000, grantCommandId: 'drx' }), /attestation failed/);
    await pool.query('ALTER TABLE tsk_ha_provisioning DROP COLUMN drift2');
    assert.equal((await ctl.provision('tsk:drift/v1', 'g-drift')).state, 'provisioned'); // clean again -> succeeds
  });
  await check('R9-HIGH1: pg_temp cannot shadow governed tables (pg_temp-last search_path keeps resolution in schema)', async () => {
    const c = new pg.Client({ connectionString: PG_URL });
    await c.connect();
    const nsp = async () => (await c.query("SELECT n.nspname FROM pg_class cl JOIN pg_namespace n ON n.oid=cl.relnamespace WHERE cl.oid=to_regclass('tsk_ha_lease_head')")).rows[0].nspname as string;
    try {
      await c.query('CREATE TEMP TABLE tsk_ha_lease_head (x int)'); // attacker temp shadow of an authority table
      assert.ok((await nsp()).startsWith('pg_temp'), 'baseline: the default search_path (pg_temp implicit first) resolves the temp shadow');
      // the FIX, exactly as pinSchema applies it: set_config LOCAL to 'schema, pg_temp' INSIDE a tx
      await c.query('BEGIN');
      await c.query("SELECT pg_catalog.set_config('search_path','public, pg_temp', true)");
      const fixed = await nsp();
      await c.query('COMMIT');
      assert.equal(fixed, 'public', 'fixed: pg_temp-last search_path resolves the real public authority table');
    } finally { await c.end(); } // ends the session -> the temp shadow is gone, pool untouched
  });
  await check('R10-CRITICAL: pg_catalog-first search_path defeats malicious function/catalog shadows (clock spoof / current_schema / pg_class)', async () => {
    const c = new pg.Client({ connectionString: PG_URL });
    await c.connect();
    try {
      await c.query("CREATE OR REPLACE FUNCTION public.clock_timestamp() RETURNS timestamptz LANGUAGE sql IMMUTABLE AS $$ SELECT TIMESTAMPTZ '2000-01-01 00:00:00Z' $$"); // spoofs control time
      await c.query("CREATE OR REPLACE FUNCTION public.current_schema() RETURNS name LANGUAGE sql IMMUTABLE AS $$ SELECT 'evil'::name $$");
      await c.query('CREATE TABLE IF NOT EXISTS public.pg_class (x int)'); // decoy relation named pg_class in public
      await c.query('BEGIN');
      await c.query("SELECT pg_catalog.set_config('search_path','public, pg_temp', true)"); // exactly what pinSchema pins
      const clk = (await c.query('SELECT clock_timestamp() AS t')).rows[0].t as Date;      // unqualified
      const cs = (await c.query('SELECT current_schema() AS s')).rows[0].s as string;       // unqualified
      const pc = Number((await c.query('SELECT count(*)::int AS n FROM pg_class')).rows[0].n); // unqualified
      await c.query('COMMIT');
      assert.ok(new Date(clk).getUTCFullYear() >= 2020, 'unqualified clock_timestamp resolves to pg_catalog (real time) — NO control-clock spoof');
      assert.equal(cs, 'public', 'unqualified current_schema resolves to pg_catalog — not the public shadow');
      assert.ok(pc > 50, 'unqualified pg_class resolves to the real pg_catalog.pg_class — not the public decoy');
    } finally {
      await c.query('DROP FUNCTION IF EXISTS public.clock_timestamp()').catch(() => {});
      await c.query('DROP FUNCTION IF EXISTS public.current_schema()').catch(() => {});
      await c.query('DROP TABLE IF EXISTS public.pg_class').catch(() => {});
      await c.end();
    }
  });
  await check('R9-MED: the REAL criticalTx holds ACCESS SHARE — a concurrent ALTER on a governed table is blocked by its backend (exact relation + pg_blocking_pids)', async () => {
    const S = 'tsk:r9lock/v1';
    await ctl.provision(S, 'g-r9lock');
    const gate = await pool.connect();
    await gate.query('BEGIN');
    await gate.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [S]); // hold the per-stream lock criticalTx takes LAST
    const op = ctl.lease(S); // enters the real criticalTx: ACCESS SHARE + attest, then BLOCKS on the advisory lock (holding ACCESS SHARE)
    // deterministic ordering: wait until the real criticalTx is BLOCKED on the advisory lock — by
    // then it has ALREADY acquired ACCESS SHARE on the governed tables (earlier in criticalTx).
    let ctlBlocked = false;
    for (let i = 0; i < 200 && !ctlBlocked; i++) {
      ctlBlocked = Number((await pool.query("SELECT count(*)::int AS n FROM pg_locks WHERE locktype='advisory' AND NOT granted")).rows[0].n) >= 1;
      if (!ctlBlocked) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(ctlBlocked, 'the real criticalTx is blocked on the advisory lock (so ACCESS SHARE is already held)');
    const ctlPid = Number((await pool.query("SELECT pid FROM pg_locks WHERE locktype='advisory' AND NOT granted ORDER BY pid LIMIT 1")).rows[0].pid); // the criticalTx backend (sole advisory-waiter)
    const altering = pool.query('ALTER TABLE tsk_ha_lease_head ADD COLUMN r9b int').catch(() => {}); // now must block on ctl ACCESS SHARE
    let proven = false;
    for (let i = 0; i < 200 && !proven; i++) {
      const rows = (await pool.query("SELECT pg_blocking_pids(w.pid) AS blockers FROM pg_locks w WHERE w.mode='AccessExclusiveLock' AND NOT w.granted AND w.relation='public.tsk_ha_lease_head'::regclass")).rows;
      proven = rows.length > 0 && (rows[0].blockers as number[]).map(Number).includes(ctlPid); // the EXACT criticalTx backend blocks the EXACT-relation ALTER
      if (!proven) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(proven, `the ALTER on tsk_ha_lease_head is blocked by the exact criticalTx backend pid ${ctlPid} (ACCESS SHARE)`);
    await gate.query('COMMIT'); gate.release(); // release the advisory lock -> the real criticalTx proceeds + commits
    await op; // ctl.lease returns once its tx commits (ACCESS SHARE released)
    await altering;
    await pool.query('ALTER TABLE tsk_ha_lease_head DROP COLUMN IF EXISTS r9b'); // cleanup
  });
  await check('R8: per-op revalidation of the tsk_ha_schema authority stamp (post-mint mutation fails closed)', async () => {
    await pool.query("UPDATE tsk_ha_schema SET catalog_manifest='tampered-stamp' WHERE id=1");
    await assert.rejects(() => ctl.provision('tsk:stamp/v1', 'g-stamp'), /authority stamp/);
    await pool.query('UPDATE tsk_ha_schema SET catalog_manifest=$1 WHERE id=1', [HA_CONTROL_MANIFEST_DIGEST]); // restore
    assert.equal((await ctl.provision('tsk:stamp/v1', 'g-stamp')).state, 'provisioned');
  });

  // ── control-clock fence-advance with REAL Redis (null/W0 allowed end-to-end) ─
  await check('fence-advance (real Redis): freeze/not-revoked/not-expired guard; revoked+elapsed advances 0->1 w/ signed evidence; idempotent retry reconciles Redis', async () => {
    const SID2 = 'tsk:pair:advance/v1';
    await ctl.provision(SID2, 'g-adv');
    const store = storeFor(SID2);
    const past = (await nowMs()) - 5_000;
    await ctl.writeLease({ streamId: SID2, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'a1' });
    await ctl.beginPromotionIntent(SID2, 'c1', 1);
    await assert.rejects(() => ctl.writeLease({ streamId: SID2, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'a2' }), /frozen while a promotion is in-flight/);
    const proof: FenceProof = { safetyMarginMs: 0, claimExpiresAtMs: (await nowMs()) + HOUR };
    await assert.rejects(() => ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof), FenceAuthorityQuarantineError); // not revoked
    await ctl.writeLease({ streamId: SID2, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: past, grantCommandId: 'a3' });
    await assert.rejects(() => ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, { ...proof, safetyMarginMs: HOUR }), /not proven fenced/); // margin keeps A inside horizon
    const res = await ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof);
    assert.equal(res.epoch, 1); assert.equal(res.fenceToken, '1'); assert.equal(res.idempotent, false);
    assert.ok(res.evidence && res.evidence.witnessFrom === 0 && res.evidence.witnessTo === 1 && res.evidence.proofMode === 'lease-expiry-control-clock');
    assert.equal((await ctl.witness(SID2))?.epoch, 1);
    assert.equal((await store.current())?.fenceEpoch, 1, 'REAL Redis record written at epoch 1');
    assert.equal((await ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof)).idempotent, true, 'idempotent retry (Redis reconciled)');
    // H4: after the fence, a Redis LOSS makes the idempotent retry fail closed
    await redis.del('tsk:fence:' + SID2);
    await assert.rejects(() => ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof), /absent on a FENCED retry/);
  });

  await check('fence-advance min-TTL: a claim TTL below the configured worst-case budget quarantines', async () => {
    const SID3 = 'tsk:pair:ttl/v1';
    await ctl.provision(SID3, 'g-ttl');
    const past = (await nowMs()) - 5_000;
    await ctl.writeLease({ streamId: SID3, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 't1' });
    await ctl.beginPromotionIntent(SID3, 'c1', 1);
    await ctl.writeLease({ streamId: SID3, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: past, grantCommandId: 't2' });
    const tooSoon = (await nowMs()) + 2_000; // remaining 2s < 5s budget
    await assert.rejects(() => ctl.advanceEpoch(SID3, 'c1', 1, 'B', storeFor(SID3), { safetyMarginMs: 0, claimExpiresAtMs: tooSoon }), /below the configured min budget/);
  });

  await check('one active intent + target==witness+1 + integer-range rejection', async () => {
    const SID4 = 'tsk:pair:intent/v1';
    await ctl.provision(SID4, 'g-i');
    await assert.rejects(() => ctl.beginPromotionIntent(SID4, 'c1', 2), /must equal witness.epoch\+1/);
    await assert.rejects(() => ctl.beginPromotionIntent(SID4, 'c1', 0), /targetEpoch must be a safe integer/);
    await ctl.beginPromotionIntent(SID4, 'c1', 1);
    await assert.rejects(() => ctl.beginPromotionIntent(SID4, 'c2', 1), /in-flight intent/);
    assert.equal((await ctl.beginPromotionIntent(SID4, 'c1', 1)).phase, 'PREPARING');
  });

  // ── barrier-controlled concurrency: two transactors, gate lock, pg_locks proof ─
  await check('barrier-controlled concurrent intents (two transactors, proven overlapping via pg_locks): exactly one winner', async () => {
    const SID5 = 'tsk:pair:race/v1';
    await ctl.provision(SID5, 'g-race');
    const txA = new NodePostgresTransactor(pool as never), txB = new NodePostgresTransactor(pool as never);
    const ctlA = new HaControlFencing(txA as never, signer, resolver, await assertControlSchemaReady(txA as never, 'public'), POLICY);
    const ctlB = new HaControlFencing(txB as never, signer, resolver, await assertControlSchemaReady(txB as never, 'public'), POLICY);
    const gate = await pool.connect();
    await gate.query('BEGIN');
    await gate.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [SID5]); // hold the per-stream lock
    const p1 = ctlA.beginPromotionIntent(SID5, 'cX', 1);
    const p2 = ctlB.beginPromotionIntent(SID5, 'cY', 1);
    // prove genuine overlap: BOTH intents are blocked WAITING on the advisory lock (the drill is
    // the only workload, so any ungranted advisory waiter is one of our two intents).
    let waiters = 0;
    for (let i = 0; i < 100 && waiters < 2; i++) {
      waiters = Number((await pool.query("SELECT count(*)::int AS n FROM pg_locks WHERE locktype='advisory' AND NOT granted")).rows[0].n);
      if (waiters < 2) await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(waiters, 2, 'both intents proven blocked/overlapping on the per-stream advisory lock');
    await gate.query('COMMIT'); gate.release();
    const results = await Promise.allSettled([p1, p2]);
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1, 'exactly one intent admitted');
    assert.equal(await histCount('tsk_ha_cutover_history', SID5), 1, 'only one PREPARING row appended');
    assert.equal((await pool.query('SELECT phase FROM tsk_ha_cutover_head WHERE stream_id=$1', [SID5])).rows[0].phase, 'PREPARING');
  });

  console.log(`\n# ${passed} PR2a fencing-foundation checks passed`);
  await pool.end().catch(() => {});
  redis.disconnect();
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
