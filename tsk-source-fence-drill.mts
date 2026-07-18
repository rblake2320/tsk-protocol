/**
 * PR2b-0 (M1) — source in-tx fence/lease gate drill, real PostgreSQL 16.
 * Validates: guard-verified signed lease install (monotonic grant_seq + prev-digest chain +
 * command idempotency), the in-tx gate (active/epoch/deadline), lock-based revoke → gate fails,
 * tamper/forgery/replay rejection. Env: TSK_TEST_SOURCE_PG_URL (or TSK_TEST_POSTGRES_URL).
 *
 * BOUNDED / MECHANISM-ONLY — this is the source gate primitive; the append-tx wiring, pre-commit
 * recheck, SourceFrozenReceipt, external witness, and full crash drills land in later PR2b-0 commits.
 * #10 stays OPEN.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import pg from 'pg';
import {
  TSK_SOURCE_LEASE_SCHEMA, TSK_SOURCE_LEASE_TABLES, NodePostgresTransactor,
  signLeaseGrant, installLeaseGrant, assertSourceLeaseWritable, readSourceLease, SourceFenceQuarantineError,
  TSK_SOURCE_WITNESS_SCHEMA, TSK_SOURCE_WITNESS_TABLES, advanceSourceWitness, readSourceWitness, assertSourceWitnessConsistent,
  type SourceVerifyKeyResolver, type BareLeaseGrant, type LeaseGrant, type SourceLiveState,
} from './packages/server/dist/index.js';

const URL = process.env['TSK_TEST_SOURCE_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
if (!URL) throw new Error('TSK_TEST_SOURCE_PG_URL (source PG16) is required');

const GUARD_KEY = 'guard-1'; // ed25519: private signs (control/guard), public verifies (source)
const guard = generateKeyPairSync('ed25519');
const guardSecret = guard.privateKey;
const resolver: SourceVerifyKeyResolver = { resolve: (kid) => (kid === GUARD_KEY ? guard.publicKey : null) };
const SID = 'tsk:pair:pr2b0/v1';
const HOUR = 3_600_000;

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK PR2b-0 source fence/lease gate drill (real source PG16)');
  const pool = new pg.Pool({ connectionString: URL, max: 4 }); pool.on('error', () => {});
  await pool.query(`DROP TABLE IF EXISTS ${TSK_SOURCE_LEASE_TABLES.join(', ')}, ${TSK_SOURCE_WITNESS_TABLES.join(', ')} CASCADE`);
  for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  for (const s of TSK_SOURCE_WITNESS_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  const tx = new NodePostgresTransactor(pool as never);
  const nowMs = async () => Number((await pool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  const grant = (over: Partial<BareLeaseGrant>): LeaseGrant => signLeaseGrant(GUARD_KEY, guardSecret, {
    streamId: SID, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'c1',
    leaseExpiresAtMs: 0, leaseGrantSeq: 1, prevGrantDigest: null, ...over,
  });

  await check('install grant seq1 (active) → gate passes at epoch 0', async () => {
    const now = await nowMs();
    const g1 = grant({ leaseExpiresAtMs: now + HOUR, commandId: 'grant-1' });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, g1));
    const st = await readSourceLease(await poolExec(pool), resolver, SID);
    assert.equal(st?.leaseStatus, 'active'); assert.equal(st?.leaseGrantSeq, 1);
    await tx.transaction(async (exec) => { const w = await assertSourceLeaseWritable(exec, resolver, SID, 0, 0); assert.equal(w.leaseEpoch, 0); });
  });

  await check('gate rejects: wrong epoch, expired deadline, missing lease, forged/unknown key', async () => {
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID, 1, 0)), /epoch .* != expected/);
    // an already-elapsed deadline (past) → reject even at the right epoch
    const past = grant({ leaseExpiresAtMs: (await nowMs()) - 10_000, commandId: 'grant-past', leaseGrantSeq: 2, prevGrantDigest: (await readSourceLease(await poolExec(pool), resolver, SID))!.grantDigest });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, past));
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID, 0, 0)), /deadline elapsed/);
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, 'tsk:unleased/v1', 0, 0)), /not leased/);
    const forged: SourceVerifyKeyResolver = { resolve: () => null };
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, forged, SID, 0, 0)), /unknown or revoked keyId/);
  });

  await check('install rejects: non-monotonic seq, broken prev chain, command reuse with different tuple', async () => {
    const now = await nowMs();
    const head = (await readSourceLease(await poolExec(pool), resolver, SID))!;
    await assert.rejects(() => tx.transaction((exec) => installLeaseGrant(exec, resolver, grant({ leaseGrantSeq: 2, prevGrantDigest: head.grantDigest, commandId: 'dup', leaseExpiresAtMs: now + HOUR }))), /strictly-increasing/);
    await assert.rejects(() => tx.transaction((exec) => installLeaseGrant(exec, resolver, grant({ leaseGrantSeq: 3, prevGrantDigest: '0'.repeat(64), commandId: 'badchain', leaseExpiresAtMs: now + HOUR }))), /does not chain/);
    // reuse commandId 'grant-1' (seq1) with a different tuple → quarantine
    await assert.rejects(() => tx.transaction((exec) => installLeaseGrant(exec, resolver, grant({ leaseGrantSeq: 3, prevGrantDigest: head.grantDigest, commandId: 'grant-1', leaseExpiresAtMs: now + 999 }))), /reused with a different grant tuple/);
  });

  await check('tamper: a corrupted head signature fails the guard verify on read', async () => {
    await pool.query("UPDATE tsk_source_lease SET guard_signature='AAAA' WHERE stream_id=$1", [SID]);
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID, 0, 0)), /invalid signature/);
  });

  await check('lock-based revoke → the gate fails closed at the fenced epoch', async () => {
    const SID2 = 'tsk:pair:pr2b0-revoke/v1';
    const now = await nowMs();
    const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID2, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'r-grant', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, g));
    await tx.transaction(async (exec) => { await assertSourceLeaseWritable(exec, resolver, SID2, 0, 0); });
    const head = (await readSourceLease(await poolExec(pool), resolver, SID2))!;
    const revoke = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID2, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: 'r-revoke', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 2, prevGrantDigest: head.grantDigest });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, revoke));
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID2, 0, 0)), SourceFenceQuarantineError);
  });

  // ── M4: external restore/fork witness ──
  const H = (x: string) => x.repeat(64).slice(0, 64);
  const WSID = 'tsk:pair:witness/v1';
  await check('witness: advance genesis; assertConsistent ok for >= high-water; advance rejects regression', async () => {
    await tx.transaction((exec) => advanceSourceWitness(exec, resolver, GUARD_KEY, guardSecret, { streamId: WSID, sourceSystemId: 'sysA', grantSeq: 2, sourceSeq: 5, headDigest: H('a') }));
    const w = await tx.transaction((exec) => readSourceWitness(exec, resolver, WSID));
    assert.equal(w?.maxSourceSeq, 5); assert.equal(w?.witnessSeq, 1);
    assertSourceWitnessConsistent(w, { sourceSystemId: 'sysA', grantSeq: 2, sourceSeq: 5, headDigest: H('a') }); // exact high-water
    assertSourceWitnessConsistent(w, { sourceSystemId: 'sysA', grantSeq: 3, sourceSeq: 7, headDigest: H('b') }); // advanced ok
    // advance forward
    await tx.transaction((exec) => advanceSourceWitness(exec, resolver, GUARD_KEY, guardSecret, { streamId: WSID, sourceSystemId: 'sysA', grantSeq: 3, sourceSeq: 7, headDigest: H('b') }));
    // advancing with a regressed high-water is rejected
    await assert.rejects(() => tx.transaction((exec) => advanceSourceWitness(exec, resolver, GUARD_KEY, guardSecret, { streamId: WSID, sourceSystemId: 'sysA', grantSeq: 3, sourceSeq: 4, headDigest: H('b') })), /restore\/rollback/);
  });
  await check('witness detects: restore (grant/seq regression), same-height FORK, system_identifier change, tamper', async () => {
    const w = (await tx.transaction((exec) => readSourceWitness(exec, resolver, WSID)))!; // sysA, gs3, ss7, headB
    const live = (over: Partial<SourceLiveState>): SourceLiveState => ({ sourceSystemId: 'sysA', grantSeq: 3, sourceSeq: 7, headDigest: H('b'), ...over });
    assert.throws(() => assertSourceWitnessConsistent(w, live({ grantSeq: 2 })), /restore\/rollback/);       // grant_seq regressed
    assert.throws(() => assertSourceWitnessConsistent(w, live({ sourceSeq: 6 })), /restore\/rollback/);      // source seq regressed
    assert.throws(() => assertSourceWitnessConsistent(w, live({ headDigest: H('c') })), /same-height FORK/); // divergent head @ ss7
    assert.throws(() => assertSourceWitnessConsistent(w, live({ sourceSystemId: 'sysB' })), /system_identifier changed/);
    assert.doesNotThrow(() => assertSourceWitnessConsistent(null, live({}))); // genesis ok
    await pool.query("UPDATE tsk_source_witness SET guard_signature='AAAA' WHERE stream_id=$1", [WSID]);
    await assert.rejects(() => tx.transaction((exec) => readSourceWitness(exec, resolver, WSID)), /invalid signature/);
  });

  console.log(`\n# ${passed} PR2b-0 source fence-gate checks passed`);
  await pool.end().catch(() => {});
}

// tiny adapter so read helpers can run outside a transactor tx (autocommit pool query)
async function poolExec(pool: pg.Pool): Promise<{ query: (text: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[]; rowCount: number }> }> {
  return { query: async (text: string, params?: unknown[]) => { const r = await pool.query(text, params as never); return { rows: r.rows as Record<string, unknown>[], rowCount: r.rowCount ?? 0 }; } };
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
