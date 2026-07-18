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
  signLeaseGrant, installLeaseGrant, assertSourceLeaseWritable, readSourceLease, SourceFenceQuarantineError, assertSourceFenceReady,
  TSK_SOURCE_WITNESS_SCHEMA, TSK_SOURCE_WITNESS_TABLES, advanceSourceWitness, assertSourceWitnessReady, readSourceWitness, assertSourceWitnessConsistent,
  type SourceVerifyKeyResolver, type BareLeaseGrant, type LeaseGrant, type SourceLiveState, type SourceCheckpointReceipt,
} from './packages/server/dist/index.js';
// (H3) the low-level signer + in-tx witness primitive are NOT on the public package API — internal
// module-path import for protocol/continuity/crash tests only (production uses the owned issuer/advance).
import { signSourceCheckpointReceipt } from './packages/server/dist/tsk-source-fence.js';

const URL = process.env['TSK_TEST_SOURCE_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
if (!URL) throw new Error('TSK_TEST_SOURCE_PG_URL (source PG16) is required');

const GUARD_KEY = 'guard-1'; // ed25519: private signs (control/guard), public verifies (source)
const guard = generateKeyPairSync('ed25519');
const guardSecret = guard.privateKey;
const SOURCE_KEY = 'source-1'; const source = generateKeyPairSync('ed25519'); // source signs its checkpoint receipts
const resolver: SourceVerifyKeyResolver = { resolve: (kid) => (kid === GUARD_KEY ? guard.publicKey : kid === SOURCE_KEY ? source.publicKey : null) };
const GEN = '0'.repeat(64);
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
  // (H1) the gate's identity binding is MANDATORY — a match for pass tests, a structurally-valid dummy
  // for tests that fail closed BEFORE the bound check (epoch/deadline/no-lease/forged-key/status).
  const B = (g: LeaseGrant) => ({ holderNodeId: g.holderNodeId, leaseId: g.leaseId, grantDigest: g.grantDigest });
  const DUMMY_BOUND = { holderNodeId: 'A', leaseId: 'l1', grantDigest: '0'.repeat(64) };

  await check('install grant seq1 (active) → gate passes at epoch 0', async () => {
    const now = await nowMs();
    const g1 = grant({ leaseExpiresAtMs: now + HOUR, commandId: 'grant-1' });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, g1));
    const st = await readSourceLease(await poolExec(pool), resolver, SID);
    assert.equal(st?.leaseStatus, 'active'); assert.equal(st?.leaseGrantSeq, 1);
    await tx.transaction(async (exec) => { const w = await assertSourceLeaseWritable(exec, resolver, SID, 0, 0, B(g1)); assert.equal(w.leaseEpoch, 0); });
  });

  await check('gate rejects: wrong epoch, expired deadline, missing lease, forged/unknown key', async () => {
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID, 1, 0, DUMMY_BOUND)), /epoch .* != expected/);
    // an already-elapsed deadline (past) → reject even at the right epoch
    const past = grant({ leaseExpiresAtMs: (await nowMs()) - 10_000, commandId: 'grant-past', leaseGrantSeq: 2, prevGrantDigest: (await readSourceLease(await poolExec(pool), resolver, SID))!.grantDigest });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, past));
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID, 0, 0, DUMMY_BOUND)), /deadline elapsed/);
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, 'tsk:unleased/v1', 0, 0, DUMMY_BOUND)), /not leased/);
    const forged: SourceVerifyKeyResolver = { resolve: () => null };
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, forged, SID, 0, 0, DUMMY_BOUND)), /unknown or revoked keyId/);
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
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID, 0, 0, DUMMY_BOUND)), /invalid signature/);
  });

  await check('lock-based revoke → the gate fails closed at the fenced epoch', async () => {
    const SID2 = 'tsk:pair:pr2b0-revoke/v1';
    const now = await nowMs();
    const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID2, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'r-grant', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, g));
    await tx.transaction(async (exec) => { await assertSourceLeaseWritable(exec, resolver, SID2, 0, 0, B(g)); });
    const head = (await readSourceLease(await poolExec(pool), resolver, SID2))!;
    const revoke = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID2, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: 'r-revoke', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 2, prevGrantDigest: head.grantDigest });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, revoke));
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID2, 0, 0, DUMMY_BOUND)), SourceFenceQuarantineError);
  });

  await check('H2 install: terminal revoke (no same-epoch reactivation), holder/leaseId immutability, epoch monotonicity', async () => {
    const S3 = 'tsk:pair:pr2b0-h2/v1'; const now = await nowMs();
    const mk = (over: Partial<BareLeaseGrant>): LeaseGrant => signLeaseGrant(GUARD_KEY, guardSecret, { streamId: S3, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'x', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 1, prevGrantDigest: null, ...over });
    const g1 = mk({ commandId: 'h2-g1' }); await tx.transaction((exec) => installLeaseGrant(exec, resolver, g1));
    // holder/leaseId immutable within the epoch
    await assert.rejects(() => tx.transaction((exec) => installLeaseGrant(exec, resolver, mk({ holderNodeId: 'B', commandId: 'h2-b', leaseGrantSeq: 2, prevGrantDigest: g1.grantDigest }))), /holder\/leaseId is immutable/);
    // revoke → terminal for the epoch; a new active grant at the same epoch is refused
    const rev = mk({ leaseStatus: 'revoked', commandId: 'h2-rev', leaseGrantSeq: 2, prevGrantDigest: g1.grantDigest });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, rev));
    await assert.rejects(() => tx.transaction((exec) => installLeaseGrant(exec, resolver, mk({ commandId: 'h2-react', leaseGrantSeq: 3, prevGrantDigest: rev.grantDigest }))), /terminally revoked/);
    // epoch cannot regress (a grant at epoch 1 is fine to advance; epoch 0 after is a regression on a higher-epoch head)
    const e1 = mk({ leaseEpoch: 1, commandId: 'h2-e1', leaseGrantSeq: 3, prevGrantDigest: rev.grantDigest });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, e1));
    await assert.rejects(() => tx.transaction((exec) => installLeaseGrant(exec, resolver, mk({ leaseEpoch: 0, commandId: 'h2-regress', leaseGrantSeq: 4, prevGrantDigest: e1.grantDigest }))), /regresses/);
  });

  // ── M4: external restore/fork witness ──
  const wReady = await assertSourceWitnessReady(tx, 'public'); // (H3) db/schema-bound witness capability
  const H = (x: string) => x.repeat(64).slice(0, 64);
  const WSID = 'tsk:pair:witness/v1';
  const ckpt = (over: Partial<Omit<SourceCheckpointReceipt, 'receiptDigest' | 'sourceKeyId' | 'sourceSignature'>>): SourceCheckpointReceipt =>
    signSourceCheckpointReceipt(SOURCE_KEY, source.privateKey, { streamId: WSID, sourceSystemId: 'sysA', sourceSeq: 5, sourceHeadDigest: H('a'), grantSeq: 2, priorSeq: 0, priorHeadDigest: GEN, ...over });
  await check('witness advances only from a SOURCE-SIGNED checkpoint receipt; monotonic; caller-forged state cannot advance', async () => {
    await advanceSourceWitness(tx, wReady, resolver, GUARD_KEY, guardSecret, ckpt({})); // genesis @ ss5
    const w = await tx.transaction((exec) => readSourceWitness(exec, resolver, WSID));
    assert.equal(w?.maxSourceSeq, 5); assert.equal(w?.witnessSeq, 1);
    // advance forward with continuity (priorSeq/head = the witnessed height ss5/H(a))
    await advanceSourceWitness(tx, wReady, resolver, GUARD_KEY, guardSecret, ckpt({ sourceSeq: 7, sourceHeadDigest: H('b'), grantSeq: 3, priorSeq: 5, priorHeadDigest: H('a') }));
    // a receipt signed by an UNKNOWN key (forged, not the source) cannot advance
    const badKp = generateKeyPairSync('ed25519');
    const forged = signSourceCheckpointReceipt(SOURCE_KEY, badKp.privateKey, { streamId: WSID, sourceSystemId: 'sysA', sourceSeq: 9, sourceHeadDigest: H('c'), grantSeq: 4, priorSeq: 7, priorHeadDigest: H('b') });
    await assert.rejects(() => advanceSourceWitness(tx, wReady, resolver, GUARD_KEY, guardSecret, forged), /invalid signature/);
    // regressed source seq rejected
    await assert.rejects(() => advanceSourceWitness(tx, wReady, resolver, GUARD_KEY, guardSecret, ckpt({ sourceSeq: 4, priorSeq: 7, priorHeadDigest: H('b'), grantSeq: 3 })), /restore\/rollback/);
  });
  await check('C5 witness catches a restore+FORK that grew BEYOND the witnessed height (continuity at prior height)', async () => {
    // current witness: ss7, head H(b). A restored+forked source presents a HIGHER seq (ss9) but its head
    // AT the witnessed height (ss7) diverges → continuity check quarantines even though it is longer.
    await assert.rejects(() => advanceSourceWitness(tx, wReady, resolver, GUARD_KEY, guardSecret, ckpt({ sourceSeq: 9, sourceHeadDigest: H('d'), grantSeq: 3, priorSeq: 7, priorHeadDigest: H('c') })), /diverges from the witness/);
    // same-height fork + regression + system change still caught by the pure consistency check
    const w = (await tx.transaction((exec) => readSourceWitness(exec, resolver, WSID)))!;
    const live = (over: Partial<SourceLiveState>): SourceLiveState => ({ sourceSystemId: 'sysA', grantSeq: 3, sourceSeq: 7, headDigest: H('b'), ...over });
    assert.throws(() => assertSourceWitnessConsistent(w, live({ headDigest: H('c') })), /same-height FORK/);
    assert.throws(() => assertSourceWitnessConsistent(w, live({ sourceSystemId: 'sysB' })), /system_identifier changed/);
    await pool.query("UPDATE tsk_source_witness SET guard_signature='AAAA' WHERE stream_id=$1", [WSID]);
    await assert.rejects(() => tx.transaction((exec) => readSourceWitness(exec, resolver, WSID)), /invalid signature/);
  });

  await check('(H2) a verifier holding PRIVATE key material is rejected at the boundary (no forgeable custody)', async () => {
    const SID3 = 'tsk:pair:h2/v1';
    const now = await nowMs();
    const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID3, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'h2-grant', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, g));
    // a resolver that hands back the PRIVATE key (as a KeyObject) must be rejected — a verifier must
    // never hold signer material (this is what would let createPublicKey(<PRIVATE PEM>) launder custody).
    const privResolver: SourceVerifyKeyResolver = { resolve: () => guard.privateKey };
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, privResolver, SID3, 0, 0, { holderNodeId: 'A', leaseId: 'l1', grantDigest: g.grantDigest })), /PUBLIC/);
  });

  await check('(H3) full-catalog attestation catches an UNLOGGED / RLS drift', async () => {
    const ok = await assertSourceFenceReady(tx as never, 'public', { streamId: SID, holderNodeId: 'A', leaseId: 'l1', grantDigest: '0'.repeat(64) });
    assert.ok(ok, 'clean catalog attests');
    await pool.query('ALTER TABLE tsk_source_lease SET UNLOGGED');
    await assert.rejects(() => assertSourceFenceReady(tx as never, 'public', { streamId: SID, holderNodeId: 'A', leaseId: 'l1', grantDigest: '0'.repeat(64) }), /attestation failed/);
    await pool.query('ALTER TABLE tsk_source_lease SET LOGGED'); // revert
    await assertSourceFenceReady(tx as never, 'public', { streamId: SID, holderNodeId: 'A', leaseId: 'l1', grantDigest: '0'.repeat(64) }); // clean again
  });

  await check('(H4) the gate fails closed when the head is not the exact latest history row (fork/relabel)', async () => {
    const SID4 = 'tsk:pair:h4/v1';
    const now = await nowMs();
    const g1 = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID4, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'h4-g1', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 1, prevGrantDigest: null });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, g1));
    const g2 = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID4, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'h4-g2', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 2, prevGrantDigest: g1.grantDigest });
    await tx.transaction((exec) => installLeaseGrant(exec, resolver, g2));
    const bound = { holderNodeId: 'A', leaseId: 'l1', grantDigest: g2.grantDigest };
    await tx.transaction(async (exec) => { await assertSourceLeaseWritable(exec, resolver, SID4, 0, 0, bound); }); // ok: head@2 == latest history
    // delete the latest history row so the (still valid, signed) head no longer matches the latest history
    await pool.query('DELETE FROM tsk_source_lease_history WHERE stream_id=$1 AND lease_grant_seq=2', [SID4]);
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID4, 0, 0, bound)), /latest history row/);
    // and a further install fails the full-chain check too
    const g3 = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID4, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'h4-g3', leaseExpiresAtMs: now + HOUR, leaseGrantSeq: 3, prevGrantDigest: g2.grantDigest });
    await assert.rejects(() => tx.transaction((exec) => installLeaseGrant(exec, resolver, g3)), /not the exact latest history row|not contiguous/);
  });

  await check('(H2) the APPEND gate verifies the FULL chain — deleting an INTERMEDIATE history row fails closed', async () => {
    const SID5 = 'tsk:pair:h2gate/v1';
    const now = await nowMs();
    let prev: string | null = null;
    for (let seq = 1; seq <= 3; seq++) {
      const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: SID5, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: `h2g-${seq}`, leaseExpiresAtMs: now + HOUR, leaseGrantSeq: seq, prevGrantDigest: prev });
      await tx.transaction((exec) => installLeaseGrant(exec, resolver, g)); prev = g.grantDigest;
    }
    const head = (await readSourceLease(await poolExec(pool), resolver, SID5))!;
    const bound = { holderNodeId: 'A', leaseId: 'l1', grantDigest: head.grantDigest };
    await tx.transaction(async (exec) => { await assertSourceLeaseWritable(exec, resolver, SID5, 0, 0, bound); }); // ok: full chain 1..3
    // delete an INTERMEDIATE row (seq2) — head==latest (seq3) still holds, but the chain is now broken
    await pool.query('DELETE FROM tsk_source_lease_history WHERE stream_id=$1 AND lease_grant_seq=2', [SID5]);
    await assert.rejects(() => tx.transaction((exec) => assertSourceLeaseWritable(exec, resolver, SID5, 0, 0, bound)), /not contiguous|chain broken/);
  });

  console.log(`\n# ${passed} PR2b-0 source fence-gate checks passed`);
  await pool.end().catch(() => {});
}

// tiny adapter so read helpers can run outside a transactor tx (autocommit pool query)
async function poolExec(pool: pg.Pool): Promise<{ query: (text: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[]; rowCount: number }> }> {
  return { query: async (text: string, params?: unknown[]) => { const r = await pool.query(text, params as never); return { rows: r.rows as Record<string, unknown>[], rowCount: r.rowCount ?? 0 }; } };
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
