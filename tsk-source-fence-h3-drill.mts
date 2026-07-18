/**
 * PR2b-0 (H3) — REAL concurrency + LOGICAL restore/fork drills.
 *  (1) Barrier-controlled concurrent append-vs-revoke on two live connections: while an append holds
 *      the lease FOR SHARE mid-tx, a conflicting revoke UPDATE genuinely BLOCKS (proven via pg_locks),
 *      commits only AFTER the in-flight append commits, then new appends fail closed. The lock-based
 *      revoke is the freeze authority — it cannot jump ahead of in-flight writers.
 *  (2) LOGICAL source rollback → divergent-write FORK: the committed source tables are snapshotted
 *      (CTAS), grown + witnessed via the ledger-derived issuer, then LOGICALLY rolled back to the
 *      snapshot (DELETE + UPDATE) and re-grown with DIFFERENT content (real head digests). The witness
 *      quarantines the fork via C5 continuity. NB: this is a LOGICAL point-in-time rollback, NOT a
 *      physical PITR / pg_basebackup restore — a physical-restore matrix is a later gate.
 *
 * Env: TSK_TEST_SOURCE_PG_URL_A (source A), TSK_TEST_CONTROL_PG_URL (control/witness).
 * REAL PG16 concurrency (part 1) + a real LOGICAL rollback (part 2), NOT a tx-throw simulation.
 * #10 stays OPEN. Child-process SIGKILL matrix + physical PITR restore remain PR2c.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import pg from 'pg';
import {
  TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA, TSK_SOURCE_WITNESS_SCHEMA, TSK_SOURCE_WITNESS_TABLES,
  provisionSchemaVersion, PgTskDurableOutbox, NodePostgresTransactor, ContractValidationError,
  signLeaseGrant, installLeaseGrant, assertSourceFenceReady, advanceSourceWitness, assertSourceWitnessReady,
  readSourceWitness, issueSourceCheckpointReceipt, SourceFenceQuarantineError,
  type PgTransactor, type StreamHeadSigner, type HotpMutationSanitizer, type SanitizedMutation,
  type TskHotpMutation, type SourceVerifyKeyResolver, type LeaseGrant, type SourceGateConfig,
} from './packages/server/dist/index.js';

const A_URL = process.env['TSK_TEST_SOURCE_PG_URL_A'] ?? process.env['TSK_TEST_SOURCE_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
const C_URL = process.env['TSK_TEST_CONTROL_PG_URL'];
if (!A_URL || !C_URL) throw new Error('TSK_TEST_SOURCE_PG_URL_A + TSK_TEST_CONTROL_PG_URL are required');

const GUARD_KEY = 'guard-1'; const guard = generateKeyPairSync('ed25519'); const guardSecret = guard.privateKey;
const SOURCE_KEY = 'source-1'; const source = generateKeyPairSync('ed25519'); const sourceSecret = source.privateKey;
const resolver: SourceVerifyKeyResolver = { resolve: (k) => (k === GUARD_KEY ? guard.publicKey : k === SOURCE_KEY ? source.publicKey : null) };
const HOUR = 3_600_000; const GEN = '0'.repeat(64);
const { privateKey } = generateKeyPairSync('ed25519');
const plainSigner: StreamHeadSigner = { keyId: 'k1', alg: 'ed25519', async sign(d) { return edSign(null, Buffer.from(d, 'utf8'), privateKey).toString('base64url'); } };
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof raw.tumblerId !== 'string' || !Number.isInteger(raw.counter)) throw new ContractValidationError('bad'); return { tumblerId: raw.tumblerId, counter: raw.counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object') throw new ContractValidationError('unsanitized'); },
};

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitUntil(pred: () => Promise<boolean> | boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  for (;;) { if (await pred()) return; if (Date.now() - start > timeoutMs) throw new Error('waitUntil timed out'); await sleep(15); }
}

async function main() {
  console.log('# TSK PR2b-0 H3 real concurrency + restore/fork drill (real A-PG + control-PG)');
  const aPool = new pg.Pool({ connectionString: A_URL, max: 8 }); aPool.on('error', () => {});
  const cPool = new pg.Pool({ connectionString: C_URL, max: 4 }); cPool.on('error', () => {});
  const aTx = new NodePostgresTransactor(aPool as never) as unknown as PgTransactor;
  const cTx = new NodePostgresTransactor(cPool as never) as unknown as PgTransactor;

  await aPool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, tsk_source_lease_history, snap_rows, snap_cp CASCADE');
  for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await aPool.query(s);
  const READY = await provisionSchemaVersion(aTx, 'public');
  await cPool.query(`DROP TABLE IF EXISTS ${TSK_SOURCE_WITNESS_TABLES.join(', ')} CASCADE`);
  for (const s of TSK_SOURCE_WITNESS_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await cPool.query(s);

  const nowMs = async () => Number((await aPool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  const seqOf = async (sid: string) => Number((await aPool.query('SELECT sequence FROM tsk_outbox_source_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence);
  const aSysId = String((await aPool.query('SELECT system_identifier::text AS s FROM pg_control_system()')).rows[0].s);
  async function provision(sid: string) { await aPool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [sid]); await aPool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [sid, 'e1']); }
  const grant = async (sid: string, over: Record<string, unknown> = {}): Promise<LeaseGrant> => signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: 'g1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 1, prevGrantDigest: null, ...over } as never);
  const mkGate = async (sid: string, g: LeaseGrant): Promise<SourceGateConfig> => ({ mode: 'fenced', resolver, controlToASkewBoundMs: 0, ready: await assertSourceFenceReady(aTx, 'public', { streamId: sid, holderNodeId: g.holderNodeId, leaseId: g.leaseId, grantDigest: g.grantDigest }) });
  const append = (ob: PgTskDurableOutbox, sid: string, counter: number) => ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter }, fenceToken: 0n }));
  // real head at a given committed source height, straight from the row chain (for assertions only)
  const headAt = async (sid: string, seq: number): Promise<string> => seq <= 0 ? GEN : String((await aPool.query('SELECT head_digest FROM tsk_outbox_rows WHERE stream_id=$1 AND sequence=$2', [sid, seq])).rows[0].head_digest);
  // (H5) a checkpoint receipt DERIVED from the committed ledger at the CURRENT height by the atomic,
  // schema-pinned, FOR SHARE-locked issuer (not hand-built from unlocked queries).
  const issue = (sid: string) => issueSourceCheckpointReceipt(aTx, 'public', sid, SOURCE_KEY, sourceSecret);

  await check('REAL barrier: while an append holds the lease FOR SHARE, a revoke UPDATE blocks (pg_locks), commits only after the append, then new appends fail closed', async () => {
    const sid = 'tsk:h3:barrier/v1'; await provision(sid); const g = await grant(sid);
    await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
    // a signer that pauses the FIRST append mid-tx (FOR SHARE on the lease is held at this point)
    let release: (() => void) | null = null; let armed = true;
    const barrierSigner: StreamHeadSigner = { keyId: 'k1', alg: 'ed25519', async sign(d) { if (armed) { armed = false; await new Promise<void>((r) => { release = r; }); } return edSign(null, Buffer.from(d, 'utf8'), privateKey).toString('base64url'); } };
    const ob = new PgTskDurableOutbox(aTx, READY, { streamId: sid, sanitizer, signer: barrierSigner, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation', sourceLeaseGate: await mkGate(sid, g) });
    const appendP = append(ob, sid, 1); // starts, then blocks in the signer while holding FOR SHARE
    await waitUntil(() => release !== null); // append is now paused mid-tx with the lease locked
    // a conflicting revoke on an INDEPENDENT connection — it must WAIT on the lease row lock
    const rev = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: 'r1', leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
    let revokeDone = false;
    const revokeP = aTx.transaction((exec) => installLeaseGrant(exec, resolver, rev)).then(() => { revokeDone = true; });
    // prove the revoke is genuinely blocked on a lock while the append holds FOR SHARE
    await waitUntil(async () => Number((await aPool.query('SELECT count(*)::int n FROM pg_locks WHERE NOT granted')).rows[0].n) >= 1);
    assert.equal(revokeDone, false, 'the revoke has not committed while the append holds FOR SHARE');
    const before = await seqOf(sid);
    (release as unknown as () => void)(); // let the in-flight append finish
    await appendP; // the append COMMITS (a revoke cannot jump ahead of an in-flight writer)
    assert.equal(await seqOf(sid), before + 1, 'the in-flight append committed');
    await revokeP; // only now does the revoke proceed
    assert.equal(revokeDone, true, 'the revoke committed after the append released the lock');
    // and the freeze is now authoritative — new appends fail closed
    const ob2 = new PgTskDurableOutbox(aTx, READY, { streamId: sid, sanitizer, signer: plainSigner, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation', sourceLeaseGate: await mkGate(sid, g) });
    const at = await seqOf(sid);
    await assert.rejects(() => append(ob2, sid, 2), SourceFenceQuarantineError);
    assert.equal(await seqOf(sid), at, 'nothing committed after the authoritative freeze');
  });

  await check('REAL restore+FORK: logically roll the source back to an earlier snapshot, re-grow with different content, witness quarantines the fork', async () => {
    const sid = 'tsk:h3:fork/v1'; await provision(sid); const g = await grant(sid);
    await aTx.transaction((exec) => installLeaseGrant(exec, resolver, g));
    const wReady = await assertSourceWitnessReady(cTx, 'public'); // (H3) db/schema-bound witness capability
    const ob = new PgTskDurableOutbox(aTx, READY, { streamId: sid, sanitizer, signer: plainSigner, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation', sourceLeaseGate: await mkGate(sid, g) });
    // grow to height 2, SNAPSHOT the real committed source tables, then ISSUE + WITNESS the ledger-derived receipt@2
    await append(ob, sid, 10); await append(ob, sid, 20);
    await aPool.query('CREATE TABLE snap_rows AS SELECT * FROM tsk_outbox_rows WHERE stream_id=$1', [sid]);
    await aPool.query('CREATE TABLE snap_cp AS SELECT * FROM tsk_outbox_source_checkpoint WHERE stream_id=$1', [sid]);
    await advanceSourceWitness(cTx, wReady, resolver, GUARD_KEY, guardSecret, await issue(sid)); // witness@2 (issuer derives height 2)
    // grow to height 3 (ORIGINAL timeline) and WITNESS the real ledger-derived head@3
    await append(ob, sid, 30);
    const headAt3orig = await headAt(sid, 3);
    await advanceSourceWitness(cTx, wReady, resolver, GUARD_KEY, guardSecret, await issue(sid)); // witness@3 (issuer derives height 3)
    const wBefore = await cTx.transaction((exec) => readSourceWitness(exec, resolver, sid));
    assert.equal(wBefore?.maxSourceSeq, 3); assert.equal(wBefore?.headDigest, headAt3orig, 'witness pinned the real head@3');
    // LOGICAL ROLLBACK to the height-2 snapshot (real DELETE + reinsert of the committed rows — a logical
    // point-in-time rollback via CTAS+DELETE/UPDATE, NOT a physical PITR/pg_basebackup restore).
    await aPool.query('DELETE FROM tsk_outbox_rows WHERE stream_id=$1 AND sequence >= 3', [sid]);
    await aPool.query('UPDATE tsk_outbox_source_checkpoint c SET sequence = s.sequence, head_digest = s.head_digest, source_epoch = s.source_epoch FROM snap_cp s WHERE c.stream_id=$1 AND s.stream_id=$1', [sid]);
    assert.equal(await seqOf(sid), 2, 'source logically rolled back to height 2');
    // DIVERGENT re-growth with DIFFERENT content → real fork heads (Hfork3 != Horig3), grown BEYOND the witnessed height
    await append(ob, sid, 777); await append(ob, sid, 888); // seq 3,4 on the forked timeline
    const headAt3fork = await headAt(sid, 3);
    assert.notEqual(headAt3fork, headAt3orig, 'the fork produced a genuinely different head@3');
    // the witness is at height 3 (Horig3); the issuer-derived receipt from the forked height-4 state carries
    // priorHead@3 = Hfork3 (real, != Horig3), so C5 continuity at the witnessed height quarantines it.
    const receiptFork = await issue(sid);
    await assert.rejects(
      () => advanceSourceWitness(cTx, wReady, resolver, GUARD_KEY, guardSecret, receiptFork),
      /diverges from the witness|restore\/FORK/,
    );
    // sanity: the witness state is unchanged (the fork was rejected, not absorbed)
    const wAfter = await cTx.transaction((exec) => readSourceWitness(exec, resolver, sid));
    assert.equal(wAfter?.headDigest, headAt3orig, 'the witness still pins the original head@3 — fork rejected');
  });

  console.log(`\n# ${passed} PR2b-0 H3 real concurrency + restore/fork checks passed`);
  await aPool.end().catch(() => {}); await cPool.end().catch(() => {});
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
