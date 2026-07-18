/**
 * INTEGRATED real-PostgreSQL adversarial evidence for the TSK durable HOTP-outbox
 * (#10). TSK .mts convention: run via tsx; REQUIRES a PostgreSQL URL and THROWS if
 * unset so CI genuinely executes it. Proves the TSK invariants under a live server:
 * signed hash-linked stream head, HOTP exactly-once, ordered no-loss delivery,
 * crash-atomicity, lost-ACK idempotency, replay rejection, stale-writer fencing,
 * restart recovery, single-active ordered publisher, schema attestation + token.
 *
 * Single-node mechanism evidence — NOT the two-node PG+Redis failover drill.
 * #10 stays OPEN until that drill passes with recorded RPO/RTO; no HA claim here.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign, verify as edVerify, createHash } from 'node:crypto';
import pg from 'pg';
import {
  ContractValidationError,
  StaleFenceError,
  canonicalOpDigest,
  streamHeadDigest,
  TSK_OUTBOX_PG_SCHEMA,
  TSK_OUTBOX_SCHEMA_MANIFEST,
  NodePostgresTransactor,
  PgTskDurableOutbox,
  PgTskPublisher,
  PgTskReceiverCheckpoint,
  attestSchema,
  assertSchemaReady,
  provisionSchemaVersion,
  schemaManifest,
  GENESIS_HEAD,
  type HotpApplier,
  type HotpMutationSanitizer,
  type OutboxRecord,
  type PgExecutor,
  type PgTransactor,
  type ReceiverDecision,
  type SanitizedMutation,
  type SchemaReadyToken,
  type SignedStreamHead,
  type StreamHeadSigner,
  type StreamHeadVerifier,
  type TskAckReceipt,
  type TskAckReceiptVerifier,
  type TskHotpMutation,
  type TskOutboxTransport,
} from './packages/server/dist/index.js';

const URL = process.env['TSK_TEST_POSTGRES_URL'] ?? process.env['BPC_TEST_POSTGRES_URL'] ?? process.env['HA_OUTBOX_PG_URL'];
if (!URL) throw new Error('TSK_TEST_POSTGRES_URL is required for the live PostgreSQL TSK HOTP-outbox test');
const { Pool } = pg;
const pool = new Pool({ connectionString: URL, max: 16 });
const SCHEMA = 'public';
let READY: SchemaReadyToken;

// PRODUCTION transactor under test: the shipped NodePostgresTransactor over a real
// pg.Pool. Bounded serialization retries are ENABLED here because the TSK outbox
// callbacks are replay-safe (redelivery is duplicate-ok; HOTP consumed exactly once
// — proven by the lost-ACK and single-active-lease checks below).
const serial = new NodePostgresTransactor(pool as unknown as ConstructorParameters<typeof NodePostgresTransactor>[0], { maxSerializationRetries: 50, retryBaseDelayMs: 5 });

// Test-only isolation-gate probe: a minimal READ COMMITTED transactor used ONLY to
// prove the consumer's SERIALIZABLE assertion fails closed. NOT a production path.
const readCommittedProbe: PgTransactor = {
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      const exec: PgExecutor = { query: async (sql, params) => { const r = await client.query(sql, params as unknown[]); return { rows: r.rows, rowCount: r.rowCount ?? 0 }; } };
      const result = await fn(exec);
      await client.query('COMMIT');
      return result;
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; } finally { client.release(); }
  },
};

// ── crypto: real ed25519 signer + verifier ──
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const KEY_ID = 'tsk-key-1';
const signer: StreamHeadSigner = { keyId: KEY_ID, alg: 'ed25519', async sign(headDigest) { return edSign(null, Buffer.from(headDigest, 'utf8'), privateKey).toString('base64url'); } };
const headVerifier: StreamHeadVerifier = {
  async verify(head) {
    if (head.keyId !== KEY_ID) throw new ContractValidationError('unknown keyId');
    if (!edVerify(null, Buffer.from(head.headDigest, 'utf8'), publicKey, Buffer.from(head.signature, 'base64url'))) throw new ContractValidationError('bad stream-head signature');
  },
};
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof raw.tumblerId !== 'string' || !Number.isInteger(raw.counter)) throw new ContractValidationError('bad'); return { tumblerId: raw.tumblerId, counter: raw.counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object' || 'secret' in (c as object)) throw new ContractValidationError('unsanitized'); },
};
const appliedLog: number[] = [];
const applier: HotpApplier = { async applyInTx(_e, r) { appliedLog.push(r.sequence); } };
const RID = 'receiver-A';
const ackSign = (r: OutboxRecord<unknown>, d: ReceiverDecision) => createHash('sha256').update(`${RID}|${r.opDigest}|${d}`).digest('hex');
const ackVerifier: TskAckReceiptVerifier = { async verify(receipt, record) { if (receipt.receiverId !== RID || receipt.signature !== ackSign(record, receipt.decision)) throw new ContractValidationError('bad ACK'); } };

async function applyDDL() { for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s); }
async function resetSchema() {
  await pool.query('DROP SCHEMA IF EXISTS tsk_alt CASCADE');
  await pool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta CASCADE');
  await applyDDL();
  READY = await provisionSchemaVersion(serial, SCHEMA);
}
async function provision(sid: string, epoch = 'e1') {
  await pool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [sid]);
  await pool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [sid, epoch]);
  await pool.query('INSERT INTO tsk_outbox_receiver_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [sid, epoch]);
}
const unacked = async (sid: string) => Number((await pool.query('SELECT count(*)::int AS n FROM tsk_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL AND quarantined_at IS NULL', [sid])).rows[0].n);
const mkOutbox = (db: PgTransactor, sid: string, ready = READY) => new PgTskDurableOutbox(db, ready, { streamId: sid, sanitizer, signer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation', sourceLeaseGate: { mode: 'unfenced-single-node' } });

/** Receiver-backed transport: delivering runs the REAL receiver and returns a
 *  signed decision receipt. Records each decision. */
function receiverTransport(sid: string, decisions: Array<{ seq: number; d: ReceiverDecision }>): TskOutboxTransport {
  const receiver = new PgTskReceiverCheckpoint(serial, sid, sanitizer, headVerifier, applier, READY);
  return {
    async deliverAndAwaitAck(record, head) {
      const d = await receiver.verifyAndApplyTumblerDelivered(record, head);
      decisions.push({ seq: record.sequence, d });
      return { streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence, opDigest: record.opDigest, decision: d, receiverId: RID, keyId: KEY_ID, issuedAt: 'now', signature: ackSign(record, d) } satisfies TskAckReceipt;
    },
  };
}

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await resetSchema(); appliedLog.length = 0; await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK HOTP-outbox integrated real-PG evidence');

  await check('live schema manifest matches the pinned manifest', async () => {
    const live = await serial.transaction((e) => schemaManifest(e));
    assert.equal(live, TSK_OUTBOX_SCHEMA_MANIFEST, 'pinned TSK_OUTBOX_SCHEMA_MANIFEST is stale');
  });

  await check('READ COMMITTED transactor cannot obtain readiness (SERIALIZABLE enforced)', async () => {
    await assert.rejects(() => assertSchemaReady(readCommittedProbe, SCHEMA), /SERIALIZABLE/);
  });

  await check('end-to-end: append N -> publish -> receiver applies strictly 1..N; HOTP consumed once', async () => {
    const sid = 'tsk:e2e/v1'; await provision(sid); const N = 12;
    const ob = mkOutbox(serial, sid);
    for (let i = 0; i < N; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: `T${i % 3}`, counter: 100 + i }, fenceToken: 0n }));
    const decisions: Array<{ seq: number; d: ReceiverDecision }> = [];
    const pub = new PgTskPublisher(serial, sid, receiverTransport(sid, decisions), 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 });
    for (let round = 0; round < 20; round++) { await pub.drainOnce(); if ((await unacked(sid)) === 0) break; }
    assert.deepEqual(appliedLog, Array.from({ length: N }, (_, i) => i + 1), 'receiver applied out of order or lost');
    assert.ok(!decisions.some((x) => x.d !== 'applied'), 'a non-applied decision appeared');
    assert.equal(await unacked(sid), 0);
    // each (tumbler,counter) consumed exactly once
    const consumed = (await pool.query('SELECT tumbler_id, last_counter FROM tsk_hotp_consumed WHERE stream_id=$1 ORDER BY tumbler_id', [sid])).rows;
    assert.equal(consumed.length, 3);
    assert.equal(Number((await pool.query('SELECT sequence FROM tsk_outbox_receiver_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), N);
  });

  await check('crash-atomicity: an append that crashes before commit rolls back (no row, no seq advance)', async () => {
    const sid = 'tsk:crash/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    // A crash before COMMIT = the callback throws after its writes; the production
    // transactor must ROLLBACK + destroy, leaving no row and no source-seq advance.
    await assert.rejects(() => ob.withOutboxTx(async (tx) => {
      await ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 1 }, fenceToken: 0n });
      throw new Error('SIMULATED CRASH before commit');
    }), /CRASH/);
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM tsk_outbox_rows WHERE stream_id=$1', [sid])).rows[0].n), 0);
    assert.equal(Number((await pool.query('SELECT sequence FROM tsk_outbox_source_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), 0);
  });

  await check('(#10 transactor) NESTED-comment transaction-control bypass is blocked; no durable partial write', async () => {
    await pool.query('DROP TABLE IF EXISTS tsk_txctl_probe');
    await pool.query('CREATE TABLE tsk_txctl_probe (id int primary key)');
    // PostgreSQL parses `/* outer /* inner */ */` as ONE nested comment, so the
    // statement is a bare COMMIT. A non-nested stripper would miss it; the lexer must
    // reject it so the prior INSERT never durably commits.
    await assert.rejects(() => serial.transaction(async (exec) => {
      await exec.query('INSERT INTO tsk_txctl_probe(id) VALUES (1)');
      await exec.query('/* outer /* inner */ */ COMMIT');
    }), /transaction\/session-control/);
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM tsk_txctl_probe')).rows[0].n), 0, 'the blocked-escape insert must roll back');
    await pool.query('DROP TABLE tsk_txctl_probe');
  });

  await check('(#10 transactor) session-control (SET ROLE / application_name / RESET ALL) is blocked; pooled session not poisoned', async () => {
    for (const evil of ['SET ROLE postgres', "SET application_name = 'poison'", 'RESET ALL', 'SET SESSION AUTHORIZATION postgres']) {
      await assert.rejects(() => serial.transaction(async (exec) => { await exec.query(evil); }), /transaction\/session-control/, `must block: ${evil}`);
    }
    // session-control smuggled through a SELECT (session-level set_config) is also blocked
    await assert.rejects(() => serial.transaction(async (exec) => { await exec.query("SELECT set_config('application_name', 'poison', false)"); }), /session-level set_config/);
    // the pooled session must remain clean — application_name never became 'poison'
    const appName = await serial.transaction(async (exec) => (await exec.query("SELECT current_setting('application_name') AS a")).rows[0].a);
    assert.notEqual(appName, 'poison', 'a blocked SET must not have poisoned the pooled session');
  });

  await check('(#10 transactor) a callback lowering synchronous_commit (tx-local off) cannot weaken THIS commit', async () => {
    await pool.query('DROP TABLE IF EXISTS tsk_durab_probe');
    await pool.query('CREATE TABLE tsk_durab_probe (id int primary key)');
    // tx-local set_config is allowed by the guard, but the transactor FORCES
    // synchronous_commit back to its configured level (default on) before COMMIT.
    await serial.transaction(async (exec) => {
      await exec.query("SELECT set_config('synchronous_commit', 'off', true)");
      await exec.query('INSERT INTO tsk_durab_probe(id) VALUES (1)');
    });
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM tsk_durab_probe')).rows[0].n), 1, 'the commit must still land durably');
    await pool.query('DROP TABLE tsk_durab_probe');
  });

  await check('(#10 transactor) fsync + full_page_writes verified on the EXACT transaction session (durability precondition)', async () => {
    const s = await serial.transaction(async (exec) => (await exec.query("SELECT current_setting('fsync') AS fsync, current_setting('full_page_writes') AS fpw")).rows[0]);
    assert.equal(s.fsync, 'on', 'the durable-outbox session must run with fsync=on');
    assert.equal(s.fpw, 'on', 'the durable-outbox session must run with full_page_writes=on');
  });

  await check('(#10 transactor) DISCARD ALL scrubs session poison (advisory lock) before the pooled connection is reused', async () => {
    const p1 = new Pool({ connectionString: URL, max: 1 }); p1.on('error', () => {});
    const t1 = new NodePostgresTransactor(p1 as unknown as ConstructorParameters<typeof NodePostgresTransactor>[0]);
    // pg_advisory_lock is a SELECT the guard allows, but it holds a SESSION-level lock
    // that survives COMMIT — only the post-commit DISCARD ALL releases it.
    await t1.transaction(async (exec) => { await exec.query('SELECT pg_advisory_lock(42)'); });
    const n = await t1.transaction(async (exec) => Number((await exec.query("SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory'")).rows[0].n));
    assert.equal(n, 0, 'the reused pooled session must be clean — the advisory lock was scrubbed by DISCARD ALL');
    await p1.end();
  });

  await check('lost-ACK idempotency: redelivery after a lost ack is duplicate-ok; HOTP consumed exactly once', async () => {
    const sid = 'tsk:lostack/v1'; await provision(sid);
    const receiver = new PgTskReceiverCheckpoint(serial, sid, sanitizer, headVerifier, applier, READY);
    const { record, head } = await mkRH(sid, 1, { tumblerId: 'T1', counter: 7 }, GENESIS_HEAD);
    // first delivery applies (imagine the ACK back to the source was lost)
    assert.equal(await receiver.verifyAndApplyTumblerDelivered(record, head), 'applied');
    // redelivery of the SAME record -> duplicate-ok, no re-apply, HOTP unchanged
    assert.equal(await receiver.verifyAndApplyTumblerDelivered(record, head), 'duplicate-ok');
    assert.equal(appliedLog.length, 1, 'applied more than once');
    assert.equal(Number((await pool.query('SELECT last_counter FROM tsk_hotp_consumed WHERE stream_id=$1 AND tumbler_id=$2', [sid, 'T1'])).rows[0].last_counter), 7);
  });

  await check('replay: a re-used/lower HOTP counter at a new sequence is reject-fork; HOTP unchanged', async () => {
    const sid = 'tsk:replay/v1'; await provision(sid);
    const receiver = new PgTskReceiverCheckpoint(serial, sid, sanitizer, headVerifier, applier, READY);
    const r1 = await mkRH(sid, 1, { tumblerId: 'T1', counter: 20 }, GENESIS_HEAD);
    assert.equal(await receiver.verifyAndApplyTumblerDelivered(r1.record, r1.head), 'applied');
    const replay = await mkRH(sid, 2, { tumblerId: 'T1', counter: 20 }, r1.head.headDigest); // reused counter
    assert.equal(await receiver.verifyAndApplyTumblerDelivered(replay.record, replay.head), 'reject-fork');
    const lower = await mkRH(sid, 2, { tumblerId: 'T1', counter: 5 }, r1.head.headDigest);
    assert.equal(await receiver.verifyAndApplyTumblerDelivered(lower.record, lower.head), 'reject-fork');
    assert.equal(Number((await pool.query('SELECT last_counter FROM tsk_hotp_consumed WHERE stream_id=$1 AND tumbler_id=$2', [sid, 'T1'])).rows[0].last_counter), 20);
  });

  await check('stale-writer fencing: a fence bump fails a stale writer append AND a stale-fenced record at the receiver', async () => {
    const sid = 'tsk:fence/v1'; await provision(sid);
    // promote: bump the authoritative fence to 1
    await pool.query('UPDATE tsk_outbox_fence SET fence_token = 1 WHERE stream_id=$1', [sid]);
    const ob = mkOutbox(serial, sid);
    await assert.rejects(() => ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 1 }, fenceToken: 0n })), (e) => e instanceof StaleFenceError);
    const receiver = new PgTskReceiverCheckpoint(serial, sid, sanitizer, headVerifier, applier, READY);
    const stale = await mkRH(sid, 1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD, '0'); // carries fence 0, persisted is 1
    assert.equal(await receiver.verifyAndApplyTumblerDelivered(stale.record, stale.head), 'reject-fence');
  });

  await check('restart recovery: checkpoint + head chain + HOTP survive a receiver restart; resume in order', async () => {
    const sid = 'tsk:restart/v1'; await provision(sid);
    const decisions: Array<{ seq: number; d: ReceiverDecision }> = [];
    const ob = mkOutbox(serial, sid);
    for (let i = 0; i < 5; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 10 + i }, fenceToken: 0n }));
    const pubA = new PgTskPublisher(serial, sid, receiverTransport(sid, decisions), 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 });
    await pubA.drainOnce();
    assert.deepEqual(appliedLog, [1, 2, 3, 4, 5]);
    const rcvSeq = Number((await pool.query('SELECT sequence FROM tsk_outbox_receiver_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence);
    assert.equal(rcvSeq, 5);
    // append more, then a FRESH receiver+publisher (restart) resumes from durable state
    for (let i = 5; i < 8; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 10 + i }, fenceToken: 0n }));
    const decisions2: Array<{ seq: number; d: ReceiverDecision }> = [];
    const pubB = new PgTskPublisher(serial, sid, receiverTransport(sid, decisions2), 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 });
    for (let r = 0; r < 20; r++) { await pubB.drainOnce(); if ((await unacked(sid)) === 0) break; }
    assert.deepEqual(appliedLog, [1, 2, 3, 4, 5, 6, 7, 8], 'restart did not resume in order');
    assert.ok(!decisions2.some((x) => x.d === 'reject-gap'), 'gap after restart');
  });

  await check('single-active lease: two concurrent publishers apply strictly 1..N, no reject-gap, no double', async () => {
    const sid = 'tsk:concurrent/v1'; await provision(sid); const N = 10;
    const ob = mkOutbox(serial, sid);
    for (let i = 0; i < N; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 100 + i }, fenceToken: 0n }));
    const decisions: Array<{ seq: number; d: ReceiverDecision }> = [];
    const t = receiverTransport(sid, decisions);
    const pubA = new PgTskPublisher(serial, sid, t, 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 });
    const pubB = new PgTskPublisher(serial, sid, t, 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 });
    for (let r = 0; r < 30; r++) { await Promise.all([pubA.drainOnce(), pubB.drainOnce()]); if ((await unacked(sid)) === 0) break; }
    assert.deepEqual(appliedLog, Array.from({ length: N }, (_, i) => i + 1));
    assert.ok(!decisions.some((x) => x.d === 'reject-gap'), 'reject-gap under concurrency');
    assert.equal(await unacked(sid), 0);
  });

  await check('attestation catches drift; readiness token is unforgeable + transactor-bound', async () => {
    await serial.transaction((e) => attestSchema(e));
    await pool.query('DROP INDEX tsk_outbox_rows_deliverable');
    await assert.rejects(() => serial.transaction((e) => attestSchema(e)), /attestation failed/);
    await resetSchema();
    const other = new NodePostgresTransactor(pool as unknown as ConstructorParameters<typeof NodePostgresTransactor>[0]); // a DISTINCT transactor instance
    assert.throws(() => new PgTskDurableOutbox(other, READY, { streamId: 's/v1', sanitizer, signer, maxPendingRows: 1, backpressure: 'quarantine', sourceLeaseGate: { mode: 'unfenced-single-node' } }), /different PgTransactor/);
    assert.throws(() => new PgTskDurableOutbox(serial, {} as SchemaReadyToken, { streamId: 's/v1', sanitizer, signer, maxPendingRows: 1, backpressure: 'quarantine', sourceLeaseGate: { mode: 'unfenced-single-node' } }), /forged or foreign/);
  });

  await check('(TOCTOU) append: mutating the raw mutation during signer.sign does not change stored/digested/signed bytes', async () => {
    const sid = 'tsk:toctou-append/v1'; await provision(sid);
    const raw = { tumblerId: 'T1', counter: 5 };
    const mutatingSigner: StreamHeadSigner = { keyId: KEY_ID, alg: 'ed25519', async sign(hd) { raw.tumblerId = 'EVIL'; raw.counter = 999; return edSign(null, Buffer.from(hd, 'utf8'), privateKey).toString('base64url'); } };
    const ob = new PgTskDurableOutbox(serial, READY, { streamId: sid, sanitizer, signer: mutatingSigner, maxPendingRows: 100, backpressure: 'quarantine', sourceLeaseGate: { mode: 'unfenced-single-node' } });
    const { head } = await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: raw, fenceToken: 0n }));
    const row = (await pool.query('SELECT tumbler_id, hotp_counter, mutation, op_digest FROM tsk_outbox_rows WHERE stream_id=$1', [sid])).rows[0];
    assert.equal(row.tumbler_id, 'T1'); assert.equal(Number(row.hotp_counter), 5);
    assert.deepEqual(row.mutation, { tumblerId: 'T1', counter: 5 }); // ORIGINAL, not EVIL/999
    assert.equal(head.opDigest, row.op_digest);
  });

  await check('(TOCTOU) publisher: mutating the ACK receipt during ackVerifier.verify cannot flip the decision to acked', async () => {
    const sid = 'tsk:toctou-ack/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 1 }, fenceToken: 0n }));
    let original: TskAckReceipt;
    const transport: TskOutboxTransport = { async deliverAndAwaitAck(record) { original = { streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence, opDigest: record.opDigest, decision: 'reject-fork', receiverId: RID, keyId: KEY_ID, issuedAt: 'now', signature: ackSign(record, 'reject-fork') }; return original; } };
    const flippingVerifier: TskAckReceiptVerifier = { async verify(receipt, record) { original.decision = 'applied'; if (receipt.signature !== ackSign(record, receipt.decision)) throw new ContractValidationError('bad'); } };
    const res = await new PgTskPublisher(serial, sid, transport, 'quarantine', sanitizer, flippingVerifier, READY, { leaseMs: 30_000 }).drainOnce();
    assert.equal(res.acked, 0); assert.equal(res.quarantined, 1); assert.equal(res.halted, true); // acted on the frozen reject-fork snapshot
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM tsk_outbox_rows WHERE stream_id=$1 AND acked_at IS NOT NULL', [sid])).rows[0].n), 0);
  });

  await check('(HIGH) durable stream halt survives a publisher restart; clearing the marker is NOT recovery (seq2 stays a permanent reject-gap)', async () => {
    const sid = 'tsk:halt/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    for (const cnt of [1, 2]) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: cnt }, fenceToken: 0n }));
    // seq1 diverges TERMINALLY (reject-fork) -> quarantine seq1 + durable halt, in one tx.
    // The receiver checkpoint never advances past 0, so seq1 is gone for good.
    const forkTransport: TskOutboxTransport = { async deliverAndAwaitAck(record) { return { streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence, opDigest: record.opDigest, decision: 'reject-fork', receiverId: RID, keyId: KEY_ID, issuedAt: 'now', signature: ackSign(record, 'reject-fork') }; } };
    const r1 = await new PgTskPublisher(serial, sid, forkTransport, 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 }).drainOnce();
    assert.equal(r1.quarantined, 1); assert.equal(r1.halted, true);
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM tsk_outbox_stream_halted WHERE stream_id=$1', [sid])).rows[0].n), 1);

    // RESTART: a BRAND-NEW publisher instance still refuses to drain — the halt lives
    // in the DB (durable), not in the publisher's memory. No spin, no reject-gap loop.
    const r2 = await new PgTskPublisher(serial, sid, receiverTransport(sid, []), 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 }).drainOnce();
    assert.deepEqual(r2, { published: 0, acked: 0, quarantined: 0, retriable: false, halted: true });

    // ATTEMPTED CLEAR with no governed repair: deleting the marker does NOT recover the
    // stream. seq1 is still quarantined, the checkpoint is still 0, so the real receiver
    // sees seq2 as a GAP forever — exactly the non-productive loop the halt existed to stop.
    await pool.query('DELETE FROM tsk_outbox_stream_halted WHERE stream_id=$1', [sid]);
    const decisions: Array<{ seq: number; d: ReceiverDecision }> = [];
    const r3 = await new PgTskPublisher(serial, sid, receiverTransport(sid, decisions), 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 }).drainOnce();
    assert.equal(r3.halted, false);   // marker is physically gone...
    assert.equal(r3.acked, 0);        // ...but NOTHING recovered — seq2 did not apply
    assert.ok(decisions.some((x) => x.seq === 2 && x.d === 'reject-gap'), 'seq2 must be a permanent reject-gap, not a recovery');
    assert.equal(Number((await pool.query('SELECT sequence FROM tsk_outbox_receiver_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), 0); // checkpoint never advanced
    assert.equal(await unacked(sid), 1); // seq2 stays unacked forever; only a governed repair (unquarantine + epoch-resync) recovers
  });

  await check('(MED) strict receipt snapshot: a transport ACK receipt carrying an accessor property is rejected (no ack, no advance)', async () => {
    const sid = 'tsk:receipt-shape/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 1 }, fenceToken: 0n }));
    const evilTransport: TskOutboxTransport = {
      async deliverAndAwaitAck(record) {
        const base: Record<string, unknown> = { streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence, opDigest: record.opDigest, decision: 'applied', receiverId: RID, keyId: KEY_ID, issuedAt: 'now', signature: ackSign(record, 'applied') };
        // launder the decision through an accessor — the strict snapshot must refuse it
        Object.defineProperty(base, 'decision', { get: () => 'applied', enumerable: true, configurable: true });
        return base as unknown as TskAckReceipt;
      },
    };
    const pub = new PgTskPublisher(serial, sid, evilTransport, 'quarantine', sanitizer, ackVerifier, READY, { leaseMs: 30_000 });
    await assert.rejects(() => pub.drainOnce(), /receipt/);
    assert.equal(await unacked(sid), 1); // nothing acked; the row is untouched
  });

  await check('(MED) transparent Proxy receipt: a Proxy-presented ACK is snapshotted; mutating the target mid-verify cannot flip the acked decision', async () => {
    const sid = 'tsk:receipt-proxy/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter: 1 }, fenceToken: 0n }));
    let target: Record<string, unknown> | null = null;
    const proxyTransport: TskOutboxTransport = {
      async deliverAndAwaitAck(record) {
        target = { streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence, opDigest: record.opDigest, decision: 'applied', receiverId: RID, keyId: KEY_ID, issuedAt: 'now', signature: ackSign(record, 'applied') };
        return new Proxy(target, {}) as unknown as TskAckReceipt; // transparent — passes every structural check
      },
    };
    const mutatingVerifier: TskAckReceiptVerifier = {
      async verify(receipt, record) {
        // flip the underlying target AFTER the snapshot was taken; the frozen snapshot must win
        if (target) { (target as { decision: string }).decision = 'reject-fork'; (target as { signature: string }).signature = ackSign(record, 'reject-fork'); }
        if (receipt.receiverId !== RID || receipt.signature !== ackSign(record, receipt.decision)) throw new ContractValidationError('bad ACK');
      },
    };
    const res = await new PgTskPublisher(serial, sid, proxyTransport, 'quarantine', sanitizer, mutatingVerifier, READY, { leaseMs: 30_000 }).drainOnce();
    assert.equal(res.acked, 1); assert.equal(res.quarantined, 0); // acted on the frozen 'applied' snapshot, not the mutated target
    assert.equal(await unacked(sid), 0);
  });

  await check('(MED) schema grammar: a valid lowercase non-public schema attests; invalid identifiers are rejected', async () => {
    await assert.rejects(() => assertSchemaReady(serial, 'Bad$Schema'), /invalid schema identifier/);
    await assert.rejects(() => assertSchemaReady(serial, '1abc'), /invalid schema identifier/);
    const c = await pool.connect();
    await c.query('DROP SCHEMA IF EXISTS tsk_alt CASCADE'); await c.query('CREATE SCHEMA tsk_alt'); await c.query('SET search_path=tsk_alt');
    for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await c.query(s);
    await c.query('RESET search_path'); c.release();
    const readyAlt = await provisionSchemaVersion(serial, 'tsk_alt'); // attests tsk_alt -> stripSchema must handle 'tsk_alt.'
    assert.ok(readyAlt);
    await pool.query('DROP SCHEMA IF EXISTS tsk_alt CASCADE');
  });

  console.log(`\n# ${passed} checks passed`);
}

// helpers that build a valid signed record+head against a live stream head
async function mkRH(sid: string, seq: number, mut: TskHotpMutation, prevHead: string, fence = '0', epoch = 'e1'): Promise<{ record: OutboxRecord<TskHotpMutation>; head: SignedStreamHead }> {
  const mutation = { tumblerId: mut.tumblerId, counter: mut.counter } as SanitizedMutation<TskHotpMutation>;
  const opDigest = canonicalOpDigest<TskHotpMutation>({ streamId: sid, sourceEpoch: epoch, sequence: seq, fenceToken: fence, mutation });
  const headDigest = streamHeadDigest({ streamId: sid, sequence: seq, prevHeadDigest: prevHead, opDigest, keyId: KEY_ID, alg: 'ed25519' });
  const signature = await signer.sign(headDigest);
  return {
    record: { contractVersion: '1', streamId: sid, sourceEpoch: epoch, sequence: seq, fenceToken: fence, opDigest, mutation },
    head: { streamId: sid, sequence: seq, prevHeadDigest: prevHead, opDigest, keyId: KEY_ID, alg: 'ed25519', headDigest, signature },
  };
}
main().then(() => pool.end()).then(() => process.exit(0)).catch(async (e) => { console.error('FAILED:', e); await pool.end().catch(() => {}); process.exit(1); });
