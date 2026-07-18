/**
 * REAL two-node A->B drill for TSK #10 (PR1 core: happy / lost-ACK partition / PG-B
 * down). TWO GENUINELY INDEPENDENT PostgreSQL 16 nodes (separate URLs, no shared
 * state): node A = durable-outbox authority, node B = receiver authority. The ONLY
 * A->B path is the authenticated, decision-bound HTTP outbox transport. Faults are
 * injected deterministically; RPO/RTO are measured and printed.
 *
 * BOUNDARY: NO HA/production claim. #10 stays OPEN — this PR1 proves the transport +
 * exactly-once-under-partition + receiver-unavailable retry only. Split-brain/fence,
 * crash+snapshot/tail resync, promotion convergence, and Redis-authority failover are
 * PR2 (the full acceptance drill that closes #10).
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import { createServer, type Server } from 'node:http';
import { generateKeyPairSync, sign as edSign, verify as edVerify, createHmac, timingSafeEqual } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import pg from 'pg';
import {
  ContractValidationError, TSK_OUTBOX_PG_SCHEMA, provisionSchemaVersion,
  NodePostgresTransactor, PgTskDurableOutbox, PgTskPublisher, PgTskReceiverCheckpoint,
  HttpOutboxTransport, createHttpOutboxReceiver, PgReplayNonceStore, TSK_TRANSPORT_NONCE_SCHEMA,
  type PgTransactor, type PgExecutor, type HotpApplier, type HotpMutationSanitizer,
  type OutboxRecord, type SanitizedMutation, type SignedStreamHead,
  type StreamHeadSigner, type StreamHeadVerifier, type TskAckReceipt, type TskAckReceiptVerifier, type TskHotpMutation,
} from './packages/server/dist/index.js';

const URL_A = process.env['TSK_TEST_POSTGRES_URL_A'];
const URL_B = process.env['TSK_TEST_POSTGRES_URL_B'];
if (!URL_A || !URL_B) throw new Error('TSK_TEST_POSTGRES_URL_A and _B (two independent PG16) are required');
if (URL_A === URL_B) throw new Error('node A and node B must be INDEPENDENT PostgreSQL instances (distinct URLs)');
const { Pool } = pg;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const SID = 'tsk:pair:2node/v1';
const EPOCH = 'e1';

// ── shared crypto ──
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const KEY_ID = 'tsk-key-1';
const signer: StreamHeadSigner = { keyId: KEY_ID, alg: 'ed25519', async sign(hd) { return edSign(null, Buffer.from(hd, 'utf8'), privateKey).toString('base64url'); } };
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
// request-signing key (A -> B) and ack key (B -> A)
const REQ_KEY = 'req-key-1';
const reqSecret = Buffer.alloc(32, 0x5a);
const RESP_KEY = 'resp-key-1';
const respSecret = Buffer.alloc(32, 0x3e);
const RID_B = 'receiver-B';
const ACK_KEY = 'ack-key-1';
const ackSecret = Buffer.alloc(32, 0x7c);
const ackBody = (a: Omit<TskAckReceipt, 'signature'>) => `${a.receiverId}|${a.keyId}|${a.streamId}|${a.sourceEpoch}|${a.sequence}|${a.opDigest}|${a.decision}|${a.issuedAt}`;
const ackSign = (a: Omit<TskAckReceipt, 'signature'>) => createHmac('sha256', ackSecret).update(ackBody(a)).digest('base64url');
const ackVerifier: TskAckReceiptVerifier = {
  async verify(receipt, record) {
    if (receipt.receiverId !== RID_B || receipt.keyId !== ACK_KEY) throw new ContractValidationError('bad ack identity');
    if (receipt.streamId !== record.streamId || receipt.sourceEpoch !== record.sourceEpoch || receipt.sequence !== record.sequence || receipt.opDigest !== record.opDigest) throw new ContractValidationError('ack does not bind record');
    const want = Buffer.from(ackSign(receipt), 'base64url');
    const got = Buffer.from(receipt.signature, 'base64url');
    if (got.length !== want.length || !timingSafeEqual(got, want)) throw new ContractValidationError('bad ack signature');
  },
};

// ── PG node helpers ──
async function applyOn(pool: pg.Pool, ddl: string) { for (const s of ddl.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s); }
async function resetNode(pool: pg.Pool, transactor: PgTransactor) {
  await pool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_transport_nonce CASCADE');
  await pool.query('DROP TABLE IF EXISTS tsk_2node_effects');
  await applyOn(pool, TSK_OUTBOX_PG_SCHEMA);
  await applyOn(pool, TSK_TRANSPORT_NONCE_SCHEMA);
  await pool.query('CREATE TABLE tsk_2node_effects (stream_id text, sequence int, applied_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (stream_id, sequence))');
  return provisionSchemaVersion(transactor, 'public');
}
const systemId = async (pool: pg.Pool) => String((await pool.query('SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0].id);
const effectsB = async (pool: pg.Pool) => Number((await pool.query('SELECT count(*)::int AS n FROM tsk_2node_effects WHERE stream_id=$1', [SID])).rows[0].n);
const unackedA = async (pool: pg.Pool) => Number((await pool.query('SELECT count(*)::int AS n FROM tsk_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL AND quarantined_at IS NULL', [SID])).rows[0].n);
const rcvSeqB = async (pool: pg.Pool) => Number((await pool.query('SELECT sequence FROM tsk_outbox_receiver_checkpoint WHERE stream_id=$1', [SID])).rows[0].sequence);
const appliedCountB = async (pool: pg.Pool) => Number((await pool.query('SELECT count(*)::int AS n FROM tsk_outbox_applied WHERE stream_id=$1', [SID])).rows[0].n);

// ── fault proxy (A -> B): pass, or drop the HTTP RESPONSE after B has applied ──
type ProxyMode = 'pass' | 'dropResponse';
function startProxy(upstreamPort: number): Promise<{ port: number; setMode: (m: ProxyMode) => void; drops: () => number; close: () => Promise<void> }> {
  let mode: ProxyMode = 'pass';
  let drops = 0;
  const server = net.createServer((client) => {
    client.on('error', () => {});
    const up = net.connect(upstreamPort, '127.0.0.1');
    up.on('error', () => {});
    let dropped = false;
    client.on('data', (d) => { if (!up.destroyed) up.write(d); });
    up.on('data', (d) => {
      if (mode === 'dropResponse' && !dropped) { dropped = true; drops++; try { client.destroy(); } catch { /* gone */ } return; } // B already applied+committed before responding
      if (!client.destroyed) client.write(d);
    });
    const cl = () => { try { up.destroy(); } catch { /* gone */ } try { client.destroy(); } catch { /* gone */ } };
    client.on('close', cl); up.on('close', cl);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    port: (server.address() as AddressInfo).port,
    setMode: (m) => { mode = m; },
    drops: () => drops,
    close: () => new Promise((r) => server.close(() => r())),
  })));
}

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK two-node A->B drill (real 2x PG16, authenticated decision-bound transport)');
  const poolA = new Pool({ connectionString: URL_A, max: 6 }); poolA.on('error', () => {});
  const poolB0 = new Pool({ connectionString: URL_B, max: 6 }); poolB0.on('error', () => {});
  const probeB = new Pool({ connectionString: URL_B, max: 2 }); probeB.on('error', () => {}); // independent observer of node B
  const txA = new NodePostgresTransactor(poolA as never);
  const READY_A = await resetNode(poolA, txA);
  // node B working handle lives in a holder so its pool can be REALLY closed + reopened (PG-B down)
  const b: { pool: pg.Pool; tx: PgTransactor; ready: Awaited<ReturnType<typeof provisionSchemaVersion>> } = { pool: poolB0, tx: new NodePostgresTransactor(poolB0 as never), ready: null as never };
  b.ready = await resetNode(b.pool, b.tx);
  // provision the stream on each independent node
  await poolA.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [SID]);
  await poolA.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [SID, EPOCH]);
  await probeB.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [SID]);
  await probeB.query('INSERT INTO tsk_outbox_receiver_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [SID, EPOCH]);

  // node B: receiver + authenticated ingest HTTP server (reads the CURRENT holder,
  // so a real pool close/reopen during the drill is transparent to the server).
  // durable side-effect counter: applied EXACTLY-ONCE inside the receiver tx (a redelivery
  // short-circuits to duplicate-ok and does NOT re-run the applier), so effect count == N.
  const applier: HotpApplier = { async applyInTx(exec: PgExecutor, r) { await exec.query('INSERT INTO tsk_2node_effects (stream_id, sequence) VALUES ($1, $2)', [r.streamId, r.sequence]); } };
  const receive = async (record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead): Promise<TskAckReceipt> => {
    const receiver = new PgTskReceiverCheckpoint(b.tx, SID, sanitizer, headVerifier, applier, b.ready);
    const decision = await receiver.verifyAndApplyTumblerDelivered(record, head);
    const base: Omit<TskAckReceipt, 'signature'> = { streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence, opDigest: record.opDigest, decision, receiverId: RID_B, keyId: ACK_KEY, issuedAt: String(Date.now()) };
    return { ...base, signature: ackSign(base) };
  };
  const nonceStore = new PgReplayNonceStore((sql, params) => b.pool.query(sql, params as never) as never, { retentionMs: 120_000 });
  const ingest = createHttpOutboxReceiver({ expectedPath: '/ingest', resolveRequestKey: (kid) => (kid === REQ_KEY ? reqSecret : null), responseKeyId: RESP_KEY, responseSecret: respSecret, receive, nonceStore });
  const bServer: Server = createServer((req, res) => ingest(req, res));
  await new Promise<void>((r) => bServer.listen(0, '127.0.0.1', r));
  const bPort = (bServer.address() as AddressInfo).port;
  const proxy = await startProxy(bPort);
  const transportUrl = `http://127.0.0.1:${proxy.port}/ingest`;
  const transport = new HttpOutboxTransport({ url: transportUrl, fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: reqSecret, resolveResponseKey: (kid) => (kid === RESP_KEY ? respSecret : null), ackVerifier, timeoutMs: 3_000 });

  const outbox = new PgTskDurableOutbox(txA, READY_A, { streamId: SID, sanitizer, signer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' });
  const mkPublisher = () => new PgTskPublisher(txA, SID, transport, 'quarantine', sanitizer, ackVerifier, READY_A, { leaseMs: 30_000 });
  const appendN = async (from: number, n: number) => { for (let i = 0; i < n; i++) await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { tumblerId: `T${(from + i) % 3}`, counter: 1000 + from + i }, fenceToken: 0n })); };
  const drain = async (maxRounds = 60) => { const pub = mkPublisher(); for (let r = 0; r < maxRounds; r++) { await pub.drainOnce(); if ((await unackedA(poolA)) === 0) return; await sleep(20); } };

  try {
    await check('(0) attest A and B are GENUINELY INDEPENDENT PostgreSQL clusters (distinct system_identifier)', async () => {
      const idA = await systemId(poolA);
      const idB = await systemId(probeB);
      assert.notEqual(idA, idB, `node A and B must be distinct clusters (system_identifier A=${idA} B=${idB})`);
      console.log(`     system_identifier A=${idA} B=${idB} (distinct)`);
    });

    await check('(1) happy A->B: append N -> B applies strictly 1..N over the authenticated transport, HOTP + side-effect once', async () => {
      const N = 8;
      const t0 = Date.now();
      await appendN(1, N);
      await drain();
      const lagMs = Date.now() - t0;
      assert.equal(await unackedA(poolA), 0, 'all rows acked on A');
      assert.equal(await rcvSeqB(probeB), N, 'B receiver checkpoint advanced to N');
      assert.equal(await appliedCountB(probeB), N, 'B applied exactly N rows');
      assert.equal(await effectsB(probeB), N, 'durable side-effect applied EXACTLY N times');
      const consumed = (await probeB.query('SELECT tumbler_id, last_counter FROM tsk_hotp_consumed WHERE stream_id=$1', [SID])).rows;
      assert.equal(consumed.length, 3, 'HOTP consumed per tumbler');
      console.log(`     converge-lag=${lagMs}ms rows=${N}`);
    });

    await check('(2) network partition drops the ACK after B applied -> retriable, no double-apply; heal converges (RPO/RTO)', async () => {
      const base = await rcvSeqB(probeB);
      await appendN(base + 1, 4);
      // arm: the next delivery's RESPONSE is dropped AFTER B applies+commits it
      proxy.setMode('dropResponse');
      const faultAt = Date.now();
      const pub = mkPublisher();
      await pub.drainOnce().catch(() => {}); // delivery reaches B; ack lost -> retriable
      // B applied seq base+1, but A did NOT record the ack -> the row is still unacked on A
      const backlog = await unackedA(poolA); // durable on A, not yet ACKED — the UNCONVERGED TAIL (not lost data)
      assert.ok(proxy.drops() >= 1, 'the ack response was actually dropped on the wire');
      assert.equal(await rcvSeqB(probeB), base + 1, 'B applied the first record despite the lost ack');
      assert.ok(backlog >= 1, `unconverged tail present (backlog=${backlog} durable rows awaiting ack)`);
      // heal and reconcile by idempotency (redelivery -> duplicate-ok, exactly-once)
      proxy.setMode('pass');
      await drain();
      const rtoMs = Date.now() - faultAt;
      assert.equal(await unackedA(poolA), 0, 'converged: all rows acked on A after heal');
      assert.equal(await appliedCountB(probeB), base + 4, 'B applied each record EXACTLY once (no double-apply after redelivery)');
      assert.equal(await effectsB(probeB), base + 4, 'durable side-effect count == N (exactly-once across the partition)');
      assert.equal(await rcvSeqB(probeB), base + 4, 'B checkpoint at N');
      // RPO is DATA LOSS, not lag: after convergence, everything appended is applied -> 0 lost.
      const dataLossRpo = (base + 4) - (await appliedCountB(probeB));
      assert.equal(dataLossRpo, 0, 'data-loss RPO = 0 (durable outbox; nothing lost)');
      console.log(`     unconverged-tail(backlog)=${backlog} rows | data-loss RPO=0 | RTO=${rtoMs}ms to converge`);
    });

    await check('(6) node-B receiver loses its PostgreSQL connection (working pool closed) -> retriable, no loss; reconnect converges (RTO)', async () => {
      const base = await rcvSeqB(probeB);
      await appendN(base + 1, 3);
      await b.pool.end(); // REAL: node B's working pool goes down -> ingest tx fails -> 500 -> retriable
      const faultAt = Date.now();
      const pub = mkPublisher();
      await pub.drainOnce().catch(() => {});
      assert.ok((await unackedA(poolA)) >= 1, 'rows stay durable + unacked on A while B is down (no loss)');
      assert.equal(await rcvSeqB(probeB), base, 'B applied nothing while down');
      // node B recovers with a fresh pool/transactor against the SAME durable DB
      b.pool = new Pool({ connectionString: URL_B, max: 6 }); b.pool.on('error', () => {});
      b.tx = new NodePostgresTransactor(b.pool as never);
      b.ready = await provisionSchemaVersion(b.tx, 'public');
      await drain();
      const rtoMs = Date.now() - faultAt;
      assert.equal(await unackedA(poolA), 0, 'converged after B recovery');
      assert.equal(await rcvSeqB(probeB), base + 3, 'B caught up to A committed head');
      assert.equal(await appliedCountB(probeB), base + 3, 'exactly-once across the outage');
      console.log(`     RTO=${rtoMs}ms from B-down to converged`);
    });

    console.log(`\n# ${passed} two-node checks passed (proxy ack-drops: ${proxy.drops()})`);
  } finally {
    await proxy.close();
    await new Promise<void>((r) => bServer.close(() => r()));
    await poolA.end().catch(() => {});
    await b.pool.end().catch(() => {});
    await probeB.end().catch(() => {});
  }
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
