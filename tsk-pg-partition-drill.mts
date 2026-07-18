/**
 * DETERMINISTIC real-network partition drill for the production NodePostgresTransactor
 * (#10). A TCP fault proxy sits between a real pg.Pool and ONE PostgreSQL. Faults are
 * injected by matching PostgreSQL WIRE-PROTOCOL state, never by timing:
 *
 *   A) cut DURING WORK  — sever the socket when a sentinel query is seen, after the
 *      INSERT but before COMMIT. Proves work-phase partitions roll back (no partial
 *      commit), the connection is destroyed, and the pool does not leak it.
 *   B) cut IN THE COMMIT WINDOW — forward the client's `COMMIT` to the server, WAIT
 *      until the server's `CommandComplete('COMMIT')` is observed on the wire (the
 *      commit is now durable server-side), then drop that response and destroy the
 *      client socket. The transactor MUST raise AmbiguousCommitError; the caller then
 *      reconciles against authoritative state by idempotency key (here the row PK,
 *      which models the outbox (streamId,sourceEpoch,sequence,opDigest) tuple) and
 *      finds the commit landed — exactly-once, no double-apply, no blind retry.
 *   C) cut DURING ACQUIRE — stall new connections so pool.connect() cannot complete;
 *      the transactor's bounded acquire deadline fires and a late connection is
 *      destroyed.
 *
 * BOUNDARY: this HARDENS the single-node transactor's partition semantics. It does
 * NOT close #10 and makes NO HA/uptime claim — the two-node PostgreSQL failover /
 * split-brain drill with measured RPO/RTO remains the HA gate. Redis is excluded.
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import pg from 'pg';
import { NodePostgresTransactor, AmbiguousCommitError } from './packages/server/dist/index.js';

const PG_URL = process.env['TSK_TEST_POSTGRES_URL'] ?? process.env['BPC_TEST_POSTGRES_URL'] ?? process.env['HA_OUTBOX_PG_URL'];
if (!PG_URL) throw new Error('TSK_TEST_POSTGRES_URL is required for the partition drill');
const u = new URL(PG_URL);
const PG_HOST = u.hostname;
const PG_PORT = Number(u.port || 5432);
const PROXY_PORT = 55491;
const STALL_DIAL_MS = 1_500; // in stallC, the upstream is dialed only AFTER this delay, so a
                             // connection ARRIVES LATE (after a shorter acquire deadline) and
                             // must be destroyed rather than leaked into the pool.
const conn = { host: '127.0.0.1', port: PROXY_PORT, user: decodeURIComponent(u.username), password: decodeURIComponent(u.password), database: u.pathname.slice(1) };
const { Pool } = pg;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// exact PostgreSQL frames (5-byte header + payload): simple Query 'Q' "COMMIT\0" from
// the client, and CommandComplete 'C' "COMMIT\0" from the server after it commits.
const CLIENT_COMMIT = Buffer.from([0x51, 0, 0, 0, 0x0b, 0x43, 0x4f, 0x4d, 0x4d, 0x49, 0x54, 0x00]);
const SERVER_COMMIT_DONE = Buffer.from([0x43, 0, 0, 0, 0x0b, 0x43, 0x4f, 0x4d, 0x4d, 0x49, 0x54, 0x00]);
const SENTINEL_A = Buffer.from('TSKPARTITIONCUTA');

type Mode = 'pass' | 'cutA' | 'cutB' | 'stallC';
interface Proxy { setMode: (m: Mode) => void; flushStalled: () => void; state: { cuts: number }; close: () => Promise<void> }

function startProxy(): Promise<Proxy> {
  let mode: Mode = 'pass';
  const state = { cuts: 0 };
  const stalled: net.Socket[] = [];
  const stallTimers: ReturnType<typeof setTimeout>[] = [];
  const server = net.createServer((client) => {
    client.on('error', () => {});
    if (mode === 'stallC') {
      // accept, then dial upstream only AFTER STALL_DIAL_MS: the client's startup
      // stalls past a shorter acquire deadline, then the connection completes LATE.
      stalled.push(client);
      stallTimers.push(setTimeout(() => {
        if (client.destroyed) return;
        const up = net.connect(PG_PORT, PG_HOST);
        up.on('error', () => {});
        client.on('data', (d) => { if (!up.destroyed) up.write(d); });
        up.on('data', (d) => { if (!client.destroyed) client.write(d); });
        const cl = () => { try { up.destroy(); } catch { /* gone */ } try { client.destroy(); } catch { /* gone */ } };
        client.on('close', cl); up.on('close', cl);
      }, STALL_DIAL_MS));
      return;
    }
    const upstream = net.connect(PG_PORT, PG_HOST);
    upstream.on('error', () => {});
    let commitForwarded = false;
    let clientDead = false;
    let cSlack = Buffer.alloc(0);
    let sSlack = Buffer.alloc(0);
    const killClient = () => { if (!clientDead) { clientDead = true; state.cuts++; try { client.destroy(); } catch { /* gone */ } } };
    client.on('data', (chunk) => {
      if (mode === 'cutA') {
        const scan = Buffer.concat([cSlack, chunk]);
        if (scan.includes(SENTINEL_A)) { try { upstream.destroy(); } catch { /* gone */ } killClient(); return; }
        cSlack = scan.subarray(Math.max(0, scan.length - SENTINEL_A.length));
      } else if (mode === 'cutB') {
        const scan = Buffer.concat([cSlack, chunk]);
        if (scan.includes(CLIENT_COMMIT)) commitForwarded = true;
        cSlack = scan.subarray(Math.max(0, scan.length - CLIENT_COMMIT.length));
      }
      if (!upstream.destroyed) upstream.write(chunk);
    });
    upstream.on('data', (chunk) => {
      if (mode === 'cutB' && commitForwarded && !clientDead) {
        const scan = Buffer.concat([sSlack, chunk]);
        if (scan.includes(SERVER_COMMIT_DONE)) { killClient(); return; } // server committed; drop its reply
        sSlack = scan.subarray(Math.max(0, scan.length - SERVER_COMMIT_DONE.length));
      }
      if (!clientDead && !client.destroyed) client.write(chunk);
    });
    const cleanup = () => { try { upstream.destroy(); } catch { /* gone */ } try { client.destroy(); } catch { /* gone */ } };
    client.on('close', cleanup);
    upstream.on('close', cleanup);
  });
  return new Promise((resolve) => server.listen(PROXY_PORT, '127.0.0.1', () => resolve({
    setMode: (x) => { mode = x; },
    flushStalled: () => { while (stallTimers.length) clearTimeout(stallTimers.pop()!); while (stalled.length) { try { stalled.pop()!.destroy(); } catch { /* gone */ } } },
    state,
    close: () => new Promise((r) => server.close(() => r())),
  })));
}

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK production Pg transactor — deterministic real-network partition drill');
  const proxy = await startProxy();
  const direct = new Pool({ connectionString: PG_URL, max: 4 }); direct.on('error', () => {});
  await direct.query('DROP TABLE IF EXISTS partition_probe');
  await direct.query('CREATE TABLE partition_probe (id int primary key, tag text)');
  // synchronous_commit=on is pinned ON THE PROXIED SESSION itself (startup option),
  // so the commit whose ack we drop in Case B is genuinely WAL-flushed (crash-durable),
  // not merely applied/visible. Verified by readback through the transactor below.
  const proxied = new Pool({ ...conn, max: 4, options: '-c synchronous_commit=on' }); proxied.on('error', () => {});
  const tx = new NodePostgresTransactor(proxied as unknown as ConstructorParameters<typeof NodePostgresTransactor>[0], { statementTimeoutMs: 5_000, transactionTimeoutMs: 8_000, acquireTimeoutMs: 3_000 });
  const inUse = () => proxied.totalCount - proxied.idleCount;

  try {
    await check('(A) work-phase partition rolls back with no partial commit; connection destroyed, pool not leaked', async () => {
      proxy.setMode('cutA');
      const t0 = Date.now();
      const err = await tx.transaction(async (exec) => {
        await exec.query('INSERT INTO partition_probe(id, tag) VALUES (2, $1)', ['A']);
        await exec.query("SELECT 'TSKPARTITIONCUTA' AS s"); // deterministic wire trigger, mid-tx
      }).then(() => null).catch((e) => e);
      const ms = Date.now() - t0;
      proxy.setMode('pass');
      assert.ok(err, 'A: the partitioned work tx must reject');
      assert.ok(ms < 8_500, `A: must be bounded (was ${ms}ms)`);
      const n = Number((await direct.query('SELECT count(*)::int AS n FROM partition_probe WHERE id = 2')).rows[0].n);
      assert.equal(n, 0, 'A: an uncommitted work-phase partition must leave NO row');
      await sleep(150);
      assert.equal(inUse(), 0, 'A: no checked-out connection leaked');
    });

    await check('(B) COMMIT-window partition -> AmbiguousCommitError; authoritative reconciliation proves exactly-once', async () => {
      // durability precondition, verified ON the proxied session used for the cut
      // (a per-session setting checked on `direct` would not prove THIS connection):
      const sc = await tx.transaction(async (exec) => String((await exec.query("SELECT current_setting('synchronous_commit') AS sc")).rows[0].sc));
      assert.equal(sc, 'on', `B: crash-durability requires synchronous_commit=on on the proxied session (was '${sc}')`);
      proxy.setMode('cutB');
      const t0 = Date.now();
      const err = await tx.transaction(async (exec) => {
        await exec.query('INSERT INTO partition_probe(id, tag) VALUES (1, $1)', ['B']);
      }).then(() => null).catch((e) => e);
      const ms = Date.now() - t0;
      proxy.setMode('pass');
      // 1) error classification: a lost COMMIT response is AMBIGUOUS, not success/failure
      assert.ok(err instanceof AmbiguousCommitError, `B: expected AmbiguousCommitError, got ${err?.constructor?.name}: ${err?.message}`);
      assert.equal(err.committed, 'unknown');
      assert.ok(ms < 8_500, `B: must be bounded (was ${ms}ms)`);
      // 2) authoritative reconciliation by idempotency key (PK models the outbox tuple):
      //    the server DID commit (we dropped the reply only AFTER its CommandComplete,
      //    on a synchronous_commit=on session — so it is WAL-flushed / crash-durable).
      const rows = (await direct.query('SELECT tag FROM partition_probe WHERE id = 1')).rows;
      assert.equal(rows.length, 1, 'B: the commit MUST be durable server-side despite the dropped ack');
      assert.equal(rows[0].tag, 'B');
      // 3) no double-apply: reconciliation by key makes even a blind retry idempotent
      const retry = await direct.query('INSERT INTO partition_probe(id, tag) VALUES (1, $1) ON CONFLICT (id) DO NOTHING', ['B-retry']);
      assert.equal(retry.rowCount, 0, 'B: the idempotency key already exists — no second apply');
      assert.equal(Number((await direct.query('SELECT count(*)::int AS n FROM partition_probe WHERE id = 1')).rows[0].n), 1);
      await sleep(150);
      assert.equal(inUse(), 0, 'B: no checked-out connection leaked after an ambiguous commit');
    });

    await check('(C) acquire-phase partition is bounded by the acquire deadline; the late-arriving connection is destroyed, not leaked', async () => {
      proxy.setMode('stallC');
      const poolC = new Pool({ ...conn, max: 1 }); poolC.on('error', () => {});
      const txC = new NodePostgresTransactor(poolC as unknown as ConstructorParameters<typeof NodePostgresTransactor>[0], { acquireTimeoutMs: 800, transactionTimeoutMs: 6_000 });
      const t0 = Date.now();
      const err = await txC.transaction(async (exec) => exec.query('SELECT 1')).then(() => null).catch((e) => e);
      const ms = Date.now() - t0;
      assert.ok(err && /acquisition timed out/.test(String(err.message)), `C: expected acquire timeout, got ${err?.message}`);
      // fired AT the ~800ms acquire deadline, strictly BEFORE the ~1500ms late arrival
      assert.ok(ms >= 700 && ms < 1_400, `C: must fire at the acquire deadline, before the late arrival (was ${ms}ms)`);
      // the connection then ARRIVES late (~1500ms). It MUST be destroyed, never pooled:
      await sleep(STALL_DIAL_MS - ms + 400);
      assert.equal(poolC.totalCount, 0, 'C: the late-arriving connection was destroyed, not returned to the pool');
      assert.equal(poolC.totalCount - poolC.idleCount, 0, 'C: no checked-out connection leaked');
      proxy.setMode('pass');
      proxy.flushStalled();
      await Promise.race([poolC.end().catch(() => {}), sleep(800)]);
    });

    console.log(`\n# ${passed} partition checks passed (proxy cuts: ${proxy.state.cuts})`);
  } finally {
    await proxied.end().catch(() => {});
    await direct.end().catch(() => {});
    await proxy.close();
  }
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
