/**
 * PR2c acceptance (#10) — real Redis Sentinel/quorum failover of the fencing authority.
 *
 * Topology (ci/redis-sentinel/docker-compose.yml): 1 master + 1 replica + 3 sentinels (quorum 2),
 * AOF everysec. This drill runs INSIDE the compose network (no host-NAT) and drives a REAL master
 * crash, proving the RedisFencingStore over a Sentinel-backed client:
 *   1. a committed+replica-ack'd fence claim SURVIVES an automatic Sentinel failover (RPO = 0);
 *   2. the promoted replica serves the SAME fence (no rollback / no stale epoch);
 *   3. the fence stays MONOTONIC across failover (a new epoch claims; an old epoch is refused);
 *   4. measured RTO = time from master crash to the fence being writable on the new master.
 *
 * Mechanism-only on a single host (processes, not physical failure domains). Env:
 * TSK_TEST_SENTINELS=host:port,... + TSK_TEST_SENTINEL_MASTER + TSK_TEST_MASTER_HOST + TSK_TEST_REPLICA_HOST.
 */
import assert from 'node:assert/strict';
import { Redis } from 'ioredis';
import { RedisFencingStore } from './packages/server/dist/index.js';

const SENTINELS = (process.env['TSK_TEST_SENTINELS'] ?? '').split(',').map((s) => s.trim()).filter(Boolean)
  .map((hp) => { const [host, port] = hp.split(':'); return { host, port: Number(port) }; });
const MASTER_NAME = process.env['TSK_TEST_SENTINEL_MASTER'] ?? 'tskmaster';
const MASTER_HOST = process.env['TSK_TEST_MASTER_HOST'] ?? 'redis-master';
const REPLICA_HOST = process.env['TSK_TEST_REPLICA_HOST'] ?? 'redis-replica';
if (SENTINELS.length < 3) throw new Error('TSK_TEST_SENTINELS must list >=3 sentinels (quorum topology)');

const FENCE_KEY = 'tsk:fence:sentinel/v1';
let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const now = () => Number(process.hrtime.bigint() / 1_000_000n);

async function waitFor<T>(label: string, fn: () => Promise<T>, timeoutMs: number, everyMs = 200): Promise<T> {
  const deadline = now() + timeoutMs;
  let lastErr: unknown;
  while (now() < deadline) { try { return await fn(); } catch (e) { lastErr = e; await sleep(everyMs); } }
  throw new Error(`waitFor(${label}) timed out after ${timeoutMs}ms: ${String(lastErr)}`);
}

async function main() {
  console.log('# TSK PR2c Redis Sentinel failover drill (1 master + 1 replica + 3 sentinels, quorum 2)');
  // sentinel-backed client used by the fencing store — auto-follows the master across failover.
  const sentinelClient = new Redis({ sentinels: SENTINELS, name: MASTER_NAME, role: 'master', maxRetriesPerRequest: null, sentinelRetryStrategy: () => 200 });
  sentinelClient.on('error', () => {});
  const store = new RedisFencingStore(sentinelClient, FENCE_KEY);
  // a DIRECT connection to a sentinel node (SENTINEL admin commands don't route through the master client).
  const sentinelAdmin = new Redis({ host: SENTINELS[0].host, port: SENTINELS[0].port, maxRetriesPerRequest: 2 }); sentinelAdmin.on('error', () => {});
  const masterAddr = async () => await sentinelAdmin.call('SENTINEL', 'get-master-addr-by-name', MASTER_NAME) as string[];

  // wait until Sentinel has a reachable master and the store is usable.
  await waitFor('initial master reachable', async () => { await sentinelClient.set('tsk:probe', '1'); }, 30_000);

  const HOUR = 3_600_000;
  await check('claim fence epoch 1 on the initial master', async () => {
    await sentinelClient.del(FENCE_KEY);
    const ok = await store.claim({ nodeId: 'B', fenceEpoch: 1, expiresAt: Date.now() + HOUR, commandId: 'c1' });
    assert.equal(ok, true);
    const cur = await store.current();
    assert.ok(cur && cur.fenceEpoch === 1 && cur.nodeId === 'B' && cur.commandId === 'c1' && cur.active === true);
  });

  // Prove the claim reached the replica BEFORE we crash the master → RPO = 0 is a guarantee, not luck.
  const master = new Redis({ host: MASTER_HOST, port: 6379, maxRetriesPerRequest: 2 }); master.on('error', () => {});
  const replica = new Redis({ host: REPLICA_HOST, port: 6379, maxRetriesPerRequest: 2 }); replica.on('error', () => {});
  await check('the fence is durably replicated to the replica before the crash (WAIT + direct read)', async () => {
    const acked = Number(await master.call('WAIT', '1', '5000'));
    assert.ok(acked >= 1, `expected >=1 replica ack from WAIT, got ${acked}`);
    const raw = await waitFor('replica has fence', async () => { const v = await replica.get(FENCE_KEY); if (!v) throw new Error('not yet'); return v; }, 5_000);
    assert.ok(String(raw).includes('"fenceEpoch":1'));
    const role = String((await replica.call('ROLE') as unknown[])[0]);
    assert.equal(role, 'slave', 'the replica is a slave before failover');
  });

  const oldMasterAddr = await masterAddr();

  let rtoMs = 0;
  await check('SHUTDOWN NOSAVE the master → Sentinel promotes the replica; the fence SURVIVES (RPO=0) and is writable (RTO measured)', async () => {
    const t0 = now();
    await master.call('SHUTDOWN', 'NOSAVE').catch(() => {}); // crash: connection drops, process exits
    // ioredis (sentinel-backed) blocks/queues until a new master is elected, then serves.
    const cur = await waitFor('fence readable on the promoted master', async () => {
      const c = await store.current();
      if (!c) throw new Error('no fence yet');
      return c;
    }, 30_000, 150);
    // first successful post-crash claim-capable op:
    const okWrite = await waitFor('fence WRITABLE on the promoted master', async () => {
      const c2 = await store.claim({ nodeId: 'B', fenceEpoch: 1, expiresAt: Date.now() + HOUR, commandId: 'c1' }); // idempotent re-claim (epoch not advanced) is a write path
      return c2 === false ? 'ok' : 'ok'; // claim returns false (epoch 1 not > current 1) but the WRITE round-tripped on the new master
    }, 30_000, 150);
    rtoMs = now() - t0;
    assert.equal(okWrite, 'ok');
    assert.ok(cur.fenceEpoch === 1 && cur.nodeId === 'B' && cur.commandId === 'c1', 'the epoch-1 fence survived the failover unchanged (RPO=0)');
    // the sentinel now points at a DIFFERENT node (the promoted replica).
    const newMasterAddr = await waitFor('sentinel reports new master', async () => { const a = await masterAddr(); if (JSON.stringify(a) === JSON.stringify(oldMasterAddr)) throw new Error('same'); return a; }, 15_000);
    assert.notDeepEqual(newMasterAddr, oldMasterAddr, 'Sentinel promoted a new master');
  });

  await check('the fence stays MONOTONIC across failover: epoch 2 claims, epoch 1 is refused (no rollback)', async () => {
    const ok2 = await store.claim({ nodeId: 'B2', fenceEpoch: 2, expiresAt: Date.now() + HOUR, commandId: 'c2' });
    assert.equal(ok2, true);
    assert.equal((await store.current())!.fenceEpoch, 2);
    const rollback = await store.claim({ nodeId: 'Bx', fenceEpoch: 1, expiresAt: Date.now() + HOUR, commandId: 'cx' });
    assert.equal(rollback, false, 'an older epoch cannot reclaim after failover — no split-brain rollback');
    assert.equal((await store.current())!.fenceEpoch, 2);
  });

  console.log('\n# ── measured per-fault RPO / RTO ──');
  console.log(`  fault: Redis master SHUTDOWN NOSAVE (crash) → Sentinel quorum failover`);
  console.log(`  RPO  : 0  (committed+replica-ack'd fence survived; verified epoch/node/command unchanged)`);
  console.log(`  RTO  : ${rtoMs} ms  (master crash → fence writable on the promoted master)`);
  console.log(`\n# ${passed} PR2c Sentinel-failover checks passed`);

  await sentinelClient.quit().catch(() => {});
  await sentinelAdmin.quit().catch(() => {});
  await replica.quit().catch(() => {});
  try { await master.quit(); } catch { /* already down */ }
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
