/**
 * PR2c acceptance (#10) — real Redis Sentinel/quorum failover of the fencing authority.
 *
 * Topology (ci/redis-sentinel/docker-compose.yml): 1 master + 2 replicas + 3 sentinels (quorum 2),
 * AOF everysec, min-replicas-to-write 1. This drill runs ON THE HOST (published ports + ioredis natMap)
 * and drives a REAL master crash, proving the RedisFencingStore over a Sentinel-backed client:
 *   1. claim() ENFORCES a WAIT replica-quorum ACK before success, so a claimed fence SURVIVES an automatic
 *      Sentinel failover (RPO = 0) — durability is a store property, not a caller-side WAIT;
 *   2. the promoted replica serves the SAME fence (no rollback / no stale epoch);
 *   3. the fence stays MONOTONIC across failover (a new epoch claims; an old epoch is refused);
 *   4. measured RTO = time from master crash to the fence readable on the new master.
 *
 * Mechanism-only on a single host (processes, not physical failure domains). Env: TSK_TEST_SENTINELS +
 * TSK_TEST_SENTINEL_MASTER + TSK_SENTINEL_NATMAP + TSK_SENTINEL_MASTER_PORT.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { Redis } from 'ioredis';
import { RedisFencingStore } from './packages/server/dist/index.js';

const SENTINELS = (process.env['TSK_TEST_SENTINELS'] ?? '').split(',').map((s) => s.trim()).filter(Boolean)
  .map((hp) => { const [host, port] = hp.split(':'); return { host, port: Number(port) }; });
const MASTER_NAME = process.env['TSK_TEST_SENTINEL_MASTER'] ?? 'tskmaster';
// natMap: internal "ip:6379" (what Sentinel advertises) → host-reachable published address, so the
// sentinel-backed client follows failover from the host. Also gives us direct per-node host connections.
const NATMAP: Record<string, { host: string; port: number }> = {};
for (const pair of (process.env['TSK_SENTINEL_NATMAP'] ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
  const [internal, external] = pair.split('=');
  const [host, port] = external.split(':');
  NATMAP[internal] = { host, port: Number(port) };
}
const REPLICA_PORT = Number(process.env['TSK_SENTINEL_REPLICA_PORT'] ?? '6391');
const MASTER_CONTAINER = process.env['TSK_SENTINEL_MASTER_CONTAINER'] ?? 'tsk-sentinel-redis-master-1';
if (SENTINELS.length < 3) throw new Error('TSK_TEST_SENTINELS must list >=3 sentinels (quorum topology)');
if (Object.keys(NATMAP).length < 3) throw new Error('TSK_SENTINEL_NATMAP must map the 3 data nodes');

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
  console.log('# TSK PR2c Redis Sentinel failover drill (1 master + 2 replicas + 3 sentinels, quorum 2, enforced-WAIT claim)');
  // sentinel-backed client used by the fencing store — auto-follows the master across failover (via natMap).
  const sentinelClient = new Redis({ sentinels: SENTINELS, name: MASTER_NAME, role: 'master', natMap: NATMAP, maxRetriesPerRequest: 3, sentinelRetryStrategy: () => 200 });
  sentinelClient.on('error', () => {});
  // ENFORCED durable claim: WAIT for >=1 replica ACK inside claim() before success (RPO=0 is a store property).
  const store = new RedisFencingStore(sentinelClient, FENCE_KEY, { waitReplicas: 1, waitTimeoutMs: 3_000 });
  // a DIRECT connection to a sentinel node (SENTINEL admin commands don't route through the master client).
  const sentinelAdmin = new Redis({ host: SENTINELS[0].host, port: SENTINELS[0].port, maxRetriesPerRequest: 2 }); sentinelAdmin.on('error', () => {});
  const masterAddr = async () => await sentinelAdmin.call('SENTINEL', 'get-master-addr-by-name', MASTER_NAME) as string[];

  // wait until Sentinel has a reachable master and the store is usable.
  await waitFor('initial master reachable', async () => { await sentinelClient.set('tsk:probe', '1'); }, 30_000);

  const HOUR = 3_600_000;
  const replica = new Redis({ host: '127.0.0.1', port: REPLICA_PORT, maxRetriesPerRequest: 2 }); replica.on('error', () => {});

  await check('durable claim of fence epoch 1 — claim() ENFORCES a WAIT replica-quorum ACK before success', async () => {
    await sentinelClient.del(FENCE_KEY);
    const ok = await store.claim({ nodeId: 'B', fenceEpoch: 1, expiresAt: Date.now() + HOUR, commandId: 'c1' });
    assert.equal(ok, true, 'claim succeeded => WAIT confirmed >=1 replica durably has it');
    const cur = await store.current();
    assert.ok(cur && cur.fenceEpoch === 1 && cur.nodeId === 'B' && cur.commandId === 'c1' && cur.active === true);
    // corroborate on a replica directly (no caller-side WAIT — the store already enforced it).
    const raw = await waitFor('replica has fence', async () => { const v = await replica.get(FENCE_KEY); if (!v) throw new Error('not yet'); return v; }, 5_000);
    assert.ok(String(raw).includes('"fenceEpoch":1'));
    assert.equal(String((await replica.call('ROLE') as unknown[])[0]), 'slave', 'the replica is a slave before failover');
  });

  const oldMasterAddr = await masterAddr();
  // a RECONNECTING process uses a fresh Sentinel-backed client (it does NOT inherit the dead connection);
  // this measures data-plane RTO (Sentinel failover + connect), not one long-lived socket's slow follow.
  const freshStore = () => new RedisFencingStore(new Redis({ sentinels: SENTINELS, name: MASTER_NAME, role: 'master', natMap: NATMAP, maxRetriesPerRequest: 5, sentinelRetryStrategy: () => 200 }), FENCE_KEY, { waitReplicas: 1, waitTimeoutMs: 3_000 });

  let rtoMs = 0; let survivor: ReturnType<typeof freshStore>;
  await check('MASTER CRASH (SHUTDOWN NOSAVE) → Sentinel promotes a replica; the durably-claimed fence SURVIVES (RPO=0)', async () => {
    const t0 = now();
    execFileSync('docker', ['exec', MASTER_CONTAINER, 'redis-cli', 'SHUTDOWN', 'NOSAVE'], { stdio: 'ignore' }); // real crash
    const newMasterAddr = await waitFor('sentinel promotes a new master', async () => { const a = await masterAddr(); if (JSON.stringify(a) === JSON.stringify(oldMasterAddr)) throw new Error('same'); return a; }, 30_000, 250);
    assert.notDeepEqual(newMasterAddr, oldMasterAddr, 'Sentinel promoted a new master');
    survivor = freshStore();
    const cur = await waitFor('fence readable on the promoted master', async () => { const c = await survivor.current(); if (!c) throw new Error('no fence yet'); return c; }, 30_000, 200);
    rtoMs = now() - t0;
    assert.ok(cur.fenceEpoch === 1 && cur.nodeId === 'B' && cur.commandId === 'c1', 'the epoch-1 fence survived the failover unchanged (RPO=0)');
  });

  await check('the promoted master is WRITABLE + MONOTONIC: epoch 2 durably claims, epoch 1 is refused (no rollback)', async () => {
    await waitFor('epoch 2 durable claim on the new master', async () => {
      const ok2 = await survivor.claim({ nodeId: 'B2', fenceEpoch: 2, expiresAt: Date.now() + HOUR, commandId: 'c2' }); // enforced WAIT quorum
      if (!ok2) throw new Error('not durably writable yet');
      return ok2;
    }, 20_000, 250);
    assert.equal((await survivor.current())!.fenceEpoch, 2);
    const rollback = await survivor.claim({ nodeId: 'Bx', fenceEpoch: 1, expiresAt: Date.now() + HOUR, commandId: 'cx' });
    assert.equal(rollback, false, 'an older epoch cannot reclaim after failover — no split-brain rollback');
    assert.equal((await survivor.current())!.fenceEpoch, 2);
  });

  console.log('\n# ── measured per-fault RPO / RTO ──');
  console.log(`  fault: Redis MASTER CRASH (SHUTDOWN NOSAVE) → Sentinel quorum (2-of-3) failover, 3 data nodes`);
  console.log(`  RPO  : 0  (claim() enforced a WAIT replica-quorum ACK before success; fence survived, epoch/node/command unchanged)`);
  console.log(`  RTO  : ${rtoMs} ms  (master crash → fence readable on the promoted master; +re-sync window to durably writable)`);
  console.log(`\n# ${passed} PR2c Sentinel-failover checks passed`);

  await sentinelClient.quit().catch(() => {});
  await sentinelAdmin.quit().catch(() => {});
  await replica.quit().catch(() => {});
  process.exit(0);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
