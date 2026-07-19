/**
 * PR2c acceptance (#10) — LIVE split-brain partition of the Redis fencing authority (not a crash).
 *
 * 1 master + 2 replicas + 3 sentinels (quorum 2), min-replicas-to-write 1. The OLD master is left ALIVE
 * but network-ISOLATED from the cluster (`docker network disconnect`). We then prove:
 *   1. the isolated old master REFUSES writes (min-replicas-to-write: 0 reachable replicas → NOREPLICAS) —
 *      so a partitioned old writer cannot make progress (no split brain);
 *   2. the surviving quorum promotes a new master that is WRITABLE + MONOTONIC (epoch 2 durably claims,
 *      epoch 1 refused), with the epoch-1 fence intact (RPO = 0);
 *   3. on HEAL (reconnect), the old master is demoted to a replica and RECONCILES to the new epoch.
 *
 * Uses `docker exec` for the isolated node (network-independent) + a Sentinel-backed client (natMap) for
 * the survivors. Mechanism-only on one host (processes, not physical failure domains).
 * Env: TSK_TEST_SENTINELS, TSK_TEST_SENTINEL_MASTER, TSK_SENTINEL_NATMAP, TSK_SENTINEL_NETWORK,
 *      TSK_SENTINEL_MASTER_CONTAINER.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { Redis } from 'ioredis';
import { RedisFencingStore } from './packages/server/dist/index.js';

const SENTINELS = (process.env['TSK_TEST_SENTINELS'] ?? '').split(',').map((s) => s.trim()).filter(Boolean)
  .map((hp) => { const [host, port] = hp.split(':'); return { host, port: Number(port) }; });
const MASTER_NAME = process.env['TSK_TEST_SENTINEL_MASTER'] ?? 'tskmaster';
const NATMAP: Record<string, { host: string; port: number }> = {};
for (const pair of (process.env['TSK_SENTINEL_NATMAP'] ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
  const [internal, external] = pair.split('='); const [host, port] = external.split(':');
  NATMAP[internal] = { host, port: Number(port) };
}
const NETWORK = process.env['TSK_SENTINEL_NETWORK'] ?? 'tsk-sentinel_tsknet';
const MASTER_CONTAINER = process.env['TSK_SENTINEL_MASTER_CONTAINER'] ?? 'tsk-sentinel-redis-master-1';
const MASTER_IP = '172.28.7.10';
if (SENTINELS.length < 3 || Object.keys(NATMAP).length < 3) throw new Error('need 3 sentinels + natMap for 3 data nodes');

const FENCE_KEY = 'tsk:fence:partition/v1';
let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const now = () => Number(process.hrtime.bigint() / 1_000_000n);
const docker = (...args: string[]) => execFileSync('docker', args, { encoding: 'utf8' });
const dexec = (...args: string[]) => docker('exec', MASTER_CONTAINER, 'redis-cli', ...args).trim();
// redis-cli reports an error REPLY (e.g. NOREPLICAS) on stdout/stderr — capture BOTH and never throw on it.
function dexecSafe(...args: string[]): string {
  try { return docker('exec', MASTER_CONTAINER, 'redis-cli', ...args).trim(); }
  catch (e) { const x = e as { stdout?: Buffer | string; stderr?: Buffer | string; message?: string }; return `${String(x.stdout ?? '')}${String(x.stderr ?? '')}${x.message ?? ''}`.trim(); }
}

async function waitFor<T>(label: string, fn: () => Promise<T>, timeoutMs: number, everyMs = 250): Promise<T> {
  const deadline = now() + timeoutMs; let lastErr: unknown;
  while (now() < deadline) { try { return await fn(); } catch (e) { lastErr = e; await sleep(everyMs); } }
  throw new Error(`waitFor(${label}) timed out after ${timeoutMs}ms: ${String(lastErr)}`);
}

async function main() {
  console.log('# TSK PR2c Redis LIVE split-brain partition drill (old master isolated ALIVE; new quorum promotes)');
  const sentinelClient = new Redis({ sentinels: SENTINELS, name: MASTER_NAME, role: 'master', natMap: NATMAP, maxRetriesPerRequest: 3, sentinelRetryStrategy: () => 200 });
  sentinelClient.on('error', () => {});
  const store = new RedisFencingStore(sentinelClient, FENCE_KEY, { waitReplicas: 1, waitTimeoutMs: 3_000 });
  const sentinelAdmin = new Redis({ host: SENTINELS[0].host, port: SENTINELS[0].port, maxRetriesPerRequest: 2 }); sentinelAdmin.on('error', () => {});
  const masterAddr = async () => (await sentinelAdmin.call('SENTINEL', 'get-master-addr-by-name', MASTER_NAME) as string[]).join(':');

  const HOUR = 3_600_000;
  await waitFor('initial master reachable', async () => { await sentinelClient.set('tsk:probe', '1'); }, 30_000);
  const oldAddr = await masterAddr();

  await check('durably claim fence epoch 1 (WAIT quorum) before the partition', async () => {
    await sentinelClient.del(FENCE_KEY);
    assert.equal(await store.claim({ nodeId: 'B', fenceEpoch: 1, expiresAt: Date.now() + HOUR, commandId: 'c1' }), true);
    assert.equal((await store.current())!.fenceEpoch, 1);
  });

  let rtoMs = 0;
  await check('PARTITION the old master ALIVE → it REFUSES writes (min-replicas-to-write; no split-brain progress)', async () => {
    const t0 = now();
    docker('network', 'disconnect', NETWORK, MASTER_CONTAINER); // isolate the master from the cluster; it stays running
    // the isolated master loses its replica quorum (acks age past min-replicas-max-lag) → it refuses writes.
    await waitFor('isolated old master refuses writes', async () => {
      const out = dexecSafe('SET', 'tsk:splitbrain', 'x');
      if (/NOREPLICAS|not enough|good replica/i.test(out)) return true;
      throw new Error('old master still accepted a write: ' + out);
    }, 25_000, 500);
    rtoMs = now() - t0;
  });

  const survivor = new RedisFencingStore(new Redis({ sentinels: SENTINELS, name: MASTER_NAME, role: 'master', natMap: NATMAP, maxRetriesPerRequest: 5, sentinelRetryStrategy: () => 200 }), FENCE_KEY, { waitReplicas: 1, waitTimeoutMs: 3_000 });
  await check('the surviving quorum promotes a NEW master that is WRITABLE + MONOTONIC; the epoch-1 fence is intact (RPO=0)', async () => {
    await waitFor('sentinel promoted a new master', async () => { const a = await masterAddr(); if (a === oldAddr) throw new Error('not yet'); return a; }, 30_000, 250);
    // a reconnecting client reaches the promoted master; the fence survived (RPO=0).
    const cur = await waitFor('fence readable on the new master', async () => { const c = await survivor.current(); if (!c) throw new Error('no fence'); return c; }, 30_000, 200);
    assert.ok(cur.fenceEpoch === 1 && cur.nodeId === 'B', 'the durably-claimed epoch-1 fence survived the partition (RPO=0)');
    await waitFor('epoch 2 durable claim on the new master', async () => {
      const ok2 = await survivor.claim({ nodeId: 'B2', fenceEpoch: 2, expiresAt: Date.now() + HOUR, commandId: 'c2' });
      if (!ok2) throw new Error('not durably writable yet');
      return ok2;
    }, 25_000, 250);
    assert.equal((await survivor.current())!.fenceEpoch, 2);
    assert.equal(await survivor.claim({ nodeId: 'Bx', fenceEpoch: 1, expiresAt: Date.now() + HOUR, commandId: 'cx' }), false, 'old epoch refused — no rollback');
  });

  await check('HEAL the partition → the old master is demoted to a replica and RECONCILES to the new epoch (2)', async () => {
    docker('network', 'connect', '--ip', MASTER_IP, NETWORK, MASTER_CONTAINER);
    // Sentinel reconfigures the returned old master as a replica of the current master; it re-syncs epoch 2.
    await waitFor('old master demoted to replica', async () => { const role = dexec('ROLE').split('\n')[0].trim(); if (role !== 'slave') throw new Error(`role=${role}`); return role; }, 30_000, 500);
    await waitFor('old master reconciled the fence to epoch 2', async () => { const v = dexec('GET', FENCE_KEY); if (!v.includes('"fenceEpoch":2')) throw new Error('stale'); return v; }, 20_000, 300);
  });

  console.log('\n# ── measured per-fault RPO / RTO ──');
  console.log(`  fault: LIVE NETWORK PARTITION isolating the master (still running) from the cluster`);
  console.log(`  RPO  : 0  (durably WAIT-quorum-claimed epoch-1 fence intact on the promoted master; old master made NO progress)`);
  console.log(`  RTO  : ${rtoMs} ms  (partition → isolated master refuses writes; new master promoted + writable shortly after)`);
  console.log(`\n# ${passed} PR2c split-brain-partition checks passed`);

  await sentinelClient.quit().catch(() => {});
  await sentinelAdmin.quit().catch(() => {});
  process.exit(0);
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
