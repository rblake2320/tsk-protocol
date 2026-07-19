import { Redis } from 'ioredis';
import { generateTumblerMap } from './packages/core/src/tumbler-map.ts';
import {
  FencedTumblerStore,
  PromotionController,
  WriterFencedError,
  handlePromotionCommand,
  signGuardCommand,
} from './packages/server/src/promotion.ts';
import { RedisFencingStore, FenceDurabilityUncertainError } from './packages/server/src/redis-fencing-store.ts';
import { MemoryTumblerStore } from './packages/server/src/store.ts';
import type { ReplicationCheckpoint } from './packages/server/src/replicating-tumbler-store.ts';

const url = process.env.TSK_REDIS_URL ?? 'redis://127.0.0.1:6389';
const key = `tsk:test:fence:${process.pid}:${Date.now()}`;
const guard = 'redis-integration-guard-secret-at-least-32-bytes';
const now = Date.now();
const checkpoint: ReplicationCheckpoint = {
  streamId: 'redis-integration-stream',
  epoch: 1,
  sequence: 1,
  headHash: 'a'.repeat(64),
};
const redisA = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 1 });
const redisB = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 1 });
let passed = 0;
let failed = 0;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function test(name: string, fn: () => Promise<void>): Promise<void> {
  try { await fn(); passed++; console.log(`  PASS ${name}`); }
  catch (error) { failed++; console.error(`  FAIL ${name}:`, error); }
}

function command(input: {
  command: 'activate' | 'promote';
  nodeId: string;
  fenceEpoch: number;
  requiredCheckpoint?: ReplicationCheckpoint;
}) {
  return signGuardCommand({
    ...input,
    issuedAt: now,
    expiresAt: now + 60_000,
    by: 'redis-integration-guard',
  }, guard);
}

try {
  await Promise.all([redisA.connect(), redisB.connect()]);
  const fenceA = new RedisFencingStore(redisA, key);
  const fenceB = new RedisFencingStore(redisB, key);

  await test('empty Redis fence has no current writer', async () => {
    assert(await fenceA.current() === null, 'new fence key was not empty');
  });

  await test('concurrent equal-epoch claims admit exactly one writer', async () => {
    const claims = await Promise.all([
      fenceA.claim({ nodeId: 'a', fenceEpoch: 1, expiresAt: now + 60_000, commandId: 'a-1' }),
      fenceB.claim({ nodeId: 'b', fenceEpoch: 1, expiresAt: now + 60_000, commandId: 'b-1' }),
    ]);
    assert(claims.filter(Boolean).length === 1, `equal epoch admitted ${claims.filter(Boolean).length}`);
  });

  await test('lower and equal epochs cannot replace the current record', async () => {
    assert(!await fenceA.claim({ nodeId: 'c', fenceEpoch: 1, expiresAt: now + 60_000, commandId: 'c-1' }), 'equal epoch replaced writer');
    let invalidEpochRejected = false;
    try {
      await fenceA.claim({ nodeId: 'c', fenceEpoch: 0, expiresAt: now + 60_000, commandId: 'c-0' });
    } catch {
      invalidEpochRejected = true;
    }
    assert(invalidEpochRejected, 'invalid zero epoch was accepted');
  });

  await test('higher epoch fences a live primary at the actual store boundary', async () => {
    await redisA.del(key);
    const primaryController = new PromotionController('primary', 'primary', fenceA, { now: () => now });
    const replicaController = new PromotionController(
      'replica',
      'replica',
      fenceB,
      { now: () => now, replicaCheckpoint: () => checkpoint },
    );
    const inner = new MemoryTumblerStore();
    const store = new FencedTumblerStore(inner, primaryController);
    const map = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
    assert((await handlePromotionCommand(
      primaryController,
      command({ command: 'activate', nodeId: 'primary', fenceEpoch: 10 }),
      guard,
    )).status === 200, 'primary activation failed');
    await store.set(map.clientId, map);
    assert((await handlePromotionCommand(
      replicaController,
      command({ command: 'promote', nodeId: 'replica', fenceEpoch: 11, requiredCheckpoint: checkpoint }),
      guard,
    )).status === 200, 'replica promotion failed');
    let fenced = false;
    try { await store.delete(map.clientId); }
    catch (error) { fenced = error instanceof WriterFencedError; }
    assert(fenced, 'old primary mutated after higher Redis epoch');
    assert(await inner.get(map.clientId) !== null, 'fenced delete reached inner store');
  });

  await test('only the exact active lease can release the record', async () => {
    const current = await fenceA.current();
    assert(current !== null && current.active, 'missing active fence');
    assert(!await fenceA.release('wrong', current.fenceEpoch, current.commandId), 'wrong node released fence');
    assert(await fenceA.release(current.nodeId, current.fenceEpoch, current.commandId), 'exact lease did not release');
    assert((await fenceA.current())?.active === false, 'release did not retain inactive epoch tombstone');
  });

  await test('corrupt Redis authority fails closed', async () => {
    await redisA.set(key, '{bad-json');
    let rejected = false;
    try { await fenceA.current(); } catch { rejected = true; }
    assert(rejected, 'corrupt record was accepted as empty/current');
  });

  await test('enforced-WAIT: a CAS that WROTE but the replica quorum did not ACK throws typed Uncertain (not ordinary false)', async () => {
    const durKey = `${key}:dur`;
    await redisA.del(durKey);
    const durStore = new RedisFencingStore(redisA, durKey, { waitReplicas: 1, waitTimeoutMs: 500 });
    // single node, NO replicas → WAIT returns 0 < 1 → the CAS wrote but durability is UNKNOWN → typed throw.
    let typed = false, stored = false;
    try { await durStore.claim({ nodeId: 'B', fenceEpoch: 1, expiresAt: Date.now() + 3_600_000, commandId: 'c1' }); }
    catch (e) { typed = e instanceof FenceDurabilityUncertainError; stored = (e as FenceDurabilityUncertainError).storedTuple?.fenceEpoch === 1; }
    assert(typed, 'expected a typed FenceDurabilityUncertainError, not an ordinary false, when WAIT under-acks after a successful CAS');
    assert(stored, 'the typed error must carry the exact stored tuple for reconciliation');
    // a CAS that is REFUSED (epoch not strictly higher) is an ordinary durable no-op — false, NEVER a throw.
    const refused = await durStore.claim({ nodeId: 'B', fenceEpoch: 1, expiresAt: Date.now() + 3_600_000, commandId: 'c1' });
    assert(refused === false, 'a refused CAS must return ordinary false (no WAIT ambiguity)');
    await redisA.del(durKey);
  });

  await test('enforced-WAIT dedicated-connection continuity: disconnect/rejection AFTER dispatch is typed Uncertain, never silent/false; no reconnect/replay', async () => {
    // Deterministic hermetic stub of the DEDICATED physical connection (redis.duplicate). Each case programs
    // the EVAL/WAIT outcome so a disconnect/rejection AFTER the CAS is dispatched is exercised WITHOUT a live
    // cluster — proving claim() reports typed uncertainty on that exact path, and that the connection is
    // created with reconnect/retry/RESEND fully disabled (so a whole-pipeline replay on a new master, which
    // would return matching ids + CAS0, cannot occur → CAS0 is an honest refusal, not a silent success).
    const dur = { waitReplicas: 1, waitTimeoutMs: 500 };
    const storedJson = JSON.stringify({ nodeId: 'B', fenceEpoch: 1, expiresAt: Date.now() + 3_600_000, commandId: 'c1', active: true });
    let lastOpts: Record<string, unknown> = {};
    const conn = (evalOut: () => Promise<unknown>, callOut: () => Promise<unknown>, connectOut: () => Promise<unknown> = async () => undefined) =>
      ({ connect: connectOut, disconnect: () => {}, eval: evalOut, call: callOut });
    const mk = (c: ReturnType<typeof conn>) => new RedisFencingStore({ duplicate: (o: Record<string, unknown>) => { lastOpts = o; return c; }, get: async () => storedJson } as unknown as Redis, 'k:ded', dur);
    const rec = { nodeId: 'B', fenceEpoch: 1, expiresAt: Date.now() + 3_600_000, commandId: 'c1' };
    const reject = () => { throw new Error('Connection is closed'); };
    const isUncertain = async (c: ReturnType<typeof conn>) => { try { await mk(c).claim(rec); return false; } catch (e) { return e instanceof FenceDurabilityUncertainError; } };
    // EVAL rejects AFTER dispatch (socket dropped mid-CAS) → the CAS may have applied → Uncertain.
    assert(await isUncertain(conn(async () => reject(), async () => 1)), 'an EVAL rejection after dispatch must be typed Uncertain');
    // CAS wrote (1), then WAIT rejects (socket dropped) → Uncertain.
    assert(await isUncertain(conn(async () => 1, async () => reject())), 'a WAIT rejection after a successful CAS must be typed Uncertain');
    // CAS wrote (1), WAIT under-acked → Uncertain.
    assert(await isUncertain(conn(async () => 1, async () => 0)), 'an under-ack must be typed Uncertain');
    // CAS wrote (1), WAIT acked on the SAME dedicated socket → durable success.
    assert((await mk(conn(async () => 1, async () => 1)).claim(rec)) === true, 'a quorum-acked same-connection claim succeeds');
    // CAS REFUSED (epoch not higher) → ordinary false; replay is IMPOSSIBLE on this connection so CAS0 is honest.
    assert((await mk(conn(async () => 0, async () => 0)).claim(rec)) === false, 'a genuinely refused CAS is ordinary false');
    // a PRE-dispatch connect failure propagates (the claim never started) — not a silent false.
    let connectFailPropagated = false;
    try { await mk(conn(async () => 1, async () => 1, async () => reject())).claim(rec); }
    catch (e) { connectFailPropagated = !(e instanceof FenceDurabilityUncertainError); }
    assert(connectFailPropagated, 'a pre-dispatch connect failure must propagate, not become a silent false/uncertain');
    // STRUCTURAL: the dedicated connection disables reconnect/retry/offline-queue/RESEND → no path-switch/replay.
    assert(lastOpts.autoResendUnfulfilledCommands === false && lastOpts.enableOfflineQueue === false && lastOpts.maxRetriesPerRequest === 0 && typeof lastOpts.retryStrategy === 'function' && (lastOpts.retryStrategy as () => unknown)() === null, 'claim must pin a non-retrying, non-replaying dedicated connection');
  });
} finally {
  await redisA.del(key).catch(() => undefined);
  await Promise.all([redisA.quit().catch(() => undefined), redisB.quit().catch(() => undefined)]);
}

console.log(`Redis fencing integration: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
