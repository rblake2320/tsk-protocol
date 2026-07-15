import { Redis } from 'ioredis';
import { generateTumblerMap } from './packages/core/src/tumbler-map.ts';
import {
  FencedTumblerStore,
  PromotionController,
  WriterFencedError,
  handlePromotionCommand,
  signGuardCommand,
} from './packages/server/src/promotion.ts';
import { RedisFencingStore } from './packages/server/src/redis-fencing-store.ts';
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
} finally {
  await redisA.del(key).catch(() => undefined);
  await Promise.all([redisA.quit().catch(() => undefined), redisB.quit().catch(() => undefined)]);
}

console.log(`Redis fencing integration: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
