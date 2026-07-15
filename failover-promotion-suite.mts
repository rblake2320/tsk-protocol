import {
  MemoryFencingStore,
  FencedTumblerStore,
  PromotionController,
  WriterFencedError,
  assertWritable,
  handlePromotionCommand,
  signGuardCommand,
  type GuardCommand,
} from './packages/server/src/promotion.ts';
import { generateTumblerMap } from './packages/core/src/tumbler-map.ts';
import { MemoryTumblerStore } from './packages/server/src/store.ts';
import { FailoverTransport, PrimaryUnavailableError } from './packages/client-sdk/src/failover-transport.ts';
import type { ReplicationCheckpoint } from './packages/server/src/replicating-tumbler-store.ts';

const GUARD = 'guard-signing-secret-32-bytes-minimum-value';
const NOW = 1_750_000_000_000;
const CHECKPOINT: ReplicationCheckpoint = { streamId: 'stream-a', epoch: 4, sequence: 19, headHash: 'a'.repeat(64) };
let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (error) { failed++; console.error(`  ✗ ${name}:`, error); }
}
function assert(condition: unknown, message: string) { if (!condition) throw new Error(message); }

function command(input: {
  command: 'activate' | 'promote' | 'demote';
  nodeId: string;
  fenceEpoch: number;
  requiredCheckpoint?: ReplicationCheckpoint;
  issuedAt?: number;
  expiresAt?: number;
}): GuardCommand {
  return signGuardCommand({
    ...input,
    issuedAt: input.issuedAt ?? NOW,
    expiresAt: input.expiresAt ?? NOW + 60_000,
    by: 'fleet-guard',
    reason: 'controlled failover',
  }, GUARD);
}

console.log('\nTSK fenced promotion and failover suite');

await test('no primary or replica is writable without a fresh signed lease', async () => {
  const fence = new MemoryFencingStore();
  const primary = new PromotionController('primary', 'primary-a', fence, { now: () => NOW });
  const replica = new PromotionController('replica', 'replica-a', fence, { now: () => NOW, replicaCheckpoint: () => CHECKPOINT });
  assert(!(await assertWritable(primary)).ok, 'unleased primary was writable');
  assert(!(await assertWritable(replica)).ok, 'unpromoted replica was writable');
});

await test('higher replica epoch fences the old primary through the shared store', async () => {
  const fence = new MemoryFencingStore();
  const primary = new PromotionController('primary', 'primary-a', fence, { now: () => NOW });
  const replica = new PromotionController('replica', 'replica-a', fence, { now: () => NOW, replicaCheckpoint: () => CHECKPOINT });
  const active = await handlePromotionCommand(primary, command({ command: 'activate', nodeId: 'primary-a', fenceEpoch: 10 }), GUARD);
  assert(active.status === 200 && (await assertWritable(primary)).ok, 'primary activation failed');
  const promoted = await handlePromotionCommand(replica, command({
    command: 'promote', nodeId: 'replica-a', fenceEpoch: 11, requiredCheckpoint: CHECKPOINT,
  }), GUARD);
  assert(promoted.status === 200, JSON.stringify(promoted));
  assert(!(await assertWritable(primary)).ok, 'old primary remained writable after newer epoch');
  assert((await assertWritable(replica)).ok, 'promoted replica not writable');
});

await test('promotion fails when local checkpoint is missing, lossy, or behind', async () => {
  const fence = new MemoryFencingStore();
  const behind = { ...CHECKPOINT, sequence: CHECKPOINT.sequence - 1, headHash: 'b'.repeat(64) };
  const replica = new PromotionController('replica', 'replica-a', fence, { now: () => NOW, replicaCheckpoint: () => behind });
  const result = await handlePromotionCommand(replica, command({
    command: 'promote', nodeId: 'replica-a', fenceEpoch: 1, requiredCheckpoint: CHECKPOINT,
  }), GUARD);
  assert(result.status === 409, JSON.stringify(result));
  assert(!(await assertWritable(replica)).ok, 'non-converged replica was writable');
});

await test('tampered, stale, expired, and replayed grants are denied', async () => {
  const fence = new MemoryFencingStore();
  const primary = new PromotionController('primary', 'primary-a', fence, { now: () => NOW });
  const valid = command({ command: 'activate', nodeId: 'primary-a', fenceEpoch: 5 });
  const tampered = { ...valid, fenceEpoch: 6 };
  assert((await handlePromotionCommand(primary, tampered, GUARD)).status === 401, 'tamper accepted');
  const stale = command({ command: 'activate', nodeId: 'primary-a', fenceEpoch: 5, issuedAt: NOW - 60_001, expiresAt: NOW + 1 });
  assert((await handlePromotionCommand(primary, stale, GUARD)).status === 401, 'stale grant accepted');
  const expired = command({ command: 'activate', nodeId: 'primary-a', fenceEpoch: 5, issuedAt: NOW - 1000, expiresAt: NOW });
  assert((await handlePromotionCommand(primary, expired, GUARD)).status === 401, 'expired grant accepted');
  assert((await handlePromotionCommand(primary, valid, GUARD)).status === 200, 'valid grant failed');
  assert((await handlePromotionCommand(primary, valid, GUARD)).status === 409, 'replayed epoch accepted');
});

await test('lease expiry and fencing-store failure deny writes', async () => {
  let now = NOW;
  const fence = new MemoryFencingStore();
  const primary = new PromotionController('primary', 'primary-a', fence, { now: () => now });
  assert((await handlePromotionCommand(primary, command({ command: 'activate', nodeId: 'primary-a', fenceEpoch: 1, expiresAt: NOW + 10 }), GUARD)).status === 200, 'activation failed');
  now += 11;
  assert(!(await assertWritable(primary)).ok, 'expired lease remained writable');

  const broken = new PromotionController('primary', 'broken', {
    current: async () => { throw new Error('fence unavailable'); },
    claim: async () => true,
    release: async () => false,
  }, { now: () => NOW });
  assert((await handlePromotionCommand(broken, command({ command: 'activate', nodeId: 'broken', fenceEpoch: 2 }), GUARD)).status === 200, 'test activation failed');
  assert(!(await assertWritable(broken)).ok, 'fence outage failed open');
});

await test('signed demotion releases the active fence and cannot be replayed', async () => {
  const fence = new MemoryFencingStore();
  const replica = new PromotionController('replica', 'replica-a', fence, { now: () => NOW, replicaCheckpoint: () => CHECKPOINT });
  assert((await handlePromotionCommand(replica, command({ command: 'promote', nodeId: 'replica-a', fenceEpoch: 9, requiredCheckpoint: CHECKPOINT }), GUARD)).status === 200, 'promotion failed');
  const demote = command({ command: 'demote', nodeId: 'replica-a', fenceEpoch: 9 });
  assert((await handlePromotionCommand(replica, demote, GUARD)).status === 200, 'demotion failed');
  assert(!(await assertWritable(replica)).ok, 'demoted replica remained writable');
  assert((await handlePromotionCommand(replica, demote, GUARD)).status === 409, 'demotion replay accepted');
});

await test('fenced store denies every mutation until the primary has a fresh lease', async () => {
  const fence = new MemoryFencingStore();
  const controller = new PromotionController('primary', 'primary-a', fence, { now: () => NOW });
  const inner = new MemoryTumblerStore();
  const store = new FencedTumblerStore(inner, controller);
  const map = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });

  let denied = false;
  try { await store.set(map.clientId, map); }
  catch (error) { denied = error instanceof WriterFencedError; }
  assert(denied, 'unleased set was not denied by the store boundary');
  assert(await inner.get(map.clientId) === null, 'denied set mutated the inner store');

  const activation = await handlePromotionCommand(
    controller,
    command({ command: 'activate', nodeId: 'primary-a', fenceEpoch: 1 }),
    GUARD,
  );
  assert(activation.status === 200, 'primary activation failed');
  await store.set(map.clientId, map);
  assert(await inner.get(map.clientId) !== null, 'leased set did not reach the inner store');
});

await test('fenced store stops mutations after a higher-epoch replica promotion', async () => {
  const fence = new MemoryFencingStore();
  const primaryController = new PromotionController('primary', 'primary-a', fence, { now: () => NOW });
  const replicaController = new PromotionController(
    'replica',
    'replica-a',
    fence,
    { now: () => NOW, replicaCheckpoint: () => CHECKPOINT },
  );
  const inner = new MemoryTumblerStore();
  const store = new FencedTumblerStore(inner, primaryController);
  const map = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });

  assert((await handlePromotionCommand(
    primaryController,
    command({ command: 'activate', nodeId: 'primary-a', fenceEpoch: 20 }),
    GUARD,
  )).status === 200, 'primary activation failed');
  await store.set(map.clientId, map);
  assert((await handlePromotionCommand(
    replicaController,
    command({
      command: 'promote',
      nodeId: 'replica-a',
      fenceEpoch: 21,
      requiredCheckpoint: CHECKPOINT,
    }),
    GUARD,
  )).status === 200, 'replica promotion failed');

  let denied = false;
  try { await store.delete(map.clientId); }
  catch (error) { denied = error instanceof WriterFencedError; }
  assert(denied, 'old primary delete remained writable after fencing');
  assert(await inner.get(map.clientId) !== null, 'fenced delete mutated the inner store');
});

await test('FailoverTransport never redirects a write to a read replica', async () => {
  const calls: string[] = [];
  const fetchImpl = async (url: string | URL | Request) => {
    calls.push(String(url));
    throw new Error('primary down');
  };
  const transport = new FailoverTransport({
    primary: 'https://primary', replicas: ['https://replica'], missThreshold: 1,
    fetchImpl: fetchImpl as typeof fetch,
  });
  let unavailable = false;
  try { await transport.write('/mutate', { method: 'POST' }); }
  catch (error) { unavailable = error instanceof Error; }
  assert(unavailable, 'write failure not surfaced');
  assert(calls.every(url => !url.startsWith('https://replica')), `write hit replica: ${calls}`);
  let typed = false;
  try { await transport.write('/mutate'); } catch (error) { typed = error instanceof PrimaryUnavailableError; }
  assert(typed, 'subsequent write did not fail closed with PrimaryUnavailableError');
});

await test('reads may fail over and later fail back independently of writer leases', async () => {
  let primaryUp = false;
  const fetchImpl = async (url: string | URL | Request) => {
    const value = String(url);
    if (value.startsWith('https://primary') && !primaryUp) throw new Error('down');
    return new Response(value, { status: 200 });
  };
  const transport = new FailoverTransport({
    primary: 'https://primary', replicas: ['https://replica'], missThreshold: 1,
    fetchImpl: fetchImpl as typeof fetch,
  });
  const failedOver = await transport.read('/state');
  assert((await failedOver.text()).startsWith('https://replica'), 'read did not fail over');
  primaryUp = true;
  assert(await transport.probePrimary(), 'primary probe failed');
  const failedBack = await transport.read('/state');
  assert((await failedBack.text()).startsWith('https://primary'), 'read did not fail back');
});

console.log(`\nTSK fenced promotion suite: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
