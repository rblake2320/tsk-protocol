/**
 * TSK HA — ReplicatingTumblerStore test suite
 * Run with: npx tsx replicating-tumbler-suite.mts
 *
 * Imports the REAL decorator from packages/server/src so the wire format and
 * mutation surface are tested against the actual TumblerMapStore API.
 */
import { ReplicatingTumblerStore } from './packages/server/src/replicating-tumbler-store.ts';
import type { TumblerReplicaOp, SecretSealer } from './packages/server/src/replicating-tumbler-store.ts';
import { MemoryTumblerStore } from './packages/server/src/store.ts';
import type { TumblerMap } from './packages/core/src/types.ts';

// ─── Test harness (matches test-suite.mts convention) ────────────────────────
let passed = 0;
let failed = 0;
const failures: string[] = [];

async function test(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e: any) {
    failed++;
    const msg = e?.message ?? String(e);
    failures.push(`${name}: ${msg}`);
    console.log(`  ✗ ${name}`);
    console.log(`    ${msg}`);
  }
}
function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

// ─── Fixtures ────────────────────────────────────────────────────────────────
const SECRET = 'a'.repeat(64); // 256-bit hex secret — must NEVER cross the wire by default

function tumbler(clientId: string): TumblerMap {
  return {
    clientId,
    sharedSecret: SECRET,
    keyLength: 32,
    segments: [
      { segmentId: 'seg-static', position: [0, 8], type: 'static' },
      { segmentId: 'seg-hotp', position: [8, 16], type: 'hotp', counter: 0 },
    ],
    checksum: { position: [28, 32] },
    createdAt: Date.now(),   // fresh — MemoryTumblerStore.get() TTL-evicts stale maps (90d default)
    version: '1',
  };
}

function makeFetch(behavior: () => Response | Promise<Response>) {
  const calls: Array<{ url: string; body: any }> = [];
  const impl = (async (url: any, init: any) => {
    calls.push({ url: String(url), body: JSON.parse(init.body) });
    return behavior();
  }) as unknown as typeof fetch;
  return { impl, calls };
}
const OK = () => new Response('{}', { status: 200 });
const FAIL = () => new Response('err', { status: 503 });

// ─── Tests ───────────────────────────────────────────────────────────────────
console.log('\nTSK ReplicatingTumblerStore Suite\n' + '─'.repeat(60));

await test('HA-03′ CRITICAL: sharedSecret NEVER crosses the wire under default policy', async () => {
  const { impl, calls } = makeFetch(OK);
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(primary, { url: 'https://r.test/replica', token: 't' }, { fetchImpl: impl });
  await store.set('c1', tumbler('c1'));
  await store.flush();
  assert(calls.length === 1, `expected 1 push, got ${calls.length}`);
  const body = calls[0].body as Extract<TumblerReplicaOp, { op: 'set' }>;
  assert(body.op === 'set', 'op should be set');
  assert(body.map.sharedSecret === '', `sharedSecret must be stripped, got "${body.map.sharedSecret}"`);
  assert(body.secretSealed === false, 'secretSealed must be false under strip policy');
  // Belt-and-suspenders: the raw secret must appear NOWHERE in the serialized payload.
  assert(!JSON.stringify(calls[0].body).includes(SECRET), 'raw secret leaked into wire payload');
});

await test('primary still holds the real secret (strip only affects the replica copy)', async () => {
  const { impl } = makeFetch(OK);
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(primary, { url: 'https://r.test/replica', token: 't' }, { fetchImpl: impl });
  await store.set('c1', tumbler('c1'));
  const local = await store.get('c1');
  assert(local !== null && local.sharedSecret === SECRET, 'primary must retain the real secret');
});

await test('sealer opt-in: secret is sealed (not raw) and secretSealed=true', async () => {
  const { impl, calls } = makeFetch(OK);
  const sealer: SecretSealer = (_c, s) => `sealed:${s.length}`;
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(
    primary, { url: 'https://r.test/replica', token: 't' }, { fetchImpl: impl, secretPolicy: sealer },
  );
  await store.set('c1', tumbler('c1'));
  await store.flush();
  const body = calls[0].body as Extract<TumblerReplicaOp, { op: 'set' }>;
  assert(body.map.sharedSecret === 'sealed:64', `expected sealed token, got "${body.map.sharedSecret}"`);
  assert(body.secretSealed === true, 'secretSealed must be true with a sealer');
  assert(!JSON.stringify(calls[0].body).includes(SECRET), 'raw secret leaked despite sealer');
});

await test('updateCounters: JS Map is serialized to entries (survives JSON)', async () => {
  const { impl, calls } = makeFetch(OK);
  const primary = new MemoryTumblerStore();
  await primary.set('c1', tumbler('c1'));
  const store = new ReplicatingTumblerStore(primary, { url: 'https://r.test/replica', token: 't' }, { fetchImpl: impl });
  await store.updateCounters('c1', new Map([['seg-hotp', 5]]));
  await store.flush();
  const body = calls[0].body as Extract<TumblerReplicaOp, { op: 'updateCounters' }>;
  assert(body.op === 'updateCounters', 'op should be updateCounters');
  assert(Array.isArray(body.updates), 'updates must serialize to an array, not {}');
  assert(body.updates.length === 1 && body.updates[0][0] === 'seg-hotp' && body.updates[0][1] === 5,
    `entries wrong: ${JSON.stringify(body.updates)}`);
});

await test('consumeCounter: mirrored only on SUCCESS, returns primary verdict', async () => {
  const { impl, calls } = makeFetch(OK);
  const primary = new MemoryTumblerStore();
  await primary.set('c1', tumbler('c1'));   // hotp counter starts at 0
  const store = new ReplicatingTumblerStore(primary, { url: 'https://r.test/replica', token: 't' }, { fetchImpl: impl });

  const first = await store.consumeCounter('c1', 'seg-hotp', 0);   // success → advances to 1
  assert(first === true, 'first consume should succeed');
  // A replay at the same matched counter is now behind → primary rejects, NOT mirrored.
  const replay = await store.consumeCounter('c1', 'seg-hotp', 0);
  assert(replay === false, 'replay at consumed counter must be rejected');
  await store.flush();

  const consumeOps = calls.filter(c => (c.body as TumblerReplicaOp).op === 'consumeCounter');
  assert(consumeOps.length === 1, `only the successful consume should be mirrored, got ${consumeOps.length}`);
});

await test('HA-01: replica failure NEVER fails or blocks the primary mutation', async () => {
  const { impl } = makeFetch(FAIL);
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(
    primary, { url: 'https://r.test/replica', token: 't' }, { fetchImpl: impl, backoffBaseMs: 1, backoffMaxMs: 2 },
  );
  await store.set('c1', tumbler('c1'));          // resolves despite 503
  assert((await store.get('c1')) !== null, 'primary write must persist regardless of replica');
});

await test('retries failed pushes then succeeds (queue head preserved)', async () => {
  let n = 0;
  const { impl, calls } = makeFetch(() => (++n < 3 ? FAIL() : OK()));
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(
    primary, { url: 'https://r.test/replica', token: 't' }, { fetchImpl: impl, backoffBaseMs: 1, backoffMaxMs: 2 },
  );
  await store.set('c1', tumbler('c1'));
  const flushed = await store.flush(2000);
  assert(flushed, 'queue should drain within timeout');
  assert(calls.length === 3, `expected 2 failures + 1 success, got ${calls.length}`);
  assert(store.queueDepth === 0, 'queue should be empty after success');
});

await test('HA-02: bounded queue sheds OLDEST and fires onDrop', async () => {
  const dropped: TumblerReplicaOp[] = [];
  const { impl } = makeFetch(FAIL);   // permanently down → nothing drains
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(
    primary, { url: 'https://r.test/replica', token: 't' },
    { fetchImpl: impl, maxQueue: 3, backoffBaseMs: 10_000, backoffMaxMs: 10_000, onDrop: (op) => dropped.push(op) },
  );
  for (const id of ['a', 'b', 'c', 'd', 'e']) await store.set(id, tumbler(id));
  assert(store.queueDepth <= 3, `queue should be capped at 3, got ${store.queueDepth}`);
  assert(dropped.length >= 1, 'onDrop should have fired');
  assert((dropped[0] as any).clientId === 'a', 'oldest (a) should be shed first');
});

await test('reads are served from primary, never the replica', async () => {
  const { impl, calls } = makeFetch(OK);
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(primary, { url: 'https://r.test/replica', token: 't' }, { fetchImpl: impl });
  await store.set('c1', tumbler('c1'));
  await store.flush();
  const before = calls.length;
  await store.get('c1');
  await store.list();
  assert(calls.length === before, 'reads must not generate replica traffic');
});

// ─── Results ─────────────────────────────────────────────────────────────────
console.log('\n' + '─'.repeat(60));
console.log(`TSK ReplicatingTumblerStore Suite: ${passed}/${passed + failed} passed`);
if (failed > 0) {
  console.log(`\nFAILURES (${failed}):`);
  for (const f of failures) console.log(`  ✗ ${f}`);
  process.exit(1);
} else {
  console.log('ALL TESTS PASSED — TSK replication decorator verified');
  process.exit(0);   // explicit: a pending backoff setTimeout would otherwise keep node alive
}
