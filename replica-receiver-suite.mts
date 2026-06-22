/**
 * TSK HA — replica receiver test suite
 * Run with: npx tsx replica-receiver-suite.mts
 *
 * Tests the receiver against the REAL decorator end-to-end: decorator push is
 * routed in-process into the receiver, and the replica store must converge to
 * the primary — while the raw shared secret never reaches the replica.
 */
import {
  authorizeReplica, validateTumblerOp, applyTumblerOp, handleTumblerIngest,
} from './packages/server/src/replica-receiver.ts';
import { ReplicatingTumblerStore } from './packages/server/src/replicating-tumbler-store.ts';
import { MemoryTumblerStore } from './packages/server/src/store.ts';
import type { TumblerMap } from './packages/core/src/types.ts';

let passed = 0, failed = 0;
const failures: string[] = [];
async function test(name: string, fn: () => Promise<void> | void) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e: any) { failed++; failures.push(`${name}: ${e?.message ?? e}`); console.log(`  ✗ ${name}\n    ${e?.message ?? e}`); }
}
function assert(c: boolean, m: string) { if (!c) throw new Error(m); }

const SECRET = 'a'.repeat(64);
const TOKEN = 'replica-shared-token';

function tumbler(clientId: string, counter = 0): TumblerMap {
  return {
    clientId, sharedSecret: SECRET, keyLength: 32,
    segments: [
      { segmentId: 'seg-static', position: [0, 8], type: 'static' },
      { segmentId: 'seg-hotp', position: [8, 16], type: 'hotp', counter },
    ],
    checksum: { position: [28, 32] }, createdAt: Date.now(), version: '1',
  };
}

console.log('\nTSK Replica Receiver Suite\n' + '─'.repeat(60));

// ── Auth ──
await test('RX-01: accepts correct token, rejects wrong/missing', () => {
  assert(authorizeReplica({ 'x-replica-token': TOKEN }, TOKEN), 'correct token must pass');
  assert(!authorizeReplica({ 'x-replica-token': 'nope' }, TOKEN), 'wrong token must fail');
  assert(!authorizeReplica({}, TOKEN), 'missing token must fail');
});

// ── Validation ──
await test('RX-04: rejects unknown op and malformed set', () => {
  assert(!validateTumblerOp({ op: 'nope' }).ok, 'unknown op rejected');
  assert(!validateTumblerOp({ op: 'set', clientId: 'c1' }).ok, 'set without map rejected');
  assert(!validateTumblerOp({ op: 'set', clientId: 'c1', map: { clientId: 'MISMATCH' } }).ok, 'clientId/map mismatch rejected');
  assert(validateTumblerOp({ op: 'set', clientId: 'c1', map: tumbler('c1'), secretSealed: false }).ok, 'good set accepted');
});

await test('RX-04: updateCounters entries validated, bad shapes rejected', () => {
  assert(validateTumblerOp({ op: 'updateCounters', clientId: 'c1', updates: [['seg', 3]] }).ok, 'valid entries accepted');
  assert(!validateTumblerOp({ op: 'updateCounters', clientId: 'c1', updates: { seg: 3 } }).ok, 'object (not entries) rejected');
  assert(!validateTumblerOp({ op: 'updateCounters', clientId: 'c1', updates: [['seg', 'x']] }).ok, 'non-number counter rejected');
});

// ── Apply / idempotency ──
await test('RX-02: updateCounters reconstructs Map and applies', async () => {
  const replica = new MemoryTumblerStore();
  await replica.set('c1', tumbler('c1', 0));
  await applyTumblerOp(replica, { op: 'updateCounters', clientId: 'c1', updates: [['seg-hotp', 7]] });
  const map = await replica.get('c1');
  const seg = map!.segments.find(s => s.segmentId === 'seg-hotp');
  assert(seg?.counter === 7, `counter should be 7, got ${seg?.counter}`);
});

await test('RX-02: consumeCounter re-delivery is monotonic (no double-advance)', async () => {
  const replica = new MemoryTumblerStore();
  await replica.set('c1', tumbler('c1', 0));
  await applyTumblerOp(replica, { op: 'consumeCounter', clientId: 'c1', segmentId: 'seg-hotp', matchedCounter: 0 }); // → 1
  await applyTumblerOp(replica, { op: 'consumeCounter', clientId: 'c1', segmentId: 'seg-hotp', matchedCounter: 0 }); // replay, rejected by CAS
  const seg = (await replica.get('c1'))!.segments.find(s => s.segmentId === 'seg-hotp');
  assert(seg?.counter === 1, `replay must not double-advance; counter should be 1, got ${seg?.counter}`);
});

// ── Status mapping ──
await test('handleTumblerIngest: 401 bad token (no mutation), 400 malformed, 200 good', async () => {
  const replica = new MemoryTumblerStore();
  const bad = await handleTumblerIngest(replica, { 'x-replica-token': 'x' }, { op: 'set', clientId: 'c1', map: tumbler('c1') }, TOKEN);
  assert(bad.status === 401, `bad token → 401, got ${bad.status}`);
  assert((await replica.list()).length === 0, 'no mutation on 401');
  const malformed = await handleTumblerIngest(replica, { 'x-replica-token': TOKEN }, { op: 'set', clientId: 'c1' }, TOKEN);
  assert(malformed.status === 400, `malformed → 400, got ${malformed.status}`);
  const good = await handleTumblerIngest(replica, { 'x-replica-token': TOKEN }, { op: 'set', clientId: 'c1', map: tumbler('c1') }, TOKEN);
  assert(good.status === 200, `good → 200, got ${good.status}`);
});

// ── END-TO-END convergence + secret safety ──
await test('END-TO-END: replica converges to primary AND never receives the raw secret', async () => {
  const primary = new MemoryTumblerStore();
  const replica = new MemoryTumblerStore();
  let sawRawSecret = false;

  const fetchImpl = (async (_url: any, init: any) => {
    if (String(init.body).includes(SECRET)) sawRawSecret = true;   // wire-level secret scan
    const body = JSON.parse(init.body);
    const headers = Object.fromEntries(Object.entries(init.headers));
    const { status } = await handleTumblerIngest(replica, headers, body, TOKEN);
    return new Response('{}', { status });
  }) as unknown as typeof fetch;

  const store = new ReplicatingTumblerStore(primary, { url: 'https://vps/replica', token: TOKEN }, { fetchImpl });

  await store.set('c1', tumbler('c1', 0));
  await store.set('c2', tumbler('c2', 0));
  await store.updateCounters('c1', new Map([['seg-hotp', 4]]));
  await store.consumeCounter('c2', 'seg-hotp', 0);   // success → mirrored
  await store.delete('c2');
  const drained = await store.flush(3000);
  assert(drained, 'queue should drain');

  assert(!sawRawSecret, 'raw shared secret must NEVER cross the wire (Tier-3 strip default)');

  // Replica converges: only c1 remains, with the propagated counter update.
  const ids = (await replica.list()).sort();
  assert(ids.length === 1 && ids[0] === 'c1', `replica should hold only c1, got ${JSON.stringify(ids)}`);
  const c1 = await replica.get('c1');
  assert(c1!.sharedSecret === '', 'replica copy must be metadata-only (sharedSecret stripped)');
  const seg = c1!.segments.find(s => s.segmentId === 'seg-hotp');
  assert(seg?.counter === 4, `counter update should propagate; got ${seg?.counter}`);
});

console.log('\n' + '─'.repeat(60));
console.log(`TSK Replica Receiver Suite: ${passed}/${passed + failed} passed`);
if (failed > 0) {
  console.log(`\nFAILURES (${failed}):`);
  for (const f of failures) console.log(`  ✗ ${f}`);
  process.exit(1);
} else {
  console.log('ALL TESTS PASSED — TSK replica receiver verified');
  process.exit(0);   // explicit: a pending backoff setTimeout would otherwise keep node alive
}
