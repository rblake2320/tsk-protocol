import { generateTumblerMap, type TumblerMap } from './packages/core/src/index.ts';
import { MemoryTumblerStore } from './packages/server/src/store.ts';
import {
  ReplicatingTumblerStore,
  verifyReplicaEnvelopeSignature,
  type TumblerReplicaOp,
} from './packages/server/src/replicating-tumbler-store.ts';

const TOKEN = 'replica-test-secret-32-bytes-minimum-value';
let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (error) { failed++; console.error(`  ✗ ${name}:`, error); }
}
function assert(condition: unknown, message: string) { if (!condition) throw new Error(message); }

function wireMap(map: TumblerMap): TumblerMap { return { ...map, sharedSecret: '' }; }

console.log('\nTSK authenticated replication stream suite');

await test('rejects weak replication tokens', () => {
  let threw = false;
  try { new ReplicatingTumblerStore(new MemoryTumblerStore(), { url: 'https://r.test', token: 'short' }); }
  catch { threw = true; }
  assert(threw, 'weak token must be rejected');
});

await test('emits signed, hash-linked, monotonic envelopes and strips raw secrets', async () => {
  const captured: TumblerReplicaOp[] = [];
  const fetchImpl = async (_url: string | URL | Request, init?: RequestInit) => {
    captured.push(JSON.parse(String(init?.body)) as TumblerReplicaOp);
    return new Response('', { status: 200 });
  };
  const store = new ReplicatingTumblerStore(
    new MemoryTumblerStore(),
    { url: 'https://r.test', token: TOKEN },
    {
      fetchImpl: fetchImpl as typeof fetch,
      streamId: 'stream-a',
      epoch: 7,
      promotionDurability: () => true,
    },
  );
  const first = generateTumblerMap();
  const second = generateTumblerMap();
  await store.set(first.clientId, first);
  await store.set(second.clientId, second);
  assert(await store.flush(), 'replication should flush');
  assert(captured.length === 2, 'two envelopes expected');
  assert(captured[0].sequence === 1 && captured[1].sequence === 2, 'sequence must be monotonic');
  assert(captured[1].previousHash === captured[0].headHash, 'hash chain must link');
  assert(captured.every(op => verifyReplicaEnvelopeSignature(op, TOKEN)), 'signatures must verify');
  assert(captured.every(op => op.mutation.op === 'set' && op.mutation.map.sharedSecret === ''), 'raw secret must be stripped');
  assert(store.promotionCheckpoint()?.headHash === captured[1].headHash, 'promotion checkpoint must equal replicated head');
});

await test('sealed-secret mode never transmits the raw secret', async () => {
  let captured: TumblerReplicaOp | undefined;
  const fetchImpl = async (_url: string | URL | Request, init?: RequestInit) => {
    captured = JSON.parse(String(init?.body)) as TumblerReplicaOp;
    return new Response('', { status: 200 });
  };
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(primary, { url: 'https://r.test', token: TOKEN }, {
    fetchImpl: fetchImpl as typeof fetch,
    secretPolicy: (_id, secret) => `sealed:${secret.slice(0, 8)}`,
  });
  const map = generateTumblerMap();
  await store.set(map.clientId, map);
  await store.flush();
  assert(store.promotionCheckpoint() === null, 'volatile source checkpoint must not qualify by default');
  assert(captured?.mutation.op === 'set', 'set envelope expected');
  if (captured?.mutation.op === 'set') {
    assert(captured.mutation.secretSealed, 'sealed marker expected');
    assert(captured.mutation.map.sharedSecret !== map.sharedSecret, 'raw secret leaked');
  }
});

await test('retry preserves the exact queue head and sequence', async () => {
  const sequences: number[] = [];
  let calls = 0;
  const fetchImpl = async (_url: string | URL | Request, init?: RequestInit) => {
    calls++;
    sequences.push((JSON.parse(String(init?.body)) as TumblerReplicaOp).sequence);
    return new Response('', { status: calls < 3 ? 503 : 200 });
  };
  const store = new ReplicatingTumblerStore(new MemoryTumblerStore(), { url: 'https://r.test', token: TOKEN }, {
    fetchImpl: fetchImpl as typeof fetch, backoffBaseMs: 1, backoffMaxMs: 1,
  });
  const map = generateTumblerMap();
  await store.set(map.clientId, map);
  assert(await store.flush(1000), 'retry should eventually flush');
  assert(sequences.join(',') === '1,1,1', `retry changed head: ${sequences}`);
});

await test('queue loss is permanent promotion disqualification and never shifts an in-flight successor', async () => {
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const sent: number[] = [];
  const dropped: string[] = [];
  const fetchImpl = async (_url: string | URL | Request, init?: RequestInit) => {
    sent.push((JSON.parse(String(init?.body)) as TumblerReplicaOp).sequence);
    await gate;
    return new Response('', { status: 200 });
  };
  const store = new ReplicatingTumblerStore(new MemoryTumblerStore(), { url: 'https://r.test', token: TOKEN }, {
    fetchImpl: fetchImpl as typeof fetch,
    maxQueue: 1,
    onDrop: mutation => dropped.push(mutation.op),
  });
  const a = generateTumblerMap();
  const b = generateTumblerMap();
  await store.set(a.clientId, a);
  await store.set(b.clientId, b); // cannot evict sequence 1 while it is in flight
  assert(store.replicationIntegrityLost, 'loss must be latched');
  assert(store.promotionCheckpoint() === null, 'lossy stream must not qualify');
  assert(dropped.length === 1, 'drop alarm required');
  release();
  await new Promise(resolve => setTimeout(resolve, 25));
  assert(sent.join(',') === '1', `unexpected operation acknowledged/sent: ${sent}`);
  assert(!(await store.flush(100)), 'flush must remain false after integrity loss');
});

await test('revocation is sequenced and promotion evidence is withheld until delivered', async () => {
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const fetchImpl = async () => { await gate; return new Response('', { status: 200 }); };
  const primary = new MemoryTumblerStore();
  const store = new ReplicatingTumblerStore(primary, { url: 'https://r.test', token: TOKEN }, {
    fetchImpl: fetchImpl as typeof fetch,
    promotionDurability: () => true,
  });
  const map = generateTumblerMap();
  await primary.set(map.clientId, wireMap(map));
  await store.delete(map.clientId);
  assert(store.promotionCheckpoint() === null, 'in-flight revocation must block promotion evidence');
  release();
  assert(await store.flush(), 'revocation should flush');
  assert(store.promotionCheckpoint()?.sequence === 1, 'delivered revocation should establish head');
});

console.log(`\nTSK replication stream suite: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
