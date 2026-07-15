import {
  TSK_MAX_HOTP_COUNTER,
  generateTumblerMap,
  type TumblerMap,
} from './packages/core/src/index.ts';
import { MemoryTumblerStore } from './packages/server/src/store.ts';
import {
  REPLICATION_GENESIS_HASH,
  ReplicatingTumblerStore,
  computeReplicationHash,
  signReplicaEnvelope,
  type TumblerReplicaMutation,
  type TumblerReplicaOp,
} from './packages/server/src/replicating-tumbler-store.ts';
import {
  TumblerReplicaReceiver,
  validateTumblerOp,
} from './packages/server/src/replica-receiver.ts';

const TOKEN = 'replica-test-secret-32-bytes-minimum-value';
const NOW = 1_750_000_000_000;
const STREAM = 'receiver-stream';
const EPOCH = 3;
let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (error) { failed++; console.error(`  ✗ ${name}:`, error); }
}
function assert(condition: unknown, message: string) { if (!condition) throw new Error(message); }
function stripped(map: TumblerMap): TumblerMap { return { ...map, sharedSecret: '' }; }

function envelope(
  mutation: TumblerReplicaMutation,
  sequence: number,
  previousHash: string,
  overrides: Partial<Omit<TumblerReplicaOp, 'mutation' | 'signature'>> = {},
): TumblerReplicaOp {
  const base = {
    streamId: overrides.streamId ?? STREAM,
    epoch: overrides.epoch ?? EPOCH,
    sequence,
    previousHash,
    mutation,
  };
  const headHash = overrides.headHash ?? computeReplicationHash(base);
  return signReplicaEnvelope({ ...base, headHash, sentAt: overrides.sentAt ?? NOW }, TOKEN);
}

console.log('\nTSK replica receiver security suite');

await test('accepts one valid signed envelope but metadata-only state cannot qualify for promotion', async () => {
  const store = new MemoryTumblerStore();
  const receiver = new TumblerReplicaReceiver(store, TOKEN, { streamId: STREAM, epoch: EPOCH, now: () => NOW });
  const map = generateTumblerMap();
  const op = envelope({ op: 'set', clientId: map.clientId, map: stripped(map), secretSealed: false }, 1, REPLICATION_GENESIS_HASH);
  const result = await receiver.ingest(op);
  assert(result.status === 200, JSON.stringify(result));
  assert(receiver.getCheckpoint().headHash === op.headHash, 'checkpoint mismatch');
  assert(receiver.promotionCheckpoint() === null, 'metadata-only replica must not qualify');
});

await test('rejects forged signatures before mutation', async () => {
  const store = new MemoryTumblerStore();
  const receiver = new TumblerReplicaReceiver(store, TOKEN, { streamId: STREAM, epoch: EPOCH, now: () => NOW });
  const map = generateTumblerMap();
  const op = envelope({ op: 'set', clientId: map.clientId, map: stripped(map), secretSealed: false }, 1, REPLICATION_GENESIS_HASH);
  op.signature = `${op.signature.slice(0, -1)}${op.signature.endsWith('A') ? 'B' : 'A'}`;
  const result = await receiver.ingest(op);
  assert(result.status === 401, JSON.stringify(result));
  assert(await store.get(map.clientId) === null, 'forgery mutated store');
});

await test('rejects stale envelopes', async () => {
  const receiver = new TumblerReplicaReceiver(new MemoryTumblerStore(), TOKEN, { streamId: STREAM, epoch: EPOCH, now: () => NOW });
  const map = generateTumblerMap();
  const op = envelope({ op: 'set', clientId: map.clientId, map: stripped(map), secretSealed: false }, 1, REPLICATION_GENESIS_HASH, { sentAt: NOW - 60_001 });
  const result = await receiver.ingest(op);
  assert(result.status === 401 && result.result.error === 'envelope_stale', JSON.stringify(result));
});

await test('rejects replay and sequence gaps; a gap permanently blocks promotion', async () => {
  const receiver = new TumblerReplicaReceiver(new MemoryTumblerStore(), TOKEN, { streamId: STREAM, epoch: EPOCH, now: () => NOW });
  const map = generateTumblerMap();
  const first = envelope({ op: 'set', clientId: map.clientId, map: stripped(map), secretSealed: false }, 1, REPLICATION_GENESIS_HASH);
  assert((await receiver.ingest(first)).status === 200, 'first op failed');
  const replay = await receiver.ingest(first);
  assert(replay.status === 409 && replay.result.error === 'envelope_replay', JSON.stringify(replay));
  const gap = envelope({ op: 'delete', clientId: map.clientId }, 3, first.headHash);
  const gapResult = await receiver.ingest(gap);
  assert(gapResult.status === 409 && gapResult.result.error === 'sequence_gap', JSON.stringify(gapResult));
  assert(receiver.promotionCheckpoint() === null, 'gap must permanently disqualify receiver');
});

await test('strict map validation rejects malformed and raw-secret maps', () => {
  const map = generateTumblerMap();
  const rawSecret = envelope({ op: 'set', clientId: map.clientId, map, secretSealed: false }, 1, REPLICATION_GENESIS_HASH);
  assert(!validateTumblerOp(rawSecret).ok, 'raw secret accepted under unsealed marker');
  const malformed = envelope({
    op: 'set', clientId: map.clientId,
    map: { ...stripped(map), keyLength: -1 }, secretSealed: false,
  }, 1, REPLICATION_GENESIS_HASH);
  assert(!validateTumblerOp(malformed).ok, 'malformed map accepted');
});

await test('newer signed set cannot roll counters, usage, or terminal lifecycle backward', async () => {
  const store = new MemoryTumblerStore();
  const receiver = new TumblerReplicaReceiver(store, TOKEN, { streamId: STREAM, epoch: EPOCH, now: () => NOW });
  const map = generateTumblerMap();
  const hotp = map.segments.find(segment => segment.type === 'hotp')!;
  const current: TumblerMap = {
    ...stripped(map), status: 'revoked', requestCount: 5,
    segments: map.segments.map(segment => segment.segmentId === hotp.segmentId ? { ...segment, counter: 5 } : segment),
  };
  const first = envelope({ op: 'set', clientId: map.clientId, map: current, secretSealed: false }, 1, REPLICATION_GENESIS_HASH);
  assert((await receiver.ingest(first)).status === 200, 'initial state failed');
  const rollbackMap: TumblerMap = { ...stripped(map), status: 'active', requestCount: 1 };
  const second = envelope({ op: 'set', clientId: map.clientId, map: rollbackMap, secretSealed: false }, 2, first.headHash);
  const result = await receiver.ingest(second);
  assert(result.status === 409 && result.result.error === 'lifecycle_rollback', JSON.stringify(result));
  assert(receiver.promotionCheckpoint() === null, 'rollback attempt must disqualify receiver');
});

await test('exhausted MAX sentinel replicates as terminal and cannot roll back', async () => {
  const store = new MemoryTumblerStore();
  const receiver = new TumblerReplicaReceiver(store, TOKEN, {
    streamId: STREAM,
    epoch: EPOCH,
    now: () => NOW,
    secretUnsealer: (_clientId, sealed) => sealed.startsWith('sealed:') ? sealed.slice(7) : 'invalid',
    promotionDurability: () => true,
  });
  const source = generateTumblerMap();
  const exhausted: TumblerMap = {
    ...source,
    sharedSecret: `sealed:${source.sharedSecret}`,
    status: 'expired',
    segments: source.segments.map(segment => segment.type === 'hotp'
      ? { ...segment, counter: TSK_MAX_HOTP_COUNTER }
      : segment),
  };
  const first = envelope(
    { op: 'set', clientId: source.clientId, map: exhausted, secretSealed: true },
    1,
    REPLICATION_GENESIS_HASH,
  );
  const applied = await receiver.ingest(first);
  assert(applied.status === 200, JSON.stringify(applied));
  const stored = await store.get(source.clientId);
  assert(stored?.status === 'expired', JSON.stringify(stored));
  assert(stored?.segments.filter(segment => segment.type === 'hotp')
    .every(segment => segment.counter === TSK_MAX_HOTP_COUNTER), JSON.stringify(stored));

  const hotp = exhausted.segments.find(segment => segment.type === 'hotp')!;
  const rollback = envelope(
    {
      op: 'updateCounters',
      clientId: source.clientId,
      updates: [[hotp.segmentId, TSK_MAX_HOTP_COUNTER - 1]],
    },
    2,
    first.headHash,
  );
  const rejected = await receiver.ingest(rollback);
  assert(rejected.status === 409 && rejected.result.error === 'counter_rollback', JSON.stringify(rejected));
  assert(receiver.promotionCheckpoint() === null, 'rollback did not disqualify promotion');
});

await test('sealed state qualifies only after successful secret unsealing', async () => {
  const store = new MemoryTumblerStore();
  const receiver = new TumblerReplicaReceiver(store, TOKEN, {
    streamId: STREAM, epoch: EPOCH, now: () => NOW,
    secretUnsealer: (_clientId, sealed) => sealed.startsWith('sealed:') ? sealed.slice(7) : 'invalid',
    promotionDurability: () => true,
  });
  const map = generateTumblerMap();
  const sealedMap = { ...map, sharedSecret: `sealed:${map.sharedSecret}` };
  const op = envelope({ op: 'set', clientId: map.clientId, map: sealedMap, secretSealed: true }, 1, REPLICATION_GENESIS_HASH);
  const result = await receiver.ingest(op);
  assert(result.status === 200, JSON.stringify(result));
  assert(receiver.promotionCheckpoint()?.headHash === op.headHash, 'unsealed replica should qualify');
  assert((await store.get(map.clientId))?.sharedSecret === map.sharedSecret, 'replica did not store usable unsealed secret');
});

await test('unsealed state still cannot qualify without durable checkpoint evidence', async () => {
  const store = new MemoryTumblerStore();
  const receiver = new TumblerReplicaReceiver(store, TOKEN, {
    streamId: STREAM,
    epoch: EPOCH,
    now: () => NOW,
    secretUnsealer: (_clientId, sealed) => sealed.startsWith('sealed:') ? sealed.slice(7) : 'invalid',
  });
  const map = generateTumblerMap();
  const sealedMap = { ...map, sharedSecret: `sealed:${map.sharedSecret}` };
  const op = envelope(
    { op: 'set', clientId: map.clientId, map: sealedMap, secretSealed: true },
    1,
    REPLICATION_GENESIS_HASH,
  );
  assert((await receiver.ingest(op)).status === 200, 'valid sealed operation failed');
  assert(receiver.promotionCheckpoint() === null, 'volatile receiver checkpoint qualified for promotion');
});

await test('end-to-end sender and receiver converge on the same signed head', async () => {
  const replica = new MemoryTumblerStore();
  const receiver = new TumblerReplicaReceiver(replica, TOKEN, { streamId: STREAM, epoch: EPOCH, now: () => NOW });
  const fetchImpl = async (_url: string | URL | Request, init?: RequestInit) => {
    const result = await receiver.ingest(JSON.parse(String(init?.body)));
    return new Response('', { status: result.status });
  };
  const sender = new ReplicatingTumblerStore(new MemoryTumblerStore(), { url: 'https://replica.test', token: TOKEN }, {
    fetchImpl: fetchImpl as typeof fetch, streamId: STREAM, epoch: EPOCH, now: () => NOW,
    promotionDurability: () => true,
  });
  const map = generateTumblerMap();
  await sender.set(map.clientId, map);
  assert(await sender.flush(), 'sender did not flush');
  const source = sender.promotionCheckpoint();
  const applied = receiver.getCheckpoint();
  assert(Boolean(source && source.headHash === applied.headHash && source.sequence === applied.sequence), 'heads did not converge');
  assert((await replica.get(map.clientId))?.sharedSecret === '', 'raw secret reached replica');
  assert(receiver.promotionCheckpoint() === null, 'stripped replica must not qualify for authentication failover');
});

console.log(`\nTSK replica receiver suite: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
