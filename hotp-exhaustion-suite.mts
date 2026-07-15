import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  TSKHOTPCounterError,
  TSK_MAX_HOTP_COUNTER,
  generateKeyFromMap,
  generateTumblerMap,
  toProvisionPayload,
  validateTSKKey,
  type TumblerMap,
} from './packages/core/src/index.ts';
import {
  FileClientStorage,
  MemoryClientStorage,
  TSKClient,
} from './packages/client-sdk/src/index.ts';
import { FileTumblerStore } from './packages/server/src/file-store.ts';
import {
  buildTSKResponseHeaders,
  verifyTSKRequest,
} from './packages/server/src/middleware.ts';
import { TSKProvisioner } from './packages/server/src/provisioner.ts';
import { validateTumblerOp } from './packages/server/src/replica-receiver.ts';
import {
  MemoryTumblerStore,
  commitValidationToMap,
  reconcileTumblerMapCounterStatus,
} from './packages/server/src/store.ts';

const NOW = 1_750_000_000_000;
let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    passed++;
    console.log(`  OK ${name}`);
  } catch (error) {
    failed++;
    console.error(`  FAIL ${name}:`, error);
  }
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function allHOTPMap(counter: number, count = 3): TumblerMap {
  const map = generateTumblerMap({ keyLength: 64, minTumblers: count, maxTumblers: count });
  return {
    ...map,
    segments: map.segments.map(segment => segment.type === 'static'
      ? segment
      : { ...segment, type: 'hotp' as const, windowSec: undefined, counter }),
  };
}

function requestFor(map: TumblerMap, key: string) {
  return {
    headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': key,
      'x-tsk-version': '1',
    },
  };
}

console.log('\nTSK numeric HOTP exhaustion suite');

await test('wire v1 exports the documented project counter maximum', () => {
  assert(TSK_MAX_HOTP_COUNTER === 2_147_483_647, String(TSK_MAX_HOTP_COUNTER));
});

await test('counter-capacity response metadata is emitted only after success', () => {
  const headers = buildTSKResponseHeaders({
    ok: true,
    rotationRequired: true,
    hotpCountersRemaining: 17,
  });
  assert(headers['x-tsk-authenticated'] === '1', JSON.stringify(headers));
  assert(headers['x-tsk-rotation-required'] === '1', JSON.stringify(headers));
  assert(headers['x-tsk-hotp-counters-remaining'] === '17', JSON.stringify(headers));
  assert(Object.keys(buildTSKResponseHeaders({ ok: false })).length === 0, 'failure emitted headers');
});

await test('provisioner validates numeric warning configuration', async () => {
  const store = new MemoryTumblerStore();
  const provisioner = new TSKProvisioner(store);
  const invalid = await provisioner.provision({}, 'operator', {
    hotpRotationWarningCounters: TSK_MAX_HOTP_COUNTER + 1,
  });
  assert(!invalid.ok && invalid.error === 'INVALID_HOTP_ROTATION_WARNING_COUNTERS', JSON.stringify(invalid));
  assert((await store.list()).length === 0, 'invalid provision mutated store');
});

await test('warning starts exactly at configured numeric capacity', () => {
  const before = allHOTPMap(TSK_MAX_HOTP_COUNTER - 1_002);
  before.hotpRotationWarningCounters = 1_000;
  const beforeResult = commitValidationToMap(before, {
    counterMatches: before.segments
      .filter(segment => segment.type === 'hotp')
      .map(segment => ({ segmentId: segment.segmentId, matchedCounter: segment.counter! })),
    usedAt: NOW,
  });
  assert(beforeResult.ok && beforeResult.hotpCountersRemaining === 1_001, JSON.stringify(beforeResult));
  assert(beforeResult.rotationRequired === false, JSON.stringify(beforeResult));

  const boundary = allHOTPMap(TSK_MAX_HOTP_COUNTER - 1_001);
  boundary.hotpRotationWarningCounters = 1_000;
  const boundaryResult = commitValidationToMap(boundary, {
    counterMatches: boundary.segments
      .filter(segment => segment.type === 'hotp')
      .map(segment => ({ segmentId: segment.segmentId, matchedCounter: segment.counter! })),
    usedAt: NOW,
  });
  assert(boundaryResult.ok && boundaryResult.hotpCountersRemaining === 1_000, JSON.stringify(boundaryResult));
  assert(boundaryResult.rotationRequired === true && boundary.status === 'expiring', JSON.stringify(boundaryResult));
});

await test('segment closest to exhaustion governs rotation', () => {
  const map = allHOTPMap(0);
  const hotp = map.segments.filter(segment => segment.type === 'hotp');
  hotp[0].counter = TSK_MAX_HOTP_COUNTER - 2;
  const result = commitValidationToMap(map, {
    counterMatches: hotp.map(segment => ({ segmentId: segment.segmentId, matchedCounter: segment.counter! })),
    usedAt: NOW,
  });
  assert(result.ok && result.hotpCountersRemaining === 1, JSON.stringify(result));
  assert(result.rotationRequired === true && map.status === 'expiring', JSON.stringify(map));
});

await test('counter reconciliation never resurrects a terminal credential', async () => {
  const map = allHOTPMap(TSK_MAX_HOTP_COUNTER - 10);
  map.status = 'expired';
  reconcileTumblerMapCounterStatus(map, 10);
  assert(map.status === 'expired', 'direct reconciliation resurrected expired map');
  const revoked = { ...map, status: 'revoked' as const };
  reconcileTumblerMapCounterStatus(revoked, 10);
  assert(revoked.status === 'revoked', 'direct reconciliation resurrected revoked map');

  const store = new MemoryTumblerStore();
  await store.set(map.clientId, map);
  assert((await store.get(map.clientId))?.status === 'expired', 'expired map was reactivated');
});

await test('zero-HOTP maps fail before any lifecycle mutation', async () => {
  const generated = allHOTPMap(0);
  const malformed: TumblerMap = {
    ...generated,
    segments: generated.segments.map(segment => segment.type === 'static'
      ? segment
      : { ...segment, type: 'totp' as const, counter: undefined, windowSec: 60 }),
  };
  const result = commitValidationToMap(malformed, { counterMatches: [], usedAt: NOW });
  assert(!result.ok && result.error === 'TSK_HOTP_COUNTER_INVALID', JSON.stringify(result));
  assert(malformed.requestCount === undefined && malformed.lastUsedAt === undefined,
    'failed commit changed lifecycle state');
  await assertRejects(
    new MemoryTumblerStore().set(malformed.clientId, malformed),
    'store accepted zero-HOTP map',
  );
});

await test('last legal counter commits MAX sentinel and the next use is denied', async () => {
  const map = allHOTPMap(TSK_MAX_HOTP_COUNTER - 1);
  const key = generateKeyFromMap(map, NOW);
  const store = new MemoryTumblerStore();
  await store.set(map.clientId, map);

  const first = await verifyTSKRequest(requestFor(map, key), store);
  assert(first.ok, JSON.stringify(first));
  assert(first.rotationRequired === true && first.hotpCountersRemaining === 0, JSON.stringify(first));
  const committed = await store.get(map.clientId);
  assert(committed?.status === 'expired', JSON.stringify(committed));
  assert(
    committed.segments.filter(segment => segment.type === 'hotp')
      .every(segment => segment.counter === TSK_MAX_HOTP_COUNTER),
    JSON.stringify(committed),
  );

  const replay = await verifyTSKRequest(requestFor(map, key), store);
  assert(!replay.ok && replay.error === 'TSK_KEY_EXPIRED', JSON.stringify(replay));
});

await test('only one concurrent request can consume the final legal counter', async () => {
  const map = allHOTPMap(TSK_MAX_HOTP_COUNTER - 1);
  const key = generateKeyFromMap(map, NOW);
  const store = new MemoryTumblerStore();
  await store.set(map.clientId, map);
  const results = await Promise.all(
    Array.from({ length: 32 }, () => verifyTSKRequest(requestFor(map, key), store)),
  );
  assert(results.filter(result => result.ok).length === 1, JSON.stringify(results));
});

await test('lookahead is clipped before the exhausted sentinel', () => {
  const stale = allHOTPMap(TSK_MAX_HOTP_COUNTER - 3);
  const staleKey = generateKeyFromMap(stale, NOW);
  const server = {
    ...stale,
    segments: stale.segments.map(segment => segment.type === 'hotp'
      ? { ...segment, counter: TSK_MAX_HOTP_COUNTER - 2 }
      : segment),
  };
  const result = validateTSKKey(staleKey, {
    map: server,
    nowMs: NOW,
    config: { hotpLookahead: 100 },
  });
  assert(!result.ok && result.internalError === 'VALIDATION_FAILED', JSON.stringify(result));
});

await test('core generation rejects the exhausted sentinel with a typed error', () => {
  const exhausted = allHOTPMap(TSK_MAX_HOTP_COUNTER);
  let error: unknown;
  try { generateKeyFromMap(exhausted, NOW); } catch (caught) { error = caught; }
  assert(error instanceof TSKHOTPCounterError, String(error));
  assert(error.code === 'TSK_HOTP_COUNTER_EXHAUSTED', error.message);
});

await test('stores reject out-of-range and rollback counter updates atomically', async () => {
  const map = allHOTPMap(10);
  const store = new MemoryTumblerStore();
  await store.set(map.clientId, map);
  const invalidMap = allHOTPMap(TSK_MAX_HOTP_COUNTER + 1);
  await assertRejects(store.set(invalidMap.clientId, invalidMap), 'out-of-range map accepted');
  const inconsistent = allHOTPMap(TSK_MAX_HOTP_COUNTER);
  await assertRejects(store.set(inconsistent.clientId, inconsistent), 'active exhausted map accepted');
  const segmentId = map.segments.find(segment => segment.type === 'hotp')!.segmentId;
  await assertRejects(
    store.updateCounters(map.clientId, new Map([[segmentId, TSK_MAX_HOTP_COUNTER + 1]])),
    'out-of-range update accepted',
  );
  await assertRejects(
    store.updateCounters(map.clientId, new Map([[segmentId, 9]])),
    'counter rollback accepted',
  );
  assert((await store.get(map.clientId))?.segments.find(segment => segment.segmentId === segmentId)?.counter === 10,
    'failed update mutated stored state');
});

await test('atomic validation commit requires the complete HOTP counter vector', () => {
  const map = allHOTPMap(0);
  const hotp = map.segments.filter(segment => segment.type === 'hotp');
  const result = commitValidationToMap(map, {
    counterMatches: hotp.slice(1).map(segment => ({
      segmentId: segment.segmentId,
      matchedCounter: segment.counter ?? 0,
    })),
    usedAt: NOW,
  });
  assert(!result.ok && result.error === 'TSK_HOTP_COUNTER_INVALID', JSON.stringify(result));
  assert(map.requestCount === undefined, 'partial vector changed lifecycle state');
});

await test('file store refuses corrupt persisted counters above the v1 maximum', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'tsk-server-counter-'));
  try {
    const file = join(directory, 'maps.json');
    const map = allHOTPMap(TSK_MAX_HOTP_COUNTER + 1);
    await writeFile(file, JSON.stringify({ maps: { [map.clientId]: map }, lastAccess: {} }));
    let error: unknown;
    try { new FileTumblerStore(file); } catch (caught) { error = caught; }
    assert(error instanceof Error && error.message.startsWith('TSK_FILE_STORE_CORRUPT:'), String(error));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('client persists MAX sentinel then refuses any further generation', async () => {
  const map = allHOTPMap(TSK_MAX_HOTP_COUNTER - 1);
  const payload = toProvisionPayload(map);
  const storage = new MemoryClientStorage();
  await storage.save(payload);
  const client = new TSKClient({ clientId: map.clientId, storage, sharedSecret: map.sharedSecret });
  await client.init();
  const generated = client.generateHeaders(NOW);
  await generated.commitHOTPCounters();
  for (const segment of payload.clientSegments.filter(segment => segment.type === 'hotp')) {
    assert(await storage.loadCounter(map.clientId, segment.segmentId) === TSK_MAX_HOTP_COUNTER,
      `counter not committed for ${segment.segmentId}`);
  }
  let error: unknown;
  try { client.generateHeaders(NOW); } catch (caught) { error = caught; }
  assert(error instanceof TSKHOTPCounterError && error.code === 'TSK_HOTP_COUNTER_EXHAUSTED', String(error));
});

await test('client restart rejects corrupt persisted counter state', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'tsk-client-counter-'));
  try {
    const file = join(directory, 'client.json');
    const map = allHOTPMap(0);
    const payload = toProvisionPayload(map);
    const hotp = payload.clientSegments.find(segment => segment.type === 'hotp')!;
    await writeFile(file, JSON.stringify({
      version: 1,
      payloads: { [map.clientId]: payload },
      counters: { [`${map.clientId}:${hotp.segmentId}`]: TSK_MAX_HOTP_COUNTER + 1 },
    }));
    const client = new TSKClient({
      clientId: map.clientId,
      storage: new FileClientStorage(file),
      sharedSecret: map.sharedSecret,
    });
    await assertRejects(client.init(), 'client accepted corrupt persisted counter');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test('replica validation rejects maps and mutations beyond the v1 maximum', () => {
  const map = allHOTPMap(TSK_MAX_HOTP_COUNTER + 1);
  const stripped = { ...map, sharedSecret: '' };
  const base = {
    streamId: 'counter-boundary',
    epoch: 1,
    sequence: 1,
    previousHash: '0'.repeat(64),
    headHash: '1'.repeat(64),
    sentAt: NOW,
    signature: 'A'.repeat(43),
  };
  assert(!validateTumblerOp({
    ...base,
    mutation: { op: 'set', clientId: map.clientId, map: stripped, secretSealed: false },
  }).ok, 'replica accepted out-of-range map');
  assert(!validateTumblerOp({
    ...base,
    mutation: {
      op: 'updateCounters',
      clientId: map.clientId,
      updates: [[map.segments.find(segment => segment.type === 'hotp')!.segmentId, TSK_MAX_HOTP_COUNTER + 1]],
    },
  }).ok, 'replica accepted out-of-range update');
});

async function assertRejects(promise: Promise<unknown>, message: string): Promise<void> {
  let rejected = false;
  try { await promise; } catch { rejected = true; }
  assert(rejected, message);
}

console.log(`Numeric HOTP exhaustion suite: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
