import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  generateKeyFromClientPayload,
  generateTumblerMap,
  toProvisionPayload,
} from './packages/core/src/index.ts';
import {
  FileClientStorage,
  TSKClient,
  TSK_RESPONSE_HEADERS,
} from './packages/client-sdk/src/index.ts';

let passed = 0;
function assert(name: string, condition: boolean, detail = ''): void {
  if (!condition) throw new Error(`${name}: ${detail}`);
  passed++;
  console.log(`  ✓ ${name}`);
}

const directory = await mkdtemp(join(tmpdir(), 'tsk-client-lifecycle-'));
const file = join(directory, 'client.json');
const originalFetch = globalThis.fetch;

try {
  const map = generateTumblerMap({ keyLength: 64, minTumblers: 3, maxTumblers: 3 });
  const payload = toProvisionPayload(map);
  const hotpSegments = payload.clientSegments.filter(segment => segment.type === 'hotp');
  assert('generated map contains a counter-based segment', hotpSegments.length >= 1);

  const storage = new FileClientStorage(file);
  await storage.save(payload);
  const client = new TSKClient({ clientId: map.clientId, storage, sharedSecret: map.sharedSecret });
  await client.init();

  globalThis.fetch = async () => new Response('application failed', {
    status: 500,
    headers: { [TSK_RESPONSE_HEADERS.AUTHENTICATED]: '1' },
  });
  const applicationFailure = await client.fetch('https://example.test/work');
  assert('authenticated application failure is returned to caller', applicationFailure.status === 500);
  const persistedCounters = await Promise.all(
    hotpSegments.map(segment => storage.loadCounter(map.clientId, segment.segmentId)),
  );
  assert(
    'authenticated response persists every counter-based segment',
    persistedCounters.every(counter => counter === 1),
  );

  globalThis.fetch = async () => new Response('ok', { status: 200 });
  await client.fetch('https://example.test/missing-auth-confirmation');
  const unconfirmedCounters = await Promise.all(
    hotpSegments.map(segment => storage.loadCounter(map.clientId, segment.segmentId)),
  );
  assert(
    '2xx without authentication confirmation advances no counter-based segment',
    unconfirmedCounters.every(counter => counter === 1),
  );

  globalThis.fetch = async () => { throw new Error('network unavailable'); };
  let networkRejected = false;
  try {
    await client.fetch('https://example.test/network-error');
  } catch {
    networkRejected = true;
  }
  assert('network failure is surfaced', networkRejected);

  const restartedStorage = new FileClientStorage(file);
  const restarted = new TSKClient({
    clientId: map.clientId,
    storage: restartedStorage,
    sharedSecret: map.sharedSecret,
  });
  await restarted.init();
  const restartedHeaders = restarted.generateHeaders(1_750_000_000_000).headers;
  const counters = new Map(
    payload.clientSegments
      .filter(segment => segment.type === 'hotp')
      .map(segment => [segment.segmentId, 1]),
  );
  const expected = generateKeyFromClientPayload(map.sharedSecret, payload, counters, 1_750_000_000_000);
  assert('restart loads persisted counters and produces the expected next key', restartedHeaders['x-tsk-key'] === expected);

  console.log(`Client lifecycle suite: ${passed}/${passed} named cases passed`);
} finally {
  globalThis.fetch = originalFetch;
  await rm(directory, { recursive: true, force: true });
}
