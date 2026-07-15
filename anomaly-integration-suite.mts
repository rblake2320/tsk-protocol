import { generateKeyFromMap, generateTumblerMap } from './packages/core/src/index.ts';
import { MemoryAnomalyEngine } from './packages/server/src/anomaly.ts';
import { verifyTSKRequest } from './packages/server/src/middleware.ts';
import { MemoryTumblerStore } from './packages/server/src/store.ts';

let passed = 0;
let failed = 0;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function test(name: string, fn: () => Promise<void> | void): Promise<void> {
  try { await fn(); passed++; console.log(`  PASS ${name}`); }
  catch (error) { failed++; console.error(`  FAIL ${name}:`, error); }
}

console.log('\nTSK anomaly integration suite');

await test('repeated checksum forgeries reach the real anomaly score', async () => {
  const store = new MemoryTumblerStore();
  const anomaly = new MemoryAnomalyEngine();
  const map = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  await store.set(map.clientId, map);
  const valid = generateKeyFromMap(map);
  const forged = valid.slice(0, -1) + (valid.endsWith('A') ? 'B' : 'A');
  for (let attempt = 0; attempt < 3; attempt++) {
    const result = await verifyTSKRequest({ headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': forged,
      'x-tsk-version': '1',
    } }, store, { anomaly, ipAddress: '127.0.0.1' });
    assert(!result.ok, 'checksum forgery was accepted');
  }
  const score = anomaly.score(map.clientId);
  assert(score.score >= 30, `checksum failures were not scored: ${JSON.stringify(score)}`);
  assert(score.verdict === 'suspicious' || score.verdict === 'attack', `unexpected verdict: ${score.verdict}`);
  assert(score.reasons.some(reason => reason.includes('integrity/segment')), 'checksum reason missing');
});

await test('one checksum failure is telemetry but remains below threshold', async () => {
  const store = new MemoryTumblerStore();
  const anomaly = new MemoryAnomalyEngine();
  const map = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  await store.set(map.clientId, map);
  const valid = generateKeyFromMap(map);
  const forged = valid.slice(0, -1) + (valid.endsWith('A') ? 'B' : 'A');
  await verifyTSKRequest({ headers: {
    'x-tsk-client-id': map.clientId,
    'x-tsk-key': forged,
    'x-tsk-version': '1',
  } }, store, { anomaly });
  const score = anomaly.score(map.clientId);
  assert(score.score === 0 && score.verdict === 'clean', JSON.stringify(score));
  assert(anomaly.trackedClients === 1, 'single failure was not retained as telemetry');
});

await test('empty legacy event is not misclassified as total segment failure', () => {
  const anomaly = new MemoryAnomalyEngine();
  for (let index = 0; index < 3; index++) {
    anomaly.record({ clientId: 'legacy', timestamp: Date.now(), segmentResults: [] });
  }
  const score = anomaly.score('legacy');
  assert(!score.reasons.some(reason => reason.includes('integrity/segment')), JSON.stringify(score));
});

console.log(`TSK anomaly integration: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
