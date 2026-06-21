/**
 * TSK Protocol — Server Lifecycle Suite
 *
 * Exercises real provisioned tumbler maps through the real server middleware:
 * expiry and max-request caps. No mocked validation path.
 *
 * Run: npx tsx lifecycle-suite.mts
 */

import { createTSKServer } from './packages/server/src/index.js';
import { verifyTSKRequest } from './packages/server/src/middleware.js';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import type { TumblerMap } from './packages/core/src/types.js';

type TestResult = { name: string; passed: boolean; detail: string };
const results: TestResult[] = [];

function assert(name: string, condition: boolean, detail = '') {
  results.push({ name, passed: condition, detail });
  console.log(`  ${condition ? '✓' : '✗'} ${name}`);
  if (!condition) console.log(`    FAIL: ${detail}`);
}

function requestFor(map: TumblerMap) {
  return {
    headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': generateKeyFromMap(map),
      'x-tsk-version': '1',
    },
  };
}

async function provisionWith(fields: Partial<TumblerMap> = {}) {
  const { store, provisioner } = createTSKServer();
  const provisioned = await provisioner.provision({ keyLength: 52, minTumblers: 2, maxTumblers: 3 });
  if (!provisioned.ok || !provisioned.tumblerMap) {
    throw new Error(`provision failed: ${provisioned.error ?? 'unknown'}`);
  }
  const map: TumblerMap = { ...provisioned.tumblerMap, ...fields };
  await store.set(map.clientId, map);
  return { store, map };
}

console.log('\n[TSK Lifecycle] Expiry');

{
  const { store, map } = await provisionWith({ expiresAt: Date.now() - 1000 });
  const expiredResult = await verifyTSKRequest(requestFor(map), store);
  assert(
    'expired credential is denied before validation',
    !expiredResult.ok && expiredResult.error === 'TSK_KEY_EXPIRED',
    JSON.stringify(expiredResult),
  );
  const afterExpired = await store.get(map.clientId);
  assert('expired credential is persisted as expired', afterExpired?.status === 'expired', JSON.stringify(afterExpired));
}

console.log('\n[TSK Lifecycle] Max-requests cap');

{
  const { store, map } = await provisionWith({ maxRequests: 1, requestCount: 0 });
  const first = await verifyTSKRequest(requestFor(map), store);
  assert('first use under maxRequests=1 succeeds', first.ok, String(first.error));

  const afterFirst = await store.get(map.clientId);
  assert('requestCount increments after successful validation', afterFirst?.requestCount === 1, JSON.stringify(afterFirst));

  const second = await verifyTSKRequest(requestFor(afterFirst ?? map), store);
  assert(
    'second use under maxRequests=1 is denied',
    !second.ok && second.error === 'TSK_KEY_USAGE_CAP_EXCEEDED',
    JSON.stringify(second),
  );
  const afterCap = await store.get(map.clientId);
  assert('usage-capped credential is persisted as expired', afterCap?.status === 'expired', JSON.stringify(afterCap));
}

const failed = results.filter(r => !r.passed);
console.log('\n' + '─'.repeat(60));
console.log(`TSK Lifecycle Suite: ${results.length - failed.length}/${results.length} passed`);
if (failed.length > 0) {
  for (const f of failed) console.log(`  ✗ ${f.name}: ${f.detail}`);
  process.exit(1);
}
console.log('ALL TESTS PASSED — TSK lifecycle gates verified');
