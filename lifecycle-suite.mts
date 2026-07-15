/**
 * TSK Protocol — Server Lifecycle Suite
 *
 * Exercises real provisioned tumbler maps through the real server middleware:
 * expiry and max-request caps. No mocked validation path.
 *
 * Run: npx tsx lifecycle-suite.mts
 */

import { createTSKServer, MemoryTumblerStore, TSKProvisioner } from './packages/server/src/index.js';
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
  assert('last allowed use signals rotation with zero remaining', first.rotationRequired === true && first.requestsRemaining === 0, JSON.stringify(first));

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

console.log('\n[TSK Lifecycle] Pre-cap rotation signal');

{
  const { store, map } = await provisionWith({
    maxRequests: 10,
    rotationWarningRequests: 2,
    requestCount: 0,
  });

  let current = map;
  for (let use = 1; use <= 7; use++) {
    const result = await verifyTSKRequest(requestFor(current), store);
    assert(`use ${use} succeeds before warning window`, result.ok && result.rotationRequired === false, JSON.stringify(result));
    current = (await store.get(map.clientId)) ?? current;
  }

  const warning = await verifyTSKRequest(requestFor(current), store);
  assert(
    'rotation is required with two requests remaining',
    warning.ok && warning.rotationRequired === true && warning.requestsRemaining === 2,
    JSON.stringify(warning),
  );
  const expiring = await store.get(map.clientId);
  assert('credential state persists as expiring', expiring?.status === 'expiring', JSON.stringify(expiring));

  current = expiring ?? current;
  for (let remaining = 1; remaining >= 0; remaining--) {
    const result = await verifyTSKRequest(requestFor(current), store);
    assert(
      `authorized remaining request succeeds with remaining=${remaining}`,
      result.ok && result.rotationRequired === true && result.requestsRemaining === remaining,
      JSON.stringify(result),
    );
    current = (await store.get(map.clientId)) ?? current;
  }

  const denied = await verifyTSKRequest(requestFor(current), store);
  assert(
    'request after the hard cap is denied without grace',
    !denied.ok && denied.error === 'TSK_KEY_USAGE_CAP_EXCEEDED',
    JSON.stringify(denied),
  );
}

console.log('\n[TSK Lifecycle] Atomic concurrent cap');

{
  const { store, map } = await provisionWith({ maxRequests: 1, requestCount: 0 });
  const counterMatches = map.segments
    .filter(segment => segment.type === 'hotp')
    .map(segment => ({ segmentId: segment.segmentId, matchedCounter: segment.counter ?? 0 }));
  const concurrent = await Promise.all([
    store.commitValidation(map.clientId, { counterMatches, usedAt: Date.now() }),
    store.commitValidation(map.clientId, { counterMatches, usedAt: Date.now() }),
  ]);
  assert('exactly one concurrent request succeeds at maxRequests=1', concurrent.filter(result => result.ok).length === 1, JSON.stringify(concurrent));
  assert('the losing concurrent request is denied by the hard cap', concurrent.some(result => result.error === 'TSK_KEY_USAGE_CAP_EXCEEDED'), JSON.stringify(concurrent));
  const after = await store.get(map.clientId);
  assert('atomic cap records exactly one successful use', after?.requestCount === 1, JSON.stringify(after));
}

console.log('\n[TSK Lifecycle] Authorized atomic replacement');

{
  const disabledStore = new MemoryTumblerStore();
  const disabled = new TSKProvisioner(disabledStore);
  const original = await disabled.provision({}, 'operator', { maxRequests: 10 });
  const denied = await disabled.replaceKey(
    original.clientId!,
    {},
    { maxRequests: 20 },
    'operator',
    'pre-cap rotation',
  );
  assert('replacement fails closed when no authorizer is configured', !denied.ok && denied.error === 'REPLACEMENT_NOT_AUTHORIZED', JSON.stringify(denied));

  const store = new MemoryTumblerStore();
  const provisioner = new TSKProvisioner(store, {
    replacementAuthorizer: async request =>
      request.requestorId === 'authorized-operator' && request.reason === 'pre-cap rotation',
  });
  const provisioned = await provisioner.provision({}, 'authorized-operator', { maxRequests: 10 });
  const oldMap = provisioned.tumblerMap!;
  await store.set(oldMap.clientId, { ...oldMap, status: 'expiring', requestCount: 9 });

  const replacement = await provisioner.replaceKey(
    oldMap.clientId,
    {},
    { maxRequests: 100, rotationWarningRequests: 10 },
    'authorized-operator',
    'pre-cap rotation',
  );
  assert('authorized replacement returns a new credential', replacement.ok && replacement.clientId !== oldMap.clientId, JSON.stringify(replacement));
  const revoked = await store.get(oldMap.clientId);
  const active = await store.get(replacement.clientId!);
  assert('old credential is retained as revoked', revoked?.status === 'revoked', JSON.stringify(revoked));
  assert('replacement credential is active with reset usage', active?.status === 'active' && active.requestCount === 0, JSON.stringify(active));
  const oldAttempt = await verifyTSKRequest(requestFor(oldMap), store);
  assert('old credential is denied after replacement', !oldAttempt.ok && oldAttempt.error === 'TSK_KEY_REVOKED', JSON.stringify(oldAttempt));
  const newAttempt = await verifyTSKRequest(requestFor(active!), store);
  assert('replacement credential validates', newAttempt.ok, JSON.stringify(newAttempt));
}

console.log('\n[TSK Lifecycle] Authorized mutation boundary');

{
  const deniedStore = new MemoryTumblerStore();
  const deniedProvisioner = new TSKProvisioner(deniedStore);
  const deniedKey = await deniedProvisioner.provision({}, 'operator', { maxRequests: 10 });
  assert('revoke fails closed without lifecycle authorizer', !await deniedProvisioner.revoke(deniedKey.clientId!, 'operator', 'test revoke'));
  assert('update fails closed without lifecycle authorizer', !await deniedProvisioner.updateKey(deniedKey.clientId!, { maxRequests: null }, 'operator', 'test update'));

  const store = new MemoryTumblerStore();
  const provisioner = new TSKProvisioner(store, {
    lifecycleAuthorizer: async request => request.requestorId === 'authorized-operator',
  });
  const provisioned = await provisioner.provision({}, 'authorized-operator', { maxRequests: 10 });
  const expired = await provisioner.updateKey(
    provisioned.clientId!,
    { status: 'expired' },
    'authorized-operator',
    'operator expiry',
  );
  assert('authorized operator can expire an active credential', expired);
  const reactivated = await provisioner.updateKey(
    provisioned.clientId!,
    { status: 'active', maxRequests: null },
    'authorized-operator',
    'attempted reactivation',
  );
  assert('expired credential cannot be reactivated through metadata update', !reactivated);
}

const failed = results.filter(r => !r.passed);
console.log('\n' + '─'.repeat(60));
console.log(`TSK Lifecycle Suite: ${results.length - failed.length}/${results.length} passed`);
if (failed.length > 0) {
  for (const f of failed) console.log(`  ✗ ${f.name}: ${f.detail}`);
  process.exit(1);
}
console.log('Named TSK lifecycle cases passed');
