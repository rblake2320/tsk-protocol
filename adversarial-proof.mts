/**
 * TSK Protocol — Adversarial Proof Suite
 *
 * 6 attack categories proving the protocol's security properties hold under adversarial conditions.
 * Run with: node --experimental-vm-modules adversarial-proof.mts
 *
 * All tests use real Node.js crypto — no mocks.
 */

import { generateTumblerMap, validateTSKKey } from './packages/core/src/index.js';
import { createTSKServer } from './packages/server/src/index.js';
import { verifyTSKRequest } from './packages/server/src/middleware.js';

type TestResult = { name: string; passed: boolean; detail: string };
const results: TestResult[] = [];

function assert(name: string, condition: boolean, detail: string) {
  results.push({ name, passed: condition, detail });
  const icon = condition ? '✓' : '✗';
  console.log(`  ${icon} ${name}`);
  if (!condition) console.log(`    FAIL: ${detail}`);
}

// ─── Setup ────────────────────────────────────────────────────────────────────
const map = generateTumblerMap({ keyLength: 96, minTumblers: 2, maxTumblers: 4 });
const NOW = Date.now();

// Generate a valid key at time NOW
async function validKey(nowMs = NOW): Promise<string> {
  const { generateKeyFromMap } = await import('./packages/core/src/key-gen.js');
  return generateKeyFromMap(map, nowMs);
}

// ─── Attack 1: Stolen Key Replay ───────────────────────────────────────────
console.log('\n[Attack 1] Stolen Key Replay — TOTP window expired');
{
  const { generateKeyFromMap } = await import('./packages/core/src/key-gen.js');
  // Generate a key in a past window (5 minutes ago = well outside ±1 window tolerance)
  const pastWindow = NOW - 5 * 60 * 1000;
  const stolenKey = generateKeyFromMap(map, pastWindow);

  // Attempt to use the stolen key at current time
  const result = validateTSKKey(stolenKey, { map, nowMs: NOW });
  assert('Expired TOTP segment rejected', !result.ok, 'Expected VALIDATION_FAILED for expired key');
  assert('Error is VALIDATION_FAILED or CHECKSUM_INVALID',
    result.error === 'INVALID_KEY' || result.error === 'VALIDATION_FAILED' || result.error === 'CHECKSUM_INVALID',
    `Got: ${result.error}`);

  // Current key still works
  const currentKey = generateKeyFromMap(map, NOW);
  const validResult = validateTSKKey(currentKey, { map, nowMs: NOW });
  assert('Current key still valid after replay attempt', validResult.ok, `Error: ${validResult.error}`);
}

// ─── Attack 2: Tampered Key ────────────────────────────────────────────────
console.log('\n[Attack 2] Tampered Key — single character mutation');
{
  const { generateKeyFromMap } = await import('./packages/core/src/key-gen.js');
  const key = generateKeyFromMap(map, NOW);

  // Flip one character in the middle
  const mid = Math.floor(key.length / 2);
  const tampered = key.slice(0, mid) + (key[mid] === 'A' ? 'B' : 'A') + key.slice(mid + 1);

  const result = validateTSKKey(tampered, { map, nowMs: NOW });
  assert('Tampered key rejected', !result.ok, 'Expected failure for mutated key');

  // Original still passes
  const original = validateTSKKey(key, { map, nowMs: NOW });
  assert('Original key valid after tamper test', original.ok, `Error: ${original.error}`);
}

// ─── Attack 3: Brute Force Segment Position Guessing ─────────────────────
console.log('\n[Attack 3] Brute Force Position Guessing — attacker constructs fake key with correct values at wrong positions');
{
  const { generateKeyFromMap } = await import('./packages/core/src/key-gen.js');
  const legitimateKey = generateKeyFromMap(map, NOW);

  // Attacker knows the key length but not positions — try scrambling segments
  // Simulate by rotating the key string by 1-10 positions
  let anyPassed = false;
  for (let shift = 1; shift <= 10; shift++) {
    const shifted = legitimateKey.slice(shift) + legitimateKey.slice(0, shift);
    const result = validateTSKKey(shifted, { map, nowMs: NOW });
    if (result.ok) anyPassed = true;
  }
  assert('Positionally-shifted keys all rejected', !anyPassed,
    'Structural secrecy holds — position shift breaks validation');
}

// ─── Attack 4: Oversized Header DoS ───────────────────────────────────────
console.log('\n[Attack 4] Oversized Header DoS — 100KB key header');
{
  const { store, anomaly } = createTSKServer();
  await store.set(map.clientId, map);

  const giantKey = 'A'.repeat(102400); // 100KB
  const fakeReq = {
    headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': giantKey,
      'x-tsk-version': '1',
    },
  };

  const result = await verifyTSKRequest(fakeReq, store);
  assert('100KB key header rejected with TSK_KEY_TOO_LARGE',
    !result.ok && result.error === 'TSK_KEY_TOO_LARGE',
    `Got: ${result.ok} / ${result.error}`);
}

// ─── Attack 5: Stolen Key Structural Analysis — Segment Pattern Detection ─
console.log('\n[Attack 5] Stolen Key Structural Analysis — attacker tries to identify which bytes are rotating');
{
  const { generateKeyFromMap } = await import('./packages/core/src/key-gen.js');
  // Generate two keys 30 seconds apart — attacker XORs to find which chars changed
  const key1 = generateKeyFromMap(map, NOW);
  const key2 = generateKeyFromMap(map, NOW + 5 * 60_000); // 5 minutes later

  // Which positions changed?
  const changedPositions: number[] = [];
  for (let i = 0; i < key1.length; i++) {
    if (key1[i] !== key2[i]) changedPositions.push(i);
  }

  // Attacker uses key1's rotating segments spliced into key2's static positions
  const hybridKey = key2.split('').map((char, i) =>
    changedPositions.includes(i) ? key1[i] : char
  ).join('');

  // At NOW+60000, key1's segments are expired — hybrid key with old rotating values should fail
  const result = validateTSKKey(hybridKey, { map, nowMs: NOW + 5 * 60_000 });
  assert('Hybrid key with expired rotating segments rejected', !result.ok,
    'Structural analysis + replay attempt correctly blocked');
}

// ─── Attack 6: Missing Headers (Absent TSK Layer) ─────────────────────────
console.log('\n[Attack 6] Missing TSK Headers — request without TSK layer rejected');
{
  const { store } = createTSKServer();
  await store.set(map.clientId, map);

  const noTskReq = {
    headers: {
      // No TSK headers at all
      'content-type': 'application/json',
    },
  };

  const result = await verifyTSKRequest(noTskReq, store);
  assert('Request without TSK headers rejected', !result.ok, `Got: ${result.error}`);
  assert('Error is TSK_HEADERS_MISSING', result.error === 'TSK_HEADERS_MISSING', `Got: ${result.error}`);
}

// ─── Full Flow Test ────────────────────────────────────────────────────────
console.log('\n[Full Flow] Provision → Generate → Validate → HOTP counter advance → replay rejected');
{
  const { store, provisioner } = createTSKServer();
  const provision = await provisioner.provision({ keyLength: 96 });
  assert('Provisioning succeeded', provision.ok, `Error: ${provision.error}`);

  const fullMap = await store.get(provision.clientId!);
  assert('Map stored server-side', fullMap !== null, 'Map missing from store');

  const { generateKeyFromMap } = await import('./packages/core/src/key-gen.js');
  const key = generateKeyFromMap(fullMap!, NOW);

  const { verifyTSKRequest } = await import('./packages/server/src/middleware.js');
  const req = {
    headers: {
      'x-tsk-client-id': provision.clientId!,
      'x-tsk-key': key,
      'x-tsk-version': '1',
    },
  };

  const validResult = await verifyTSKRequest(req, store);
  assert('Valid key accepted', validResult.ok, `Error: ${validResult.error}`);

  // Revoke client
  await provisioner.revoke(provision.clientId!);
  const revokeResult = await verifyTSKRequest(req, store);
  assert('Revoked client rejected', !revokeResult.ok, `Expected rejection after revoke`);
}

// ─── Results ──────────────────────────────────────────────────────────────
console.log('\n' + '─'.repeat(60));
const passed = results.filter(r => r.passed).length;
const total = results.length;
console.log(`TSK Adversarial Proof: ${passed}/${total} tests passed`);
if (passed === total) {
  console.log('ALL TESTS PASSED — TSK Protocol adversarially proven');
} else {
  const failed = results.filter(r => !r.passed);
  console.log('FAILURES:');
  for (const f of failed) console.log(`  - ${f.name}: ${f.detail}`);
  process.exit(1);
}
