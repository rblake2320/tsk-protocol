/**
 * RED TEAM FUZZING SUITE — tsk-protocol
 * Adversarial inputs, boundary conditions, type confusion, malformed data
 * Written by external red team — NOT the protocol authors
 */
import { randomBytes } from 'node:crypto';
import { createTSKServer } from './packages/server/src/index.js';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import { validateTSKKey } from './packages/core/src/validate.js';
import { generateTumblerMap } from './packages/core/src/tumbler-map.js';
import { hmac } from './packages/core/src/crypto.js';
import type { TumblerMap } from './packages/core/src/types.js';

// ─── Harness ──────────────────────────────────────────────────────────────────
let passed = 0; let failed = 0; let warnings = 0;
const findings: { sev: string; name: string; detail: string }[] = [];

function test(name: string, fn: () => void | Promise<void>) {
  return Promise.resolve().then(fn).then(() => {
    passed++;
    console.log(`  ✓ ${name}`);
  }).catch((e: any) => {
    failed++;
    const msg = e?.message ?? String(e);
    findings.push({ sev: 'FAIL', name, detail: msg });
    console.log(`  ✗ ${name}: ${msg}`);
  });
}

function warn(name: string, detail: string) {
  warnings++;
  findings.push({ sev: 'WARN', name, detail });
  console.log(`  ⚠ ${name}: ${detail}`);
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

// ─── Setup ────────────────────────────────────────────────────────────────────
const { store, provisioner, anomaly } = createTSKServer();
const prov = await provisioner.provision({ keyLength: 52, minTumblers: 2, maxTumblers: 4 });
if (!prov.ok || !prov.tumblerMap) { console.error('FATAL: provision failed'); process.exit(1); }
const map = prov.tumblerMap!;
const NOW = Date.now();
const validKey = generateKeyFromMap(map, NOW);

// ─── FUZZ GROUP 1: Header Injection & Null Bytes ──────────────────────────────
console.log('\n[FUZZ-1] Header Injection & Null Bytes');

await test('Null byte in client-id header', async () => {
  const r = await store.get('tsk_\x00evil');
  assert(r === null, 'Null-byte client ID should not match any stored map');
});

await test('Null byte injected into key string', () => {
  const poisoned = validKey.slice(0, 10) + '\x00' + validKey.slice(11);
  const r = validateTSKKey(poisoned, { map, nowMs: NOW });
  assert(!r.ok, 'Key with null byte should be rejected');
});

await test('Unicode in key (emoji injection)', () => {
  const poisoned = '🔥'.repeat(13); // 52 chars visually but multi-byte
  const r = validateTSKKey(poisoned, { map, nowMs: NOW });
  assert(!r.ok, 'Emoji key should be rejected');
});

await test('Unicode combining characters (length spoofing)', () => {
  // Combining chars make string look shorter but are valid JS chars
  const combining = '\u0300\u0301\u0302'; // 3 combining accent chars
  const poisoned = validKey.slice(0, 49) + combining;
  const r = validateTSKKey(poisoned, { map, nowMs: NOW });
  assert(!r.ok, 'Combining-char key should be rejected');
});

await test('Key with only whitespace', () => {
  const r = validateTSKKey(' '.repeat(52), { map, nowMs: NOW });
  assert(!r.ok, 'Whitespace key rejected');
});

await test('Key with tab/newline/CRLF characters', () => {
  const poisoned = '\t'.repeat(26) + '\n'.repeat(26);
  const r = validateTSKKey(poisoned, { map, nowMs: NOW });
  assert(!r.ok, 'CRLF key rejected');
});

await test('Key with SQL injection payload', () => {
  const sqli = "' OR '1'='1"; // 11 chars, pad to 52
  const padded = sqli + 'A'.repeat(52 - sqli.length);
  const r = validateTSKKey(padded, { map, nowMs: NOW });
  assert(!r.ok, 'SQL injection key rejected');
});

await test('Key with path traversal payload', () => {
  const traversal = '../../../etc/passwd'.padEnd(52, 'A').slice(0, 52);
  const r = validateTSKKey(traversal, { map, nowMs: NOW });
  assert(!r.ok, 'Path traversal key rejected');
});

await test('Key with XSS payload', () => {
  const xss = '<script>alert(1)</script>'.padEnd(52, 'A').slice(0, 52);
  const r = validateTSKKey(xss, { map, nowMs: NOW });
  assert(!r.ok, 'XSS payload key rejected');
});

await test('Empty string key', () => {
  const r = validateTSKKey('', { map, nowMs: NOW });
  assert(!r.ok, 'Empty key rejected');
});

await test('Single char key', () => {
  const r = validateTSKKey('A', { map, nowMs: NOW });
  assert(!r.ok, 'Single-char key rejected');
});

await test('Key of length maxKeyLength+1 (257 chars)', () => {
  const r = validateTSKKey('A'.repeat(257), { map, nowMs: NOW });
  assert(!r.ok, 'Over-max-length key rejected');
});

await test('Key of length minKeyLength-1 (15 chars)', () => {
  const r = validateTSKKey('A'.repeat(15), { map, nowMs: NOW });
  assert(!r.ok, 'Under-min-length key rejected');
});

await test('Key of exactly minKeyLength (16 chars) with wrong map', () => {
  // map.keyLength is 52, so 16-char key should fail length check
  const r = validateTSKKey('A'.repeat(16), { map, nowMs: NOW });
  assert(!r.ok, '16-char key against 52-char map rejected');
});

// ─── FUZZ GROUP 2: Boundary Conditions ────────────────────────────────────────
console.log('\n[FUZZ-2] Boundary Conditions');

await test('Key at exact TOTP window boundary (T=0)', () => {
  // T=0 means time=0, which is a valid but extreme boundary
  const r = validateTSKKey(generateKeyFromMap(map, 0), { map, nowMs: 0 });
  assert(r.ok, 'Key at T=0 should be valid');
});

await test('Key generated at far future time (year 2100)', () => {
  const future = new Date('2100-01-01').getTime();
  const futureKey = generateKeyFromMap(map, future);
  const r = validateTSKKey(futureKey, { map, nowMs: future });
  assert(r.ok, 'Far-future key valid at its own time');
  const rNow = validateTSKKey(futureKey, { map, nowMs: NOW });
  assert(!rNow.ok, 'Far-future key invalid at current time');
});

await test('Key generated at negative timestamp', () => {
  // Negative timestamps are technically valid JS Dates
  const negTime = -1000000;
  const negKey = generateKeyFromMap(map, negTime);
  const r = validateTSKKey(negKey, { map, nowMs: negTime });
  // Should work (HMAC is deterministic for any input)
  assert(r.ok, 'Negative timestamp key valid at same negative time');
  const rNow = validateTSKKey(negKey, { map, nowMs: NOW });
  assert(!rNow.ok, 'Negative timestamp key invalid at current time');
});

await test('nowMs = NaN (corrupted time)', () => {
  try {
    const r = validateTSKKey(validKey, { map, nowMs: NaN });
    // NaN in TOTP: Math.floor(NaN/1000/60) = NaN, T+delta = NaN
    // HMAC(secret, "totp:seg:NaN") will produce a value, but won't match valid key
    // This should not throw, just return ok:false
    assert(!r.ok || r.ok, 'NaN time does not crash the validator'); // just checking no throw
    if (r.ok) {
      warn('NaN timestamp accepted', 'validateTSKKey accepted NaN as nowMs — potential logic flaw');
    }
  } catch (e: any) {
    throw new Error(`NaN timestamp caused crash: ${e.message}`);
  }
});

await test('nowMs = Infinity', () => {
  try {
    const r = validateTSKKey(validKey, { map, nowMs: Infinity });
    assert(!r.ok || r.ok, 'Infinity time does not crash');
    if (r.ok) {
      warn('Infinity timestamp accepted', 'validateTSKKey accepted Infinity as nowMs');
    }
  } catch (e: any) {
    throw new Error(`Infinity timestamp caused crash: ${e.message}`);
  }
});

await test('nowMs = -Infinity', () => {
  try {
    const r = validateTSKKey(validKey, { map, nowMs: -Infinity });
    assert(!r.ok || r.ok, '-Infinity time does not crash');
  } catch (e: any) {
    throw new Error(`-Infinity timestamp caused crash: ${e.message}`);
  }
});

// ─── FUZZ GROUP 3: Malformed TumblerMap Structures ────────────────────────────
console.log('\n[FUZZ-3] Malformed TumblerMap Structures');

await test('Map with overlapping segment positions', () => {
  const badMap: TumblerMap = {
    ...map,
    segments: [
      { segmentId: 'id_aaa', position: [0, 20], type: 'static' },
      { segmentId: 'seg_bbb', position: [10, 30], type: 'totp', windowSec: 30 }, // overlaps!
    ],
    checksum: { position: [44, 52] },
    keyLength: 52,
  };
  try {
    const key = generateKeyFromMap(badMap, NOW);
    const r = validateTSKKey(key, { map: badMap, nowMs: NOW });
    // Overlapping positions mean segment values overwrite each other
    // This is a structural integrity issue — should ideally be caught
    if (r.ok) {
      warn('Overlapping segments accepted', `Map with overlapping positions [0,20] and [10,30] produced a valid key — no overlap detection`);
    }
  } catch (e: any) {
    // Throwing is acceptable here
  }
});

await test('Map with zero-length segment', () => {
  const badMap: TumblerMap = {
    ...map,
    segments: [
      { segmentId: 'id_zero', position: [0, 0], type: 'static' }, // zero length!
      ...map.segments.slice(1),
    ],
  };
  try {
    const key = generateKeyFromMap(badMap, NOW);
    const r = validateTSKKey(key, { map: badMap, nowMs: NOW });
    if (r.ok) {
      warn('Zero-length segment accepted', 'Map with zero-length segment position [0,0] was accepted');
    }
  } catch (e: any) {
    // Expected to fail
  }
});

await test('Map with checksum position beyond keyLength', () => {
  const badMap: TumblerMap = {
    ...map,
    checksum: { position: [60, 68] }, // beyond keyLength=52!
  };
  try {
    const key = generateKeyFromMap(badMap, NOW);
    const r = validateTSKKey(key, { map: badMap, nowMs: NOW });
    if (r.ok) {
      warn('Out-of-bounds checksum accepted', 'Checksum position beyond keyLength was accepted');
    }
  } catch (e: any) {
    // Expected
  }
});

await test('Map with empty segments array', () => {
  const badMap: TumblerMap = {
    ...map,
    segments: [],
  };
  try {
    const key = generateKeyFromMap(badMap, NOW);
    const r = validateTSKKey(key, { map: badMap, nowMs: NOW });
    // With no segments, only checksum is checked — this might pass!
    if (r.ok) {
      warn('Empty segments map accepted', 'A map with NO segments passed validation — only checksum checked. Any key with correct checksum passes!');
    }
  } catch (e: any) {
    // OK
  }
});

await test('Map with negative segment positions', () => {
  const badMap: TumblerMap = {
    ...map,
    segments: [
      { segmentId: 'id_neg', position: [-5, 10], type: 'static' },
    ],
  };
  try {
    const key = generateKeyFromMap(badMap, NOW);
    const r = validateTSKKey(key, { map: badMap, nowMs: NOW });
    if (r.ok) {
      warn('Negative position accepted', 'Segment with negative start position was accepted');
    }
  } catch (e: any) {
    // OK
  }
});

await test('Map with duplicate segmentIds', () => {
  const badMap: TumblerMap = {
    ...map,
    segments: [
      { segmentId: 'SAME_ID', position: [0, 10], type: 'static' },
      { segmentId: 'SAME_ID', position: [10, 20], type: 'totp', windowSec: 30 },
    ],
    checksum: { position: [44, 52] },
  };
  try {
    const key = generateKeyFromMap(badMap, NOW);
    const r = validateTSKKey(key, { map: badMap, nowMs: NOW });
    if (r.ok) {
      warn('Duplicate segmentId accepted', 'Map with duplicate segmentIds was accepted — anomaly engine uses segmentId prefix for stolen-key detection, duplicates could confuse it');
    }
  } catch (e: any) {
    // OK
  }
});

await test('Map with HOTP counter = undefined (missing counter)', () => {
  const badMap: TumblerMap = {
    ...map,
    segments: map.segments.map(s => s.type === 'hotp' ? { ...s, counter: undefined } : s),
  };
  // counter ?? 0 fallback should handle this, but let's verify
  const key = generateKeyFromMap(badMap, NOW);
  const r = validateTSKKey(key, { map: badMap, nowMs: NOW });
  // Should work due to ?? 0 fallback
  assert(r.ok || !r.ok, 'Undefined counter handled without crash');
});

await test('Map with HOTP counter = Number.MAX_SAFE_INTEGER', () => {
  const bigMap: TumblerMap = {
    ...map,
    segments: map.segments.map(s => s.type === 'hotp' ? { ...s, counter: Number.MAX_SAFE_INTEGER } : s),
  };
  try {
    const key = generateKeyFromMap(bigMap, NOW);
    const r = validateTSKKey(key, { map: bigMap, nowMs: NOW });
    // MAX_SAFE_INTEGER + 1 = MAX_SAFE_INTEGER (precision loss) — potential counter wrap
    if (r.ok) {
      warn('MAX_SAFE_INTEGER counter', 'HOTP counter at MAX_SAFE_INTEGER validated — counter increment may lose precision');
    }
  } catch (e: any) {
    throw new Error(`MAX_SAFE_INTEGER counter crashed: ${e.message}`);
  }
});

// ─── FUZZ GROUP 4: Provisioner Abuse ──────────────────────────────────────────
console.log('\n[FUZZ-4] Provisioner Abuse');

await test('Provision with keyLength=0', async () => {
  try {
    const r = await provisioner.provision({ keyLength: 0 });
    if (r.ok) {
      warn('keyLength=0 accepted', 'Provisioner accepted keyLength=0 — should reject');
    }
  } catch (e: any) {
    // Expected to throw
  }
});

await test('Provision with keyLength=1', async () => {
  try {
    const r = await provisioner.provision({ keyLength: 1 });
    if (r.ok) {
      warn('keyLength=1 accepted', 'Provisioner accepted keyLength=1 — too small for any segments');
    }
  } catch (e: any) {
    // Expected
  }
});

await test('Provision with minTumblers > maxTumblers', async () => {
  try {
    const r = await provisioner.provision({ minTumblers: 10, maxTumblers: 2 });
    if (r.ok) {
      warn('minTumblers > maxTumblers accepted', 'Provisioner accepted inverted tumbler bounds');
    }
  } catch (e: any) {
    // Expected
  }
});

await test('Provision with minTumblers=0', async () => {
  try {
    const r = await provisioner.provision({ minTumblers: 0, maxTumblers: 0 });
    if (r.ok) {
      warn('minTumblers=0 accepted', 'Provisioner accepted 0 tumblers — map has no rotating segments');
    }
  } catch (e: any) {
    // Expected
  }
});

await test('Provision with negative keyLength', async () => {
  try {
    const r = await provisioner.provision({ keyLength: -100 });
    if (r.ok) {
      warn('Negative keyLength accepted', 'Provisioner accepted negative keyLength');
    }
  } catch (e: any) {
    // Expected
  }
});

await test('Provision with extremely large keyLength (100000)', async () => {
  try {
    const start = Date.now();
    const r = await provisioner.provision({ keyLength: 100000 });
    const elapsed = Date.now() - start;
    if (r.ok) {
      warn('keyLength=100000 accepted', `Provisioner accepted 100KB key length in ${elapsed}ms — potential DoS vector`);
    }
  } catch (e: any) {
    // Expected
  }
});

await test('Provision with allowedWindows containing 0', async () => {
  try {
    const r = await provisioner.provision({ allowedWindows: [0] });
    if (r.ok && r.tumblerMap) {
      // windowSec=0 means T = floor(nowMs/1000/0) = Infinity or NaN
      warn('windowSec=0 accepted', 'Provisioner accepted TOTP window of 0 seconds — division by zero in T calculation');
    }
  } catch (e: any) {
    // Expected
  }
});

await test('Provision with allowedWindows containing negative value', async () => {
  try {
    const r = await provisioner.provision({ allowedWindows: [-30] });
    if (r.ok) {
      warn('Negative windowSec accepted', 'Provisioner accepted negative TOTP window');
    }
  } catch (e: any) {
    // Expected
  }
});

// ─── FUZZ GROUP 5: Store Abuse ─────────────────────────────────────────────────
console.log('\n[FUZZ-5] Store Abuse');

await test('Store.get with empty string clientId', async () => {
  const r = await store.get('');
  assert(r === null, 'Empty clientId returns null');
});

await test('Store.get with very long clientId (10KB)', async () => {
  const r = await store.get('A'.repeat(10000));
  assert(r === null, 'Very long clientId returns null without crash');
});

await test('Store.get with special chars in clientId', async () => {
  const r = await store.get('../../../etc/passwd');
  assert(r === null, 'Path traversal clientId returns null');
});

await test('Store.updateCounters with non-existent clientId', async () => {
  try {
    await store.updateCounters('nonexistent_client', new Map([['seg_x', 99]]));
    // Should silently succeed (no-op)
  } catch (e: any) {
    throw new Error(`updateCounters with missing client crashed: ${e.message}`);
  }
});

await test('Store.consumeCounter with wrong expectedCounter', async () => {
  const result = await store.consumeCounter!(map.clientId, 'nonexistent_seg', 9999);
  assert(result === false, 'consumeCounter with wrong counter returns false');
});

await test('Store.consumeCounter with non-existent clientId', async () => {
  const result = await store.consumeCounter!('ghost_client', 'seg_x', 0);
  assert(result === false, 'consumeCounter with ghost client returns false');
});

// ─── FUZZ GROUP 6: verifyTSKRequest Header Fuzzing ────────────────────────────
console.log('\n[FUZZ-6] verifyTSKRequest Header Fuzzing');
import { verifyTSKRequest } from './packages/server/src/middleware.js';

await test('Array-valued x-tsk-key header (HTTP header injection)', async () => {
  const r = await verifyTSKRequest({
    headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': [validKey, 'evil_second_value'] as any,
      'x-tsk-version': '1',
    }
  }, store);
  // getHeader takes first element of array — this should still work
  assert(r.ok || !r.ok, 'Array header handled without crash');
  if (r.ok) {
    // This is actually fine — it takes first element
  }
});

await test('x-tsk-version set to unsupported value "2"', async () => {
  const r = await verifyTSKRequest({
    headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': validKey,
      'x-tsk-version': '2',
    }
  }, store);
  assert(!r.ok, 'Version 2 rejected');
  assert(r.error === 'TSK_VERSION_UNSUPPORTED', `Expected TSK_VERSION_UNSUPPORTED, got ${r.error}`);
});

await test('x-tsk-version set to empty string', async () => {
  // Empty version should be treated as absent (no version check)
  const r = await verifyTSKRequest({
    headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': validKey,
      'x-tsk-version': '',
    }
  }, store);
  // Empty string is falsy — version check skipped
  assert(r.ok || !r.ok, 'Empty version handled without crash');
});

await test('x-tsk-key exactly 1024 bytes (boundary)', async () => {
  const r = await verifyTSKRequest({
    headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': 'A'.repeat(1024),
      'x-tsk-version': '1',
    }
  }, store);
  // 1024 is exactly TSK_MAX_KEY_HEADER_BYTES — should NOT trigger too-large check
  // but will fail validation (wrong key)
  assert(!r.ok, '1024-byte key rejected (wrong key, not too-large)');
  assert(r.error !== 'TSK_KEY_TOO_LARGE', `1024-byte key should not be TSK_KEY_TOO_LARGE (boundary is >1024)`);
});

await test('x-tsk-key exactly 1025 bytes (over boundary)', async () => {
  const r = await verifyTSKRequest({
    headers: {
      'x-tsk-client-id': map.clientId,
      'x-tsk-key': 'A'.repeat(1025),
      'x-tsk-version': '1',
    }
  }, store);
  assert(!r.ok, '1025-byte key rejected');
  assert(r.error === 'TSK_KEY_TOO_LARGE', `Expected TSK_KEY_TOO_LARGE, got ${r.error}`);
});

await test('Missing x-tsk-client-id header', async () => {
  const r = await verifyTSKRequest({
    headers: { 'x-tsk-key': validKey, 'x-tsk-version': '1' }
  }, store);
  assert(!r.ok, 'Missing clientId rejected');
  assert(r.error === 'TSK_HEADERS_MISSING', `Expected TSK_HEADERS_MISSING, got ${r.error}`);
});

await test('Missing x-tsk-key header', async () => {
  const r = await verifyTSKRequest({
    headers: { 'x-tsk-client-id': map.clientId, 'x-tsk-version': '1' }
  }, store);
  assert(!r.ok, 'Missing key rejected');
  assert(r.error === 'TSK_HEADERS_MISSING', `Expected TSK_HEADERS_MISSING, got ${r.error}`);
});

await test('Both required headers missing', async () => {
  const r = await verifyTSKRequest({ headers: {} }, store);
  assert(!r.ok, 'Empty headers rejected');
});

await test('Headers object with undefined values', async () => {
  const r = await verifyTSKRequest({
    headers: {
      'x-tsk-client-id': undefined,
      'x-tsk-key': undefined,
    }
  }, store);
  assert(!r.ok, 'Undefined header values rejected');
});

// ─── FUZZ GROUP 7: Anomaly Engine Fuzzing ─────────────────────────────────────
console.log('\n[FUZZ-7] Anomaly Engine Fuzzing');

await test('Record event with empty segmentResults array', () => {
  try {
    anomaly.record({
      clientId: 'test_client',
      timestamp: NOW,
      segmentResults: [],
    });
    const s = anomaly.score('test_client');
    assert(s.score >= 0 && s.score <= 100, 'Score in valid range after empty event');
  } catch (e: any) {
    throw new Error(`Empty segmentResults crashed anomaly engine: ${e.message}`);
  }
});

await test('Score for client with no events', () => {
  const s = anomaly.score('never_seen_client_xyz');
  assert(s.score === 0, 'Unknown client has score 0');
  assert(s.verdict === 'clean', 'Unknown client is clean');
});

await test('Anomaly engine: 10 failures triggers high score', () => {
  const testClient = 'fuzz_client_flood';
  for (let i = 0; i < 10; i++) {
    anomaly.record({
      clientId: testClient,
      timestamp: NOW,
      segmentResults: [{ segmentId: 'seg_x', type: 'totp' as const, valid: false }],
    });
  }
  const s = anomaly.score(testClient);
  assert(s.score >= 40, `Expected score >=40 for 10 failures, got ${s.score}`);
});

await test('Anomaly engine: stolen-key pattern detection', () => {
  const testClient = 'fuzz_stolen_key';
  // Static segment passes (id_ prefix), rotating fails
  for (let i = 0; i < 3; i++) {
    anomaly.record({
      clientId: testClient,
      timestamp: NOW,
      segmentResults: [
        { segmentId: 'id_static', type: 'static' as const, valid: true },   // static passes
        { segmentId: 'seg_totp', type: 'totp' as const, valid: false },    // rotating fails
      ],
    });
  }
  const s = anomaly.score(testClient);
  assert(s.score >= 50, `Expected score >=50 for stolen-key pattern, got ${s.score}`);
  assert(s.verdict !== 'clean', `Expected suspicious/attack verdict, got ${s.verdict}`);
});

await test('Anomaly engine: score capped at 100', () => {
  const testClient = 'fuzz_max_score';
  // Trigger all scoring conditions simultaneously
  for (let i = 0; i < 15; i++) {
    anomaly.record({
      clientId: testClient,
      timestamp: NOW,
      segmentResults: [
        { segmentId: 'id_static', type: 'static' as const, valid: true },
        { segmentId: 'seg_totp', type: 'totp' as const, valid: false },
      ],
    });
  }
  const s = anomaly.score(testClient);
  assert(s.score <= 100, `Score must not exceed 100, got ${s.score}`);
});

await test('Anomaly engine: reset clears state', () => {
  const testClient = 'fuzz_reset_test';
  for (let i = 0; i < 10; i++) {
    anomaly.record({ clientId: testClient, timestamp: NOW, segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }] });
  }
  anomaly.reset(testClient);
  const s = anomaly.score(testClient);
  assert(s.score === 0, 'Score is 0 after reset');
});

await test('Anomaly engine: events outside window are pruned', () => {
  const testClient = 'fuzz_window_prune';
  const oldTime = NOW - 6 * 60 * 1000; // 6 minutes ago (outside 5-min window)
  for (let i = 0; i < 10; i++) {
    anomaly.record({ clientId: testClient, timestamp: oldTime, segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }] });
  }
  // Record one fresh event to trigger pruning
  anomaly.record({ clientId: testClient, timestamp: NOW, segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }] });
  const s = anomaly.score(testClient);
  // Only 1 event in window — should be low score
  assert(s.score < 40, `Old events should be pruned, score should be low, got ${s.score}`);
});

// ─── Results ──────────────────────────────────────────────────────────────────
console.log('\n' + '═'.repeat(70));
console.log('RED TEAM FUZZ RESULTS');
console.log('═'.repeat(70));
console.log(`Tests: ${passed + failed} | Passed: ${passed} | Failed: ${failed} | Warnings: ${warnings}`);
if (findings.length > 0) {
  console.log('\nFINDINGS:');
  for (const f of findings) {
    console.log(`  [${f.sev}] ${f.name}`);
    console.log(`         ${f.detail}`);
  }
} else {
  console.log('No findings.');
}
if (failed > 0) process.exit(1);
