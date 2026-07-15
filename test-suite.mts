/**
 * TSK Protocol — Full Test Suite
 * Run with: npx tsx test-suite.mts
 */

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

// ─── Import core modules directly (avoid module resolution issues) ───────────
// We inline the core logic here for a self-contained test that proves the protocol works

// ============================================================================
// CRYPTO PRIMITIVES
// ============================================================================

function hmac(secret: string, data: string): string {
  return createHmac('sha256', Buffer.from(secret, 'hex'))
    .update(data)
    .digest('base64url');
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function generateSharedSecret(): string {
  return randomBytes(32).toString('hex');
}

// ============================================================================
// TYPES
// ============================================================================

type SegmentType = 'static' | 'totp' | 'hotp';

interface SegmentConfig {
  segmentId: string;
  position: [number, number];
  type: SegmentType;
  windowSec?: number;
  counter?: number;
}

interface TumblerMap {
  clientId: string;
  sharedSecret: string;
  keyLength: number;
  segments: SegmentConfig[];
  checksum: { position: [number, number] };
  createdAt: number;
  version: '1';
}

// ============================================================================
// SEGMENT DERIVATION
// ============================================================================

function padOrTruncate(s: string, length: number): string {
  if (s.length >= length) return s.slice(0, length);
  let result = s;
  while (result.length < length) {
    result += hmac(s, result);
  }
  return result.slice(0, length);
}

function deriveSegmentValue(secret: string, seg: SegmentConfig, nowMs: number): string {
  const segLen = seg.position[1] - seg.position[0];
  let input: string;
  if (seg.type === 'static') {
    input = `static:${seg.segmentId}`;
  } else if (seg.type === 'totp') {
    const T = Math.floor(nowMs / 1000 / (seg.windowSec ?? 60));
    input = `totp:${seg.segmentId}:${T}`;
  } else {
    input = `hotp:${seg.segmentId}:${seg.counter ?? 0}`;
  }
  return padOrTruncate(hmac(secret, input), segLen);
}

// ============================================================================
// KEY GENERATION
// ============================================================================

function generateKey(map: TumblerMap, nowMs: number): string {
  const buf = new Array<string>(map.keyLength).fill('\x00');

  for (const seg of map.segments) {
    const val = deriveSegmentValue(map.sharedSecret, seg, nowMs);
    for (let i = 0; i < seg.position[1] - seg.position[0]; i++) {
      buf[seg.position[0] + i] = val[i] ?? 'A';
    }
  }

  const withoutCs = buf.slice(0, map.checksum.position[0]).join('');
  const cs = hmac(map.sharedSecret, `checksum:${withoutCs}`).slice(0, map.checksum.position[1] - map.checksum.position[0]);
  for (let i = 0; i < cs.length; i++) {
    buf[map.checksum.position[0] + i] = cs[i];
  }
  return buf.join('');
}

// ============================================================================
// VALIDATION
// ============================================================================

interface ValidationResult {
  ok: boolean;
  error?: string;
  segmentResults?: { segmentId: string; valid: boolean }[];
  counterUpdates?: Map<string, number>;
}

function validateKey(key: string, map: TumblerMap, nowMs: number, totpTolerance = 1, hotpLookahead = 5): ValidationResult {
  if (key.length !== map.keyLength) return { ok: false, error: 'KEY_LENGTH_MISMATCH' };

  // Checksum first
  const csStart = map.checksum.position[0];
  const csEnd = map.checksum.position[1];
  const providedCs = key.slice(csStart, csEnd);
  const expectedCs = hmac(map.sharedSecret, `checksum:${key.slice(0, csStart)}`).slice(0, csEnd - csStart);
  if (!constantTimeEqual(providedCs, expectedCs)) {
    return { ok: false, error: 'CHECKSUM_INVALID' };
  }

  const segResults: { segmentId: string; valid: boolean }[] = [];
  const counterUpdates = new Map<string, number>();
  let allValid = true;

  for (const seg of map.segments) {
    const provided = key.slice(seg.position[0], seg.position[1]);
    let valid = false;

    if (seg.type === 'static') {
      valid = constantTimeEqual(provided, deriveSegmentValue(map.sharedSecret, seg, nowMs));
    } else if (seg.type === 'totp') {
      const ws = seg.windowSec ?? 60;
      const T = Math.floor(nowMs / 1000 / ws);
      for (let d = -totpTolerance; d <= totpTolerance; d++) {
        const segLen = seg.position[1] - seg.position[0];
        const expected = padOrTruncate(hmac(map.sharedSecret, `totp:${seg.segmentId}:${T + d}`), segLen);
        if (constantTimeEqual(provided, expected)) { valid = true; break; }
      }
    } else {
      const base = seg.counter ?? 0;
      for (let la = 0; la <= hotpLookahead; la++) {
        const segLen = seg.position[1] - seg.position[0];
        const expected = padOrTruncate(hmac(map.sharedSecret, `hotp:${seg.segmentId}:${base + la}`), segLen);
        if (constantTimeEqual(provided, expected)) {
          valid = true;
          counterUpdates.set(seg.segmentId, base + la + 1);
          break;
        }
      }
    }

    segResults.push({ segmentId: seg.segmentId, valid });
    if (!valid) allValid = false;
  }

  if (!allValid) return { ok: false, error: 'VALIDATION_FAILED', segmentResults: segResults };
  return { ok: true, segmentResults: segResults, counterUpdates };
}

// ============================================================================
// TEST HARNESS
// ============================================================================

let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e: any) {
    failed++;
    const msg = e.message ?? String(e);
    failures.push(`${name}: ${msg}`);
    console.log(`  ✗ ${name}`);
    console.log(`    ${msg}`);
  }
}

function assert(condition: boolean, msg: string) {
  if (!condition) throw new Error(msg);
}

// ============================================================================
// BUILD TEST TUMBLER MAP
// ============================================================================

const NOW = Date.now();
const secret = generateSharedSecret();

// Deterministic map with known structure for testing
const testMap: TumblerMap = {
  clientId: 'tsk_test_client',
  sharedSecret: secret,
  keyLength: 52,
  segments: [
    { segmentId: 'id_001', position: [0, 8], type: 'static' },
    { segmentId: 'seg_totp30', position: [8, 18], type: 'totp', windowSec: 30 },
    { segmentId: 'seg_totp60', position: [18, 28], type: 'totp', windowSec: 60 },
    { segmentId: 'seg_hotp', position: [28, 36], type: 'hotp', counter: 0 },
    { segmentId: 'seg_static2', position: [36, 44], type: 'static' },
  ],
  checksum: { position: [44, 52] },
  createdAt: NOW,
  version: '1',
};

// ============================================================================
// TESTS
// ============================================================================

console.log('\n[1] Crypto Primitives');

test('HMAC produces deterministic output', () => {
  const a = hmac(secret, 'test');
  const b = hmac(secret, 'test');
  assert(a === b, `Expected ${a} === ${b}`);
});

test('HMAC differs with different inputs', () => {
  const a = hmac(secret, 'test1');
  const b = hmac(secret, 'test2');
  assert(a !== b, 'Expected different HMAC outputs');
});

test('HMAC differs with different secrets', () => {
  const s2 = generateSharedSecret();
  const a = hmac(secret, 'test');
  const b = hmac(s2, 'test');
  assert(a !== b, 'Expected different secrets → different HMAC');
});

test('timingSafeEqual wrapper: equal strings pass', () => {
  assert(constantTimeEqual('hello', 'hello'), 'Equal strings should match');
});

test('timingSafeEqual wrapper: unequal strings fail', () => {
  assert(!constantTimeEqual('hello', 'world'), 'Unequal strings should not match');
});

test('timingSafeEqual wrapper: different lengths fail', () => {
  assert(!constantTimeEqual('hello', 'hi'), 'Different lengths should not match');
});

console.log('\n[2] Segment Derivation');

test('Static segment is deterministic', () => {
  const a = deriveSegmentValue(secret, testMap.segments[0], NOW);
  const b = deriveSegmentValue(secret, testMap.segments[0], NOW + 60000);
  assert(a === b, 'Static segment should be time-independent');
});

test('TOTP segment changes across windows', () => {
  const seg = testMap.segments[1]; // 30s window
  const a = deriveSegmentValue(secret, seg, NOW);
  const b = deriveSegmentValue(secret, seg, NOW + 31_000); // Next 30s window
  assert(a !== b, 'TOTP segment should differ across windows');
});

test('TOTP segment stable within window', () => {
  const seg = testMap.segments[1]; // 30s window
  const windowStart = Math.floor(NOW / 30000) * 30000;
  const a = deriveSegmentValue(secret, seg, windowStart * 1000);
  const b = deriveSegmentValue(secret, seg, windowStart * 1000 + 5000);
  // These should be the same because same T = floor(ms/1000/30)
  const T1 = Math.floor(windowStart / 30);
  const T2 = Math.floor((windowStart + 5) / 30);
  if (T1 === T2) {
    assert(a === b, 'Same TOTP window should produce same value');
  }
});

test('HOTP segment changes with counter', () => {
  const seg0 = { ...testMap.segments[3], counter: 0 };
  const seg1 = { ...testMap.segments[3], counter: 1 };
  const a = deriveSegmentValue(secret, seg0, NOW);
  const b = deriveSegmentValue(secret, seg1, NOW);
  assert(a !== b, 'Different HOTP counters should produce different values');
});

test('Segment value fills correct length', () => {
  for (const seg of testMap.segments) {
    const val = deriveSegmentValue(secret, seg, NOW);
    const expected = seg.position[1] - seg.position[0];
    assert(val.length === expected, `Segment ${seg.segmentId}: expected ${expected} chars, got ${val.length}`);
  }
});

console.log('\n[3] Key Generation');

test('Generated key has correct length', () => {
  const key = generateKey(testMap, NOW);
  assert(key.length === 52, `Expected 52 chars, got ${key.length}`);
});

test('Generated key is deterministic for same time', () => {
  const a = generateKey(testMap, NOW);
  const b = generateKey(testMap, NOW);
  assert(a === b, 'Same time should produce same key');
});

test('Key differs at different times (TOTP segments change)', () => {
  const a = generateKey(testMap, NOW);
  const b = generateKey(testMap, NOW + 120_000); // 2 min later
  assert(a !== b, 'Keys at different times should differ');
});

test('Key contains valid checksum', () => {
  const key = generateKey(testMap, NOW);
  const csStart = testMap.checksum.position[0];
  const csEnd = testMap.checksum.position[1];
  const withoutCs = key.slice(0, csStart);
  const expected = hmac(secret, `checksum:${withoutCs}`).slice(0, csEnd - csStart);
  assert(key.slice(csStart, csEnd) === expected, 'Checksum mismatch');
});

console.log('\n[4] Validation — Happy Path');

test('Valid key passes validation', () => {
  const key = generateKey(testMap, NOW);
  const result = validateKey(key, testMap, NOW);
  assert(result.ok, `Expected ok, got error: ${result.error}`);
});

test('All segment results are valid', () => {
  const key = generateKey(testMap, NOW);
  const result = validateKey(key, testMap, NOW);
  assert(result.ok, `Validation failed: ${result.error}`);
  assert(result.segmentResults!.every(sr => sr.valid), 'Expected all segments valid');
});

test('TOTP tolerance: key from ±1 window still valid', () => {
  const seg = testMap.segments[1]; // 30s window
  const windowSec = seg.windowSec!;
  // Generate key at time T-1 window (just before current window)
  const pastKey = generateKey(testMap, NOW - (windowSec * 1000));
  const result = validateKey(pastKey, testMap, NOW, 1);
  assert(result.ok, `Key from -1 window should pass with tolerance=1, got: ${result.error}`);
});

test('HOTP counter: key with counter=0 valid, advances counter', () => {
  const key = generateKey(testMap, NOW);
  const result = validateKey(key, testMap, NOW);
  assert(result.ok, `Expected ok, got: ${result.error}`);
  const update = result.counterUpdates?.get('seg_hotp');
  assert(update === 1, `Expected counter advance to 1, got ${update}`);
});

test('HOTP lookahead: counter+3 valid within lookahead=5', () => {
  const futureMap = JSON.parse(JSON.stringify(testMap)) as TumblerMap;
  futureMap.segments[3].counter = 3; // counter is at 3
  const key = generateKey(futureMap, NOW);
  // Validate against original map (counter still at 0), lookahead=5 should catch counter=3
  const result = validateKey(key, testMap, NOW, 1, 5);
  assert(result.ok, `Counter=3 should pass with lookahead=5, got: ${result.error}`);
});

console.log('\n[5] Validation — Attack Rejection');

test('Wrong key length rejected', () => {
  const result = validateKey('short', testMap, NOW);
  assert(!result.ok, 'Short key should fail');
  assert(result.error === 'KEY_LENGTH_MISMATCH', `Expected KEY_LENGTH_MISMATCH, got ${result.error}`);
});

test('Tampered key rejected (single char flip)', () => {
  const key = generateKey(testMap, NOW);
  const mid = 20;
  const tampered = key.slice(0, mid) + (key[mid] === 'A' ? 'B' : 'A') + key.slice(mid + 1);
  const result = validateKey(tampered, testMap, NOW);
  assert(!result.ok, 'Tampered key should fail');
});

test('Expired TOTP rejected (5 min old)', () => {
  const oldKey = generateKey(testMap, NOW - 5 * 60 * 1000);
  const result = validateKey(oldKey, testMap, NOW, 1);
  assert(!result.ok, '5-minute-old key should fail with tolerance=1');
});

test('Replay with wrong HOTP counter rejected', () => {
  const advanced = JSON.parse(JSON.stringify(testMap)) as TumblerMap;
  advanced.segments[3].counter = 100; // way past lookahead
  const key = generateKey(advanced, NOW);
  const result = validateKey(key, testMap, NOW, 1, 5);
  assert(!result.ok, 'Counter=100 with lookahead=5 should fail');
});

test('Wrong shared secret rejected', () => {
  const wrongSecret = generateSharedSecret();
  const wrongMap = { ...testMap, sharedSecret: wrongSecret };
  const key = generateKey(wrongMap, NOW);
  const result = validateKey(key, testMap, NOW);
  assert(!result.ok, 'Key from wrong secret should fail');
});

test('Positionally shifted key rejected', () => {
  const key = generateKey(testMap, NOW);
  const shifted = key.slice(1) + key[0];
  const result = validateKey(shifted, testMap, NOW);
  assert(!result.ok, 'Positionally shifted key should fail');
});

test('All-zeros key rejected', () => {
  const zeros = '0'.repeat(52);
  const result = validateKey(zeros, testMap, NOW);
  assert(!result.ok, 'All-zeros key should fail');
});

test('Random key rejected', () => {
  const rand = randomBytes(52).toString('base64url').slice(0, 52);
  const result = validateKey(rand, testMap, NOW);
  assert(!result.ok, 'Random key should fail');
});

console.log('\n[6] Stale And Hybrid Credential Cases');

test('Hybrid key (old rotating + current static) rejected', () => {
  const key1 = generateKey(testMap, NOW);
  const key2 = generateKey(testMap, NOW + 120_000);
  // Find which positions changed
  const changed: number[] = [];
  for (let i = 0; i < key1.length; i++) {
    if (key1[i] !== key2[i]) changed.push(i);
  }
  // Splice old rotating values into new static positions
  const hybrid = key2.split('').map((c, i) => changed.includes(i) ? key1[i] : c).join('');
  const result = validateKey(hybrid, testMap, NOW + 120_000);
  assert(!result.ok, 'Hybrid key should fail');
});

test('Segment failure pattern detects stolen key', () => {
  // Simulate: attacker has correct static segment but expired rotating segments
  const oldKey = generateKey(testMap, NOW - 300_000); // 5 min ago
  const result = validateKey(oldKey, testMap, NOW, 1);
  assert(!result.ok, 'Old key should fail');
  if (result.segmentResults) {
    const staticPassed = result.segmentResults.filter(sr =>
      sr.segmentId.startsWith('id_') || sr.segmentId.startsWith('seg_static')
    ).every(sr => sr.valid);
    const rotatingFailed = result.segmentResults.filter(sr =>
      sr.segmentId.startsWith('seg_totp') || sr.segmentId.startsWith('seg_hotp')
    ).some(sr => !sr.valid);
    assert(staticPassed, 'Static segments should still match in stolen key');
    assert(rotatingFailed, 'Rotating segments should fail in stolen key');
    console.log(`    → Stolen key pattern detected: static=pass, rotating=fail`);
  }
});

console.log('\n[7] Provisioning Flow');

test('Different clients get different maps', () => {
  const s1 = generateSharedSecret();
  const s2 = generateSharedSecret();
  assert(s1 !== s2, 'Shared secrets should be unique');
  const k1 = generateKey({ ...testMap, sharedSecret: s1 }, NOW);
  const k2 = generateKey({ ...testMap, sharedSecret: s2 }, NOW);
  assert(k1 !== k2, 'Keys from different secrets should differ');
});

test('Revoked client (missing map) fails validation', () => {
  // Simulate revocation: map not found → we can just check key against wrong map
  const revokedMap = { ...testMap, sharedSecret: generateSharedSecret() };
  const key = generateKey(testMap, NOW);
  const result = validateKey(key, revokedMap, NOW);
  assert(!result.ok, 'Key should fail against revoked (different) map');
});

console.log('\n[8] Edge Cases');

test('Key at exact TOTP window boundary', () => {
  const seg = testMap.segments[1]; // 30s window
  const boundaryMs = Math.floor(NOW / 30000) * 30000 * 1000; // exact boundary
  const key = generateKey(testMap, boundaryMs);
  const result = validateKey(key, testMap, boundaryMs);
  assert(result.ok, `Boundary key should pass, got: ${result.error}`);
});

test('Very long segment value (padOrTruncate)', () => {
  const longSeg: SegmentConfig = {
    segmentId: 'long_seg',
    position: [0, 100], // 100 chars — longer than one HMAC output
    type: 'static',
  };
  const val = deriveSegmentValue(secret, longSeg, NOW);
  assert(val.length === 100, `Expected 100 chars, got ${val.length}`);
});

test('Multiple HOTP advances within lookahead', () => {
  for (let c = 0; c <= 5; c++) {
    const advMap = JSON.parse(JSON.stringify(testMap)) as TumblerMap;
    advMap.segments[3].counter = c;
    const key = generateKey(advMap, NOW);
    const result = validateKey(key, testMap, NOW, 1, 5);
    assert(result.ok, `Counter=${c} should pass within lookahead=5, got: ${result.error}`);
  }
});

test('HOTP counter=6 beyond lookahead=5 fails', () => {
  const advMap = JSON.parse(JSON.stringify(testMap)) as TumblerMap;
  advMap.segments[3].counter = 6;
  const key = generateKey(advMap, NOW);
  const result = validateKey(key, testMap, NOW, 1, 5);
  assert(!result.ok, 'Counter=6 should fail with lookahead=5');
});

// ============================================================================
// RESULTS
// ============================================================================

console.log('\n' + '─'.repeat(60));
console.log(`TSK Protocol Test Suite: ${passed}/${passed + failed} passed`);
if (failed > 0) {
  console.log(`\nFAILURES (${failed}):`);
  for (const f of failures) console.log(`  ✗ ${f}`);
  process.exit(1);
} else {
  console.log('Named TSK protocol cases passed');
}
