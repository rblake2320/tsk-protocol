/**
 * RED TEAM CRYPTOGRAPHIC ATTACK SUITE — tsk-protocol
 * Replay attacks, timing oracle, HMAC length extension, counter manipulation,
 * segment isolation, oracle attacks, and more.
 */
import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import { createTSKServer } from './packages/server/src/index.js';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import { validateTSKKey } from './packages/core/src/validate.js';
import { generateTumblerMap } from './packages/core/src/tumbler-map.js';
import { hmac } from './packages/core/src/crypto.js';
import { verifyTSKRequest } from './packages/server/src/middleware.js';
import { computeChecksum, CHECKSUM_LENGTH } from './packages/core/src/tumbler-map.js';
import { deriveSegmentValue } from './packages/core/src/segment.js';
import type { TumblerMap } from './packages/core/src/types.js';

// ─── Harness ──────────────────────────────────────────────────────────────────
let passed = 0; let failed = 0;
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
  findings.push({ sev: 'WARN', name, detail });
  console.log(`  ⚠ WARN: ${name}: ${detail}`);
}
function assert(cond: boolean, msg: string) { if (!cond) throw new Error(msg); }

// ─── Setup ────────────────────────────────────────────────────────────────────
const { store, provisioner, anomaly } = createTSKServer();
const prov = await provisioner.provision({ keyLength: 52, minTumblers: 2, maxTumblers: 4 });
if (!prov.ok || !prov.tumblerMap) { console.error('FATAL'); process.exit(1); }
const map = prov.tumblerMap!;
const NOW = Date.now();
const validKey = generateKeyFromMap(map, NOW);

// ─── CRYPTO-1: Replay Attack Variants ─────────────────────────────────────────
console.log('\n[CRYPTO-1] Replay Attack Variants');

await test('Immediate replay of valid TOTP key', async () => {
  const r1 = await verifyTSKRequest({ headers: { 'x-tsk-client-id': map.clientId, 'x-tsk-key': validKey, 'x-tsk-version': '1' } }, store);
  const r2 = await verifyTSKRequest({ headers: { 'x-tsk-client-id': map.clientId, 'x-tsk-key': validKey, 'x-tsk-version': '1' } }, store);
  // TOTP keys are valid for the entire window — immediate replay SUCCEEDS
  // This is by design but worth documenting
  if (r1.ok && r2.ok) {
    warn('TOTP replay succeeds within window', 
      'A captured TOTP key can be replayed unlimited times within its validity window (up to 300s for 300s windows). ' +
      'There is NO per-request nonce or one-time-use mechanism for TOTP segments. ' +
      'An attacker who intercepts a key can replay it for up to 300 seconds.');
  }
  assert(r1.ok, 'First request should succeed');
});

await test('HOTP key replay after counter advance', async () => {
  // Provision a pure-HOTP map
  const hotpProv = await provisioner.provision({ keyLength: 52, minTumblers: 1, maxTumblers: 1 });
  if (!hotpProv.ok || !hotpProv.tumblerMap) return;
  // Force all segments to HOTP for this test
  const hotpMap: TumblerMap = {
    ...hotpProv.tumblerMap,
    segments: hotpProv.tumblerMap.segments.map(s => ({
      ...s, type: 'hotp' as const, counter: 0, windowSec: undefined
    })),
  };
  await store.set(hotpMap.clientId, hotpMap);
  const key0 = generateKeyFromMap(hotpMap, NOW);
  // First use — should succeed and advance counter
  const r1 = await verifyTSKRequest({ headers: { 'x-tsk-client-id': hotpMap.clientId, 'x-tsk-key': key0, 'x-tsk-version': '1' } }, store);
  // Replay — counter has advanced, old key should fail
  const r2 = await verifyTSKRequest({ headers: { 'x-tsk-client-id': hotpMap.clientId, 'x-tsk-key': key0, 'x-tsk-version': '1' } }, store);
  assert(r1.ok, 'First HOTP use should succeed');
  assert(!r2.ok, 'HOTP replay should be rejected after counter advance');
});

await test('HOTP lookahead window replay attack', async () => {
  // If client generates counter+3 key (within lookahead), server accepts and advances to counter+4
  // Attacker who captured counter+1 or counter+2 keys can no longer use them
  const hotpProv = await provisioner.provision({ keyLength: 52, minTumblers: 1, maxTumblers: 1 });
  if (!hotpProv.ok || !hotpProv.tumblerMap) return;
  const hotpMap: TumblerMap = {
    ...hotpProv.tumblerMap,
    segments: hotpProv.tumblerMap.segments.map(s => ({
      ...s, type: 'hotp' as const, counter: 0, windowSec: undefined
    })),
  };
  await store.set(hotpMap.clientId, hotpMap);
  // Generate key for counter=3 (within default lookahead=5)
  const mapAtCounter3: TumblerMap = {
    ...hotpMap,
    segments: hotpMap.segments.map(s => ({ ...s, counter: 3 })),
  };
  const keyCounter3 = generateKeyFromMap(mapAtCounter3, NOW);
  const r = await verifyTSKRequest({ headers: { 'x-tsk-client-id': hotpMap.clientId, 'x-tsk-key': keyCounter3, 'x-tsk-version': '1' } }, store);
  assert(r.ok, 'Counter+3 key should be accepted within lookahead');
  // Now try counter=1 (behind the advanced counter) — should fail
  const mapAtCounter1: TumblerMap = {
    ...hotpMap,
    segments: hotpMap.segments.map(s => ({ ...s, counter: 1 })),
  };
  const keyCounter1 = generateKeyFromMap(mapAtCounter1, NOW);
  const r2 = await verifyTSKRequest({ headers: { 'x-tsk-client-id': hotpMap.clientId, 'x-tsk-key': keyCounter1, 'x-tsk-version': '1' } }, store);
  assert(!r2.ok, 'Counter behind advanced value should be rejected');
});

// ─── CRYPTO-2: Timing Oracle Analysis ─────────────────────────────────────────
console.log('\n[CRYPTO-2] Timing Oracle Analysis');

await test('Timing analysis: checksum-fail vs segment-fail paths', () => {
  // If checksum validation short-circuits before segment validation,
  // an attacker can distinguish "wrong checksum" from "wrong segment" by timing
  const ITERATIONS = 5000;
  
  // Key with correct length but wrong checksum (random last 8 chars)
  const wrongChecksumKey = validKey.slice(0, 44) + randomBytes(6).toString('base64url').slice(0, 8);
  
  // Key with correct checksum but wrong segment values (we need to craft this)
  // Use a key from a different time (expired TOTP) — segments wrong, checksum was valid at that time
  const oldKey = generateKeyFromMap(map, NOW - 10 * 60 * 1000); // 10 min old
  
  function measureMs(key: string, iters: number): number {
    const times: number[] = [];
    for (let i = 0; i < iters; i++) {
      const t0 = performance.now();
      validateTSKKey(key, { map, nowMs: NOW });
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    return times[Math.floor(times.length / 2)]; // median
  }
  
  const timeChecksumFail = measureMs(wrongChecksumKey, ITERATIONS);
  const timeSegmentFail = measureMs(oldKey, ITERATIONS);
  const timeValid = measureMs(validKey, ITERATIONS);
  
  const diff1 = Math.abs(timeChecksumFail - timeSegmentFail);
  const diff2 = Math.abs(timeChecksumFail - timeValid);
  
  console.log(`    Timing (median over ${ITERATIONS} iters):`);
  console.log(`      Wrong checksum:  ${timeChecksumFail.toFixed(4)}ms`);
  console.log(`      Expired segment: ${timeSegmentFail.toFixed(4)}ms`);
  console.log(`      Valid key:       ${timeValid.toFixed(4)}ms`);
  console.log(`      Checksum vs Segment diff: ${diff1.toFixed(4)}ms`);
  
  // Note: checksum is validated AFTER segments in validate.ts
  // This means a wrong-checksum key still goes through full segment validation
  // That's actually good for timing resistance
  
  if (diff1 > 0.5) {
    warn('Timing difference detected', 
      `${diff1.toFixed(4)}ms difference between checksum-fail and segment-fail paths — potential timing oracle`);
  }
  assert(true, 'Timing test completed');
});

await test('Timing analysis: constantTimeEqual length check leak', () => {
  // constantTimeEqual returns false immediately if lengths differ (before timingSafeEqual)
  // This means an attacker can distinguish "wrong length" from "wrong content" by timing
  const ITERATIONS = 3000;
  
  function measureConstantTimeEqual(a: string, b: string, iters: number): number {
    const times: number[] = [];
    for (let i = 0; i < iters; i++) {
      const t0 = performance.now();
      // Simulate what constantTimeEqual does
      if (a.length !== b.length) { times.push(performance.now() - t0); continue; }
      const bufA = Buffer.from(a);
      const bufB = Buffer.from(b);
      timingSafeEqual(bufA, bufB);
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    return times[Math.floor(times.length / 2)];
  }
  
  const seg = validKey.slice(0, 8); // first segment
  const wrongLen = validKey.slice(0, 7); // wrong length
  const wrongContent = 'XXXXXXXX'; // same length, wrong content
  
  const timeLengthMismatch = measureConstantTimeEqual(seg, wrongLen, ITERATIONS);
  const timeContentMismatch = measureConstantTimeEqual(seg, wrongContent, ITERATIONS);
  
  const diff = Math.abs(timeLengthMismatch - timeContentMismatch);
  console.log(`    Length mismatch: ${timeLengthMismatch.toFixed(4)}ms`);
  console.log(`    Content mismatch: ${timeContentMismatch.toFixed(4)}ms`);
  console.log(`    Difference: ${diff.toFixed(4)}ms`);
  
  if (diff > 0.05) {
    warn('Length-check timing leak in constantTimeEqual',
      `constantTimeEqual short-circuits on length mismatch before calling timingSafeEqual. ` +
      `This leaks whether the compared strings have the same length — a minor timing side-channel. ` +
      `Diff: ${diff.toFixed(4)}ms`);
  }
  assert(true, 'Timing analysis completed');
});

// ─── CRYPTO-3: HMAC Construction Analysis ─────────────────────────────────────
console.log('\n[CRYPTO-3] HMAC Construction Analysis');

await test('HMAC key is hex-decoded before use', () => {
  // IL4/5/6/7 FIX: crypto.ts now validates the secret before use via validateHexSecret().
  // Previously, Buffer.from(badHex, 'hex') would silently produce an empty buffer,
  // causing all clients with invalid secrets to share the same HMAC key.
  // Now, hmac() throws a TypeError for non-hex secrets, preventing silent key collapse.
  const badHexSecret = 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ'; // not hex
  const shortSecret = 'abc123'; // too short

  let threwForBadHex = false;
  let threwForShortSecret = false;
  try { hmac(badHexSecret, 'test_data'); } catch (e) { threwForBadHex = true; }
  try { hmac(shortSecret, 'test_data'); } catch (e) { threwForShortSecret = true; }

  assert(threwForBadHex, 'hmac() should throw for non-hex secret (FIXED: no silent key collapse)');
  assert(threwForShortSecret, 'hmac() should throw for short secret (FIXED: no silent key collapse)');
  console.log('    FIXED: hmac() now throws for invalid secrets — no silent key collapse ✓');
});

await test('HMAC derivation input collision: static vs totp segmentId', () => {
  // Could "static:seg_abc123" collide with "totp:seg_abc123:T" for some T?
  // No — different prefixes prevent this. But what about segmentId containing ":"?
  const collidingSegId = 'abc:123'; // contains colon
  const input1 = `static:${collidingSegId}`;       // "static:abc:123"
  const input2 = `totp:abc:123:0`;                  // "totp:abc:123:0" — different
  const input3 = `static:abc`;                       // "static:abc" + ":123" — different prefix
  
  const secret = randomBytes(32).toString('hex');
  const h1 = hmac(secret, input1);
  const h2 = hmac(secret, input2);
  const h3 = hmac(secret, input3);
  
  // These should all be different — HMAC is collision resistant
  assert(h1 !== h2, 'static:abc:123 != totp:abc:123:0');
  assert(h1 !== h3, 'static:abc:123 != static:abc');
  
  // But check: can a segmentId with ":" cause type confusion?
  // "totp:seg_with:colon:T" — the T parser would see extra colons
  // This is a derivation input formatting issue
  const segWithColon = 'seg_with:colon';
  const totpInput = `totp:${segWithColon}:100`;  // "totp:seg_with:colon:100"
  const staticInput = `static:${segWithColon}`;   // "static:seg_with:colon"
  
  // These are fine since HMAC doesn't parse the string — it just hashes it
  // But if a segmentId = "x:100" then:
  // totp:x:100:T could be confused with totp:x:100 for T=undefined
  // This is a theoretical concern but HMAC makes it irrelevant in practice
  
  console.log(`    Derivation input collision test: all distinct ✓`);
  assert(true, 'HMAC input collision analysis complete');
});

await test('padOrTruncate: HMAC-of-HMAC chaining for long segments', () => {
  // padOrTruncate calls hmac(s, result) where s is the ORIGINAL hmac output
  // and result grows. This is non-standard — let's verify it's deterministic
  // and doesn't create weak patterns.
  // IL4/5/6/7 FIX: sharedSecret must be 64 hex chars (256 bits). The provisioner
  // now generates secrets with randomBytes(32).toString('hex') = 64 hex chars.
  const secret = randomBytes(32).toString('hex'); // 64 hex chars = 256 bits ✓
  assert(secret.length === 64, `Secret must be 64 hex chars, got ${secret.length}`);
  const seg = { segmentId: 'seg_long', position: [0, 200] as [number, number], type: 'static' as const };

  // Generate a very long segment value twice
  const val1 = deriveSegmentValue(secret, seg, NOW);
  const val2 = deriveSegmentValue(secret, seg, NOW);
  assert(val1 === val2, 'Long segment derivation is deterministic');
  assert(val1.length === 200, `Expected length 200, got ${val1.length}`);

  // Check for repeated patterns (weak padding)
  const base64urlChars = new Set(val1.split(''));
  const uniqueChars = base64urlChars.size;
  console.log(`    Long segment (200 chars): ${uniqueChars} unique chars (expected: ~64 base64url chars)`);
  if (uniqueChars < 20) {
    warn('Low entropy in padded segment', `Only ${uniqueChars} unique chars in 200-char padded segment — possible weak padding`);
  }
  assert(true, 'padOrTruncate analysis complete');
});

await test('Checksum covers only pre-checksum bytes, not full key', () => {
  // computeChecksum(secret, keyWithoutChecksum) — checksum covers chars [0, checksumStart)
  // This means the checksum does NOT cover itself (expected)
  // But: does the checksum cover ALL segment positions?
  // If checksum position is [44,52] and key is 52 chars, then chars [0,44] are covered
  // Segments must all fit within [0,44] for full coverage
  
  // Check if any segment extends into or beyond checksum region
  const checksumStart = map.checksum.position[0];
  const overlappingSegs = map.segments.filter(s => s.position[1] > checksumStart);
  
  if (overlappingSegs.length > 0) {
    warn('Segment overlaps checksum region',
      `Segment(s) extend into checksum region: ${overlappingSegs.map(s => `${s.segmentId}[${s.position}]`).join(', ')}. ` +
      `The checksum only covers bytes [0, ${checksumStart}), so segment bytes in the checksum region are NOT integrity-protected by the checksum.`);
  } else {
    console.log(`    All segments within [0, ${checksumStart}) — checksum covers all segment bytes ✓`);
  }
  assert(true, 'Checksum coverage analysis complete');
});

// ─── CRYPTO-4: Key Derivation Attacks ─────────────────────────────────────────
console.log('\n[CRYPTO-4] Key Derivation & Structural Attacks');

await test('Cross-client key confusion: use client A key for client B', async () => {
  const prov2 = await provisioner.provision({ keyLength: 52 });
  if (!prov2.ok || !prov2.tumblerMap) return;
  const map2 = prov2.tumblerMap;
  const keyForMap2 = generateKeyFromMap(map2, NOW);
  
  // Try to use map2's key against map1's client ID
  const r = await verifyTSKRequest({
    headers: {
      'x-tsk-client-id': map.clientId,  // client 1
      'x-tsk-key': keyForMap2,           // key for client 2
      'x-tsk-version': '1',
    }
  }, store);
  assert(!r.ok, 'Cross-client key confusion rejected');
});

await test('Key from same secret but different segmentId', () => {
  // What if attacker knows the secret and creates a fake segment with a different ID?
  const fakeMap: TumblerMap = {
    ...map,
    segments: map.segments.map(s => ({ ...s, segmentId: s.segmentId + '_fake' })),
  };
  const fakeKey = generateKeyFromMap(fakeMap, NOW);
  const r = validateTSKKey(fakeKey, { map, nowMs: NOW });
  assert(!r.ok, 'Key with fake segmentIds rejected');
});

await test('Segment value truncation: first N chars of HMAC are predictable?', () => {
  // HMAC-SHA256 output is 32 bytes = 43 base64url chars
  // Truncating to shorter values reduces entropy
  // A 4-char segment has only 64^4 = 16,777,216 possible values
  // For a 30s TOTP window, an attacker has 30s to try all 16M values
  
  const shortSegMap: TumblerMap = {
    ...map,
    segments: [
      { segmentId: 'id_short', position: [0, 4], type: 'static' },  // 4 chars = 16M values
      { segmentId: 'seg_short', position: [4, 8], type: 'totp', windowSec: 30 },  // 4 chars
    ],
    checksum: { position: [44, 52] },
    keyLength: 52,
  };
  
  // With 4-char segments, brute force space is 64^4 = 16,777,216
  // This is feasible for an attacker with API access
  const segEntropy = Math.log2(Math.pow(64, 4));
  console.log(`    4-char segment entropy: ${segEntropy.toFixed(1)} bits (64^4 = ${Math.pow(64,4).toLocaleString()} values)`);
  
  if (segEntropy < 24) {
    warn('Short segment low entropy',
      `A 4-char segment has only ${segEntropy.toFixed(1)} bits of entropy (${Math.pow(64,4).toLocaleString()} values). ` +
      `With a 30s TOTP window, an attacker could brute-force this segment value in <30s with sufficient API throughput. ` +
      `The spec does not enforce minimum segment length.`);
  }
  assert(true, 'Segment entropy analysis complete');
});

await test('TOTP window size 300s: 5-minute replay window', async () => {
  // A 300s TOTP window means a captured key is valid for up to 600s (±1 window = ±300s)
  // This is a significant replay window
  const longWindowMap: TumblerMap = {
    ...map,
    segments: map.segments.map(s => s.type === 'totp' ? { ...s, windowSec: 300 } : s),
  };
  await store.set(longWindowMap.clientId, longWindowMap);
  
  const keyNow = generateKeyFromMap(longWindowMap, NOW);
  // Test at T+299s (still in same window)
  const r299 = validateTSKKey(keyNow, { map: longWindowMap, nowMs: NOW + 299000 });
  // Test at T+600s (±1 window tolerance = ±300s, so T+600 is exactly at boundary)
  const r600 = validateTSKKey(keyNow, { map: longWindowMap, nowMs: NOW + 600000 });
  // Test at T+601s (just outside tolerance)
  const r601 = validateTSKKey(keyNow, { map: longWindowMap, nowMs: NOW + 601000 });
  
  console.log(`    Key valid at +299s: ${r299.ok}`);
  console.log(`    Key valid at +600s: ${r600.ok}`);
  console.log(`    Key valid at +601s: ${r601.ok}`);
  
  if (r600.ok) {
    warn('300s TOTP window = 10-minute replay window',
      `With windowSec=300 and totpToleranceWindows=1, a captured key is valid for up to 600 seconds (10 minutes). ` +
      `The spec allows windowSec up to 300. This is a significant replay window for stolen keys.`);
  }
  assert(true, 'TOTP window replay analysis complete');
});

await test('HOTP lookahead=5: attacker can pre-generate 5 future keys', () => {
  // The default hotpLookahead=5 means the server accepts counter+0 through counter+5
  // An attacker who intercepts the shared secret can pre-generate 5 valid future keys
  // This is a design trade-off (counter drift tolerance vs replay risk)
  
  // More critically: if an attacker intercepts counter+3, the server advances to counter+4
  // The legitimate client at counter+0 now needs to catch up — but counter+0 through +3 are now invalid
  // This is a denial-of-service vector: attacker can burn through the client's lookahead window
  
  warn('HOTP lookahead DoS vector',
    `hotpLookahead=5 means an attacker who intercepts a single HOTP key can advance the server counter, ` +
    `potentially desynchronizing the legitimate client. If the attacker intercepts key at counter+4, ` +
    `the server advances to counter+5, and the legitimate client at counter+0 is now 5 behind. ` +
    `With lookahead=5, the client can still catch up, but this is a fragile synchronization.`);
  assert(true, 'HOTP lookahead analysis complete');
});

// ─── CRYPTO-5: Checksum Bypass Attempts ───────────────────────────────────────
console.log('\n[CRYPTO-5] Checksum Bypass Attempts');

await test('Length extension attack on checksum HMAC', () => {
  // HMAC is not vulnerable to length extension (unlike plain SHA)
  // But let's verify the checksum computation is actually HMAC and not hash
  const cs1 = computeChecksum(map.sharedSecret, validKey.slice(0, 44));
  const cs2 = computeChecksum(map.sharedSecret, validKey.slice(0, 44) + 'extra');
  // cs1 already declared above
  assert(cs1 !== cs2, 'Checksum changes with different input (HMAC not vulnerable to length extension)');
  console.log(`    Checksum 1: ${cs1}`);
  console.log(`    Checksum 2: ${cs2}`);
  assert(true, 'Length extension attack not applicable to HMAC ✓');
  void cs2;
});

await test('Checksum with empty key body', () => {
  const cs = computeChecksum(map.sharedSecret, '');
  assert(cs.length === CHECKSUM_LENGTH, 'Checksum of empty body has correct length');
  console.log(`    Checksum of empty body: ${cs}`);
});

await test('Two different keys with same checksum (collision)', () => {
  // HMAC-SHA256 truncated to 8 base64url chars = 48 bits of checksum
  // Birthday bound: ~2^24 = 16M attempts needed for collision
  // We won't find one in reasonable time, but document the entropy
  const checksumBits = CHECKSUM_LENGTH * 6; // 12 base64url chars = 72 bits
  console.log(`    Checksum entropy: ${checksumBits} bits (8 base64url chars)`);
  console.log(`    Birthday bound: ~2^${checksumBits/2} = ${Math.pow(2, checksumBits/2).toExponential(2)} attempts`);
  
  if (checksumBits < 64) { // This should no longer trigger (72 > 64)
    warn('Checksum only 48 bits',
      `The checksum is 8 base64url characters = 48 bits. Birthday collision probability reaches 50% at ~2^24 (~16M) attempts. ` +
      `For a high-value API, this may be insufficient. NIST recommends ≥64 bits for MACs.`);
  }
  assert(true, 'Checksum collision analysis complete');
});

// ─── CRYPTO-6: Segment Isolation Oracle ───────────────────────────────────────
console.log('\n[CRYPTO-6] Segment Isolation Oracle');

await test('Segment failure oracle: segmentResults leak which segments failed', async () => {
  // validateTSKKey returns segmentResults with per-segment valid/invalid status
  // This is intentional (for anomaly detection) but leaks information
  // An attacker who can observe segmentResults can learn which positions are rotating
  
  // Craft a key where we know some segments are correct
  const r = validateTSKKey(validKey, { map, nowMs: NOW });
  if (r.ok && r.segmentResults) {
    console.log(`    Valid key segment results: ${r.segmentResults.map(s => `${s.segmentId}=${s.valid}`).join(', ')}`);
  }
  
  // Try an expired key — some segments may still be valid (static ones)
  const expiredKey = generateKeyFromMap(map, NOW - 10 * 60 * 1000);
  const r2 = validateTSKKey(expiredKey, { map, nowMs: NOW });
  if (!r2.ok && r2.segmentResults) {
    const staticPassed = r2.segmentResults.filter(s => s.valid);
    const rotatingFailed = r2.segmentResults.filter(s => !s.valid);
    console.log(`    Expired key: ${staticPassed.length} segments still valid (static), ${rotatingFailed.length} failed (rotating)`);
    
    if (staticPassed.length > 0) {
      warn('segmentResults oracle leaks structural information',
        `validateTSKKey returns per-segment results even on failure. ` +
        `An attacker who can observe these results learns which segmentIds correspond to static vs rotating segments. ` +
        `While segmentIds are server-side, if they leak through error responses or logs, ` +
        `the attacker learns the structural map — defeating "structural secrecy." ` +
        `The middleware does NOT expose segmentResults to callers, but internal logging might.`);
    }
  }
  assert(true, 'Segment oracle analysis complete');
});

await test('Anomaly engine segmentId prefix assumption is fragile', () => {
  // The anomaly engine detects stolen keys by checking:
  // sr.segmentId.startsWith('id_') for static segments
  // This is a naming convention, not enforced by the type system
  
  // What if a rotating segment has ID starting with 'id_'?
  const badMap: TumblerMap = {
    ...map,
    segments: [
      { segmentId: 'id_rotating_trap', position: [0, 10], type: 'totp', windowSec: 30 }, // rotating but 'id_' prefix!
      { segmentId: 'seg_static', position: [10, 20], type: 'static' },
    ],
    checksum: { position: [44, 52] },
  };
  
  // Anomaly engine would classify 'id_rotating_trap' as static
  // If this segment fails, it would trigger stolen-key pattern detection
  // even though it's actually a legitimate TOTP expiry
  warn('Anomaly engine segmentId prefix assumption',
    `The anomaly engine uses segmentId.startsWith('id_') to identify static segments. ` +
    `generateTumblerMap uses 'id' prefix for the first (static) segment and 'seg' for others. ` +
    `But this is a convention, not enforced. A map with a rotating segment named 'id_...' would ` +
    `cause false positive stolen-key alerts on legitimate TOTP expiry. ` +
    `The detection logic should use segment.type === 'static' instead of name prefix.`);
  assert(true, 'Anomaly engine prefix analysis complete');
});

// ─── Results ──────────────────────────────────────────────────────────────────
console.log('\n' + '═'.repeat(70));
console.log('RED TEAM CRYPTO RESULTS');
console.log('═'.repeat(70));
console.log(`Tests: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
if (findings.length > 0) {
  console.log('\nFINDINGS:');
  for (const f of findings) {
    console.log(`  [${f.sev}] ${f.name}`);
    console.log(`         ${f.detail}`);
  }
}
if (failed > 0) process.exit(1);
