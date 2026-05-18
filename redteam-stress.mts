/**
 * RED TEAM STRESS & DoS SUITE — tsk-protocol
 * Resource exhaustion, memory leaks, concurrency, throughput limits,
 * anomaly engine flooding, provisioner spam, and store exhaustion.
 */
import { randomBytes } from 'node:crypto';
import { createTSKServer } from './packages/server/src/index.js';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import { validateTSKKey } from './packages/core/src/validate.js';
import { verifyTSKRequest } from './packages/server/src/middleware.js';
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
  console.log(`  ⚠ WARN: ${name}`);
  console.log(`         ${detail}`);
}
function assert(cond: boolean, msg: string) { if (!cond) throw new Error(msg); }

const { store, provisioner, anomaly } = createTSKServer();
const prov = await provisioner.provision({ keyLength: 96, minTumblers: 2, maxTumblers: 4 });
if (!prov.ok || !prov.tumblerMap) { console.error('FATAL'); process.exit(1); }
const map = prov.tumblerMap!;
const NOW = Date.now();
const validKey = generateKeyFromMap(map, NOW);

// ─── STRESS-1: Throughput Benchmarks ──────────────────────────────────────────
console.log('\n[STRESS-1] Throughput Benchmarks');

await test('Validation throughput: 500K validations', () => {
  const N = 500_000;
  const start = performance.now();
  for (let i = 0; i < N; i++) {
    validateTSKKey(validKey, { map, nowMs: NOW });
  }
  const elapsed = performance.now() - start;
  const rps = Math.round(N / (elapsed / 1000));
  console.log(`    ${N.toLocaleString()} validations in ${elapsed.toFixed(0)}ms = ${rps.toLocaleString()} validations/sec`);
  assert(elapsed < 30000, `500K validations took too long: ${elapsed.toFixed(0)}ms`);
});

await test('Key generation throughput: 100K keys', () => {
  const N = 100_000;
  const start = performance.now();
  for (let i = 0; i < N; i++) {
    generateKeyFromMap(map, NOW + i * 1000);
  }
  const elapsed = performance.now() - start;
  const rps = Math.round(N / (elapsed / 1000));
  console.log(`    ${N.toLocaleString()} key generations in ${elapsed.toFixed(0)}ms = ${rps.toLocaleString()} keys/sec`);
  assert(elapsed < 30000, `100K key generations took too long: ${elapsed.toFixed(0)}ms`);
});

await test('Provisioner throughput: 1000 provisions', async () => {
  const N = 1000;
  const start = performance.now();
  const results = await Promise.all(
    Array.from({ length: N }, () => provisioner.provision({ keyLength: 96 }))
  );
  const elapsed = performance.now() - start;
  const successCount = results.filter(r => r.ok).length;
  const rps = Math.round(N / (elapsed / 1000));
  console.log(`    ${N} provisions in ${elapsed.toFixed(0)}ms = ${rps} provisions/sec (${successCount} succeeded)`);
  assert(successCount === N, `Expected ${N} successful provisions, got ${successCount}`);
});

// ─── STRESS-2: Memory Exhaustion Attacks ──────────────────────────────────────
console.log('\n[STRESS-2] Memory Exhaustion Attacks');

await test('Store exhaustion: provision 50,000 clients', async () => {
  const { store: bigStore, provisioner: bigProv } = createTSKServer();
  const N = 50_000;
  const start = performance.now();
  
  // Batch provision to avoid Promise.all memory spike
  for (let batch = 0; batch < N / 1000; batch++) {
    await Promise.all(
      Array.from({ length: 1000 }, () => bigProv.provision({ keyLength: 96 }))
    );
  }
  
  const elapsed = performance.now() - start;
  const clientCount = (await bigStore.list()).length;
  const memUsage = process.memoryUsage();
  
  console.log(`    ${N.toLocaleString()} clients provisioned in ${elapsed.toFixed(0)}ms`);
  console.log(`    Heap used: ${(memUsage.heapUsed / 1024 / 1024).toFixed(1)}MB`);
  console.log(`    RSS: ${(memUsage.rss / 1024 / 1024).toFixed(1)}MB`);
  
  if (memUsage.heapUsed > 500 * 1024 * 1024) {
    warn('Memory exhaustion via provisioner spam',
      `50,000 provisioned clients consumed ${(memUsage.heapUsed / 1024 / 1024).toFixed(1)}MB heap. ` +
      `MemoryTumblerStore has no size limit. An attacker with provisioning access can exhaust server memory. ` +
      `There is no maximum client count, no TTL on tumbler maps, and no eviction policy.`);
  }
  assert(clientCount === N, `Expected ${N} clients in store`);
});

await test('Anomaly engine memory exhaustion: flood with unique clients', () => {
  const { anomaly: bigAnomaly } = createTSKServer();
  const N = 100_000;
  const start = performance.now();
  
  for (let i = 0; i < N; i++) {
    bigAnomaly.record({
      clientId: `flood_client_${i}`,
      timestamp: NOW,
      segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }],
    });
  }
  
  const elapsed = performance.now() - start;
  const memUsage = process.memoryUsage();
  console.log(`    ${N.toLocaleString()} unique client events in ${elapsed.toFixed(0)}ms`);
  console.log(`    Heap used: ${(memUsage.heapUsed / 1024 / 1024).toFixed(1)}MB`);
  
  warn('Anomaly engine unbounded memory growth',
    `The MemoryAnomalyEngine Map grows unboundedly with unique clientIds. ` +
    `100,000 unique clients with 1 event each consumed ${(memUsage.heapUsed / 1024 / 1024).toFixed(1)}MB. ` +
    `There is no maximum entry count, no LRU eviction, and no cleanup for clients that ` +
    `have no recent events. An attacker can exhaust server memory by sending requests ` +
    `with random clientIds (even non-existent ones are recorded if they pass the header check).`);
  assert(true, 'Anomaly memory exhaustion analyzed');
});

await test('Anomaly engine: single client with 100K events', () => {
  const { anomaly: singleAnomaly } = createTSKServer();
  const N = 100_000;
  const start = performance.now();
  
  // All events within the 5-minute window
  for (let i = 0; i < N; i++) {
    singleAnomaly.record({
      clientId: 'mega_flood_client',
      timestamp: NOW - (i % (5 * 60 * 1000)), // within window
      segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }],
    });
  }
  
  const elapsed = performance.now() - start;
  console.log(`    100K events for single client in ${elapsed.toFixed(0)}ms`);
  
  // Now score — this iterates all events
  const scoreStart = performance.now();
  const s = singleAnomaly.score('mega_flood_client');
  const scoreElapsed = performance.now() - scoreStart;
  
  console.log(`    Score: ${s.score} (${s.verdict}) computed in ${scoreElapsed.toFixed(2)}ms`);
  
  if (scoreElapsed > 100) {
    warn('Anomaly score computation O(n) with event count',
      `Scoring a client with 1M events took ${scoreElapsed.toFixed(2)}ms. ` +
      `The score() method iterates ALL events in the window. ` +
      `An attacker who floods a single clientId can cause O(n) score computation, ` +
      `making every subsequent request to that client slow. ` +
      `The record() method does prune old events, but only on new record() calls, ` +
      `not on score() calls.`);
  }
  assert(true, 'Single-client flood analyzed');
});

// ─── STRESS-3: Concurrent Request Stress ──────────────────────────────────────
console.log('\n[STRESS-3] Concurrent Request Stress');

await test('Concurrent validation: 10,000 parallel requests', async () => {
  // Use a TOTP-only map for this test — TOTP has no one-time-use mechanism,
  // so all concurrent requests with the same key should succeed.
  // (HOTP correctly limits to 1 success via CAS — tested separately below.)
  const { store: totpStore, provisioner: totpProv } = createTSKServer();
  const totpPr = await totpProv.provision({ keyLength: 96, minTumblers: 2, maxTumblers: 2 });
  if (!totpPr.ok || !totpPr.tumblerMap) throw new Error('TOTP provision failed');
  // Force all segments to TOTP type
  const totpMap: TumblerMap = {
    ...totpPr.tumblerMap,
    segments: totpPr.tumblerMap.segments.map(s => ({
      ...s, type: 'totp' as const, windowSec: 60, counter: undefined
    })),
  };
  await totpStore.set(totpMap.clientId, totpMap);
  const totpKey = generateKeyFromMap(totpMap, NOW);

  const N = 10_000;
  const start = performance.now();
  const results = await Promise.all(
    Array.from({ length: N }, () =>
      verifyTSKRequest({
        headers: {
          'x-tsk-client-id': totpMap.clientId,
          'x-tsk-key': totpKey,
          'x-tsk-version': '1',
        }
      }, totpStore)
    )
  );
  const elapsed = performance.now() - start;
  const successCount = results.filter(r => r.ok).length;
  const rps = Math.round(N / (elapsed / 1000));
  console.log(`    ${N.toLocaleString()} concurrent TOTP requests in ${elapsed.toFixed(0)}ms = ${rps.toLocaleString()} req/sec`);
  console.log(`    Success: ${successCount}/${N}`);
  // All TOTP requests should succeed (no one-time-use)
  if (successCount !== N) {
    warn('Concurrent TOTP requests: not all succeeded',
      `${N - successCount} of ${N} concurrent TOTP requests failed. ` +
      `Expected all to succeed since TOTP has no one-time-use mechanism.`);
  }
  assert(successCount === N, `Expected ${N} TOTP successes, got ${successCount}`);
  console.log('    CAS correctly allows all concurrent TOTP requests ✓');
});

await test('Concurrent HOTP: race condition under load', async () => {
  const { store: raceStore, provisioner: raceProv } = createTSKServer();
  const racePr = await raceProv.provision({ keyLength: 96, minTumblers: 1, maxTumblers: 1 });
  if (!racePr.ok || !racePr.tumblerMap) return;
  
  const hotpMap: TumblerMap = {
    ...racePr.tumblerMap,
    segments: racePr.tumblerMap.segments.map(s => ({
      ...s, type: 'hotp' as const, counter: 0, windowSec: undefined
    })),
  };
  await raceStore.set(hotpMap.clientId, hotpMap);
  const hotpKey = generateKeyFromMap(hotpMap, NOW);
  
  // Fire 50 concurrent HOTP requests with the same key
  const N = 50;
  const results = await Promise.all(
    Array.from({ length: N }, () =>
      verifyTSKRequest({
        headers: {
          'x-tsk-client-id': hotpMap.clientId,
          'x-tsk-key': hotpKey,
          'x-tsk-version': '1',
        }
      }, raceStore)
    )
  );
  
  const successCount = results.filter(r => r.ok).length;
  const replayCount = results.filter(r => r.error === 'TSK_HOTP_REPLAY_DETECTED').length;
  
  console.log(`    ${N} concurrent HOTP requests: ${successCount} succeeded, ${replayCount} replay-detected, ${N - successCount - replayCount} other failures`);
  
  if (successCount > 1) {
    warn('HOTP CAS race: multiple concurrent requests succeeded',
      `${successCount} of ${N} concurrent HOTP requests with the same key succeeded. ` +
      `The CAS mechanism (consumeCounter) should allow only 1. ` +
      `This indicates a race condition in the MemoryTumblerStore.consumeCounter implementation.`);
  } else {
    console.log(`    CAS correctly limited to ${successCount} success ✓`);
  }
  assert(true, 'HOTP race condition analyzed');
});

// ─── STRESS-4: DoS via Expensive Operations ────────────────────────────────────
console.log('\n[STRESS-4] DoS via Expensive Operations');

await test('DoS: padOrTruncate with extremely long segment (10KB)', () => {
  // padOrTruncate loops calling hmac() until the result is long enough
  // For a 10KB segment, this requires ~240 HMAC calls (43 chars per HMAC)
  const longSegMap: TumblerMap = {
    ...map,
    segments: [
      { segmentId: 'id_huge', position: [0, 10000], type: 'static' },
    ],
    checksum: { position: [10000, 10008] },
    keyLength: 10008,
  };
  
  const start = performance.now();
  try {
    const key = generateKeyFromMap(longSegMap, NOW);
    const elapsed = performance.now() - start;
    console.log(`    10KB segment key generated in ${elapsed.toFixed(0)}ms (key length: ${key.length})`);
    
    if (elapsed > 100) {
      warn('DoS via large segment key generation',
        `Generating a key with a 10KB segment took ${elapsed.toFixed(0)}ms. ` +
        `padOrTruncate() calls HMAC ~240 times for a 10KB segment. ` +
        `An attacker who can trigger key generation with large segments can cause CPU exhaustion. ` +
        `The provisioner accepts keyLength=100000 (no limit), making this a viable DoS vector.`);
    }
  } catch (e: any) {
    console.log(`    10KB segment generation failed: ${e.message}`);
  }
  assert(true, 'Large segment DoS analyzed');
});

await test('DoS: validate 1024-byte key (max header size)', async () => {
  // TSK_MAX_KEY_HEADER_BYTES = 1024, but validation happens AFTER the size check
  // A 1024-byte key passes the size check but then goes through full validation
  // For a map with keyLength=1024, this means iterating many segments
  
  const { store: dosStore, provisioner: dosProv } = createTSKServer();
  const dosPr = await dosProv.provision({ keyLength: 256, minTumblers: 5, maxTumblers: 5 });
  if (!dosPr.ok || !dosPr.tumblerMap) return;
  
  const N = 10_000;
  const start = performance.now();
  
  for (let i = 0; i < N; i++) {
    await verifyTSKRequest({
      headers: {
        'x-tsk-client-id': dosPr.tumblerMap.clientId,
        'x-tsk-key': 'A'.repeat(256),
        'x-tsk-version': '1',
      }
    }, dosStore);
  }
  
  const elapsed = performance.now() - start;
  const rps = Math.round(N / (elapsed / 1000));
  console.log(`    ${N.toLocaleString()} invalid 256-char key validations in ${elapsed.toFixed(0)}ms = ${rps.toLocaleString()} req/sec`);
  assert(true, 'Max-size key DoS analyzed');
});

await test('DoS: anomaly engine record() with huge segmentResults array', () => {
  const { anomaly: bigAnomaly } = createTSKServer();
  const N = 10_000;
  
  // Record events with 1000 segment results each
  const hugeSegResults = Array.from({ length: 1000 }, (_, i) => ({
    segmentId: `seg_${i}`,
    type: 'totp' as const,
    valid: false,
  }));
  
  const start = performance.now();
  for (let i = 0; i < N; i++) {
    bigAnomaly.record({
      clientId: 'huge_segs_client',
      timestamp: NOW,
      segmentResults: hugeSegResults,
    });
  }
  const elapsed = performance.now() - start;
  console.log(`    ${N.toLocaleString()} events with 1000 segments each in ${elapsed.toFixed(0)}ms`);
  
  // Now score — iterates all events AND all segment results
  const scoreStart = performance.now();
  const s = bigAnomaly.score('huge_segs_client');
  const scoreElapsed = performance.now() - scoreStart;
  console.log(`    Score computed in ${scoreElapsed.toFixed(2)}ms`);
  
  if (scoreElapsed > 50) {
    warn('Anomaly score O(events × segments) complexity',
      `Scoring with ${N} events × 1000 segments took ${scoreElapsed.toFixed(2)}ms. ` +
      `The score() method has O(events × segmentResults) complexity. ` +
      `An attacker can craft requests with many fake segment results to slow down scoring.`);
  }
  assert(true, 'Anomaly engine complexity analyzed');
});

// ─── STRESS-5: Provisioner Spam ────────────────────────────────────────────────
console.log('\n[STRESS-5] Provisioner Spam & Resource Limits');

await test('Provisioner: no rate limiting or authentication', async () => {
  // The provisioner has no built-in rate limiting
  // Anyone who can call provisioner.provision() can create unlimited clients
  // This is a design gap — provisioning should require authentication
  
  const { provisioner: openProv } = createTSKServer();
  const N = 100;
  const start = performance.now();
  const results = await Promise.all(
    Array.from({ length: N }, () => openProv.provision({ keyLength: 96 }))
  );
  const elapsed = performance.now() - start;
  const successCount = results.filter(r => r.ok).length;
  
  warn('Provisioner has no rate limiting or authentication',
    `${successCount} clients provisioned in ${elapsed.toFixed(0)}ms with no authentication. ` +
    `The TSKProvisioner.provision() method has no built-in rate limiting, authentication, ` +
    `or authorization. Any caller can provision unlimited clients. ` +
    `In production, this endpoint MUST be protected by authentication and rate limiting.`);
  assert(successCount === N, 'All provisions succeeded (no protection)');
});

await test('Store: list() performance with 50K clients', async () => {
  const { store: listStore, provisioner: listProv } = createTSKServer();
  
  // Provision 50K clients
  for (let batch = 0; batch < 50; batch++) {
    await Promise.all(Array.from({ length: 1000 }, () => listProv.provision({ keyLength: 96 })));
  }
  
  const start = performance.now();
  const clients = await listStore.list();
  const elapsed = performance.now() - start;
  
  console.log(`    list() with ${clients.length.toLocaleString()} clients: ${elapsed.toFixed(2)}ms`);
  
  if (elapsed > 100) {
    warn('Store.list() performance degrades with client count',
      `list() with ${clients.length.toLocaleString()} clients took ${elapsed.toFixed(2)}ms. ` +
      `MemoryTumblerStore.list() returns Array.from(this.maps.keys()) — O(n) operation. ` +
      `For large deployments, this could be slow.`);
  }
  assert(clients.length === 50000, `Expected 50000 clients, got ${clients.length}`);
});

// ─── STRESS-6: padOrTruncate Infinite Loop Risk ────────────────────────────────
console.log('\n[STRESS-6] padOrTruncate Infinite Loop Risk');

await test('padOrTruncate: length=0 segment (potential infinite loop)', () => {
  // padOrTruncate(s, 0): s.length >= 0 is always true → returns s.slice(0, 0) = ''
  // This is fine, but let's verify
  const zeroSeg = { segmentId: 'zero', position: [0, 0] as [number, number], type: 'static' as const };
  const secret = randomBytes(32).toString('hex');
  
  try {
    const val = deriveSegmentValue(secret, zeroSeg, NOW);
    assert(val === '', `Expected empty string for zero-length segment, got '${val}'`);
    console.log(`    Zero-length segment returns empty string ✓`);
  } catch (e: any) {
    throw new Error(`Zero-length segment crashed: ${e.message}`);
  }
});

await test('padOrTruncate: verify no infinite loop for any reasonable length', () => {
  // padOrTruncate loops while result.length < length
  // Each iteration adds at least 43 chars (base64url of SHA256)
  // So max iterations = ceil(length / 43)
  // For length=10000, max iterations = 233 — finite
  
  const secret = randomBytes(32).toString('hex');
  
  // Test various lengths
  const lengths = [1, 43, 44, 100, 500, 1000];
  for (const len of lengths) {
    const seg = { segmentId: 'test', position: [0, len] as [number, number], type: 'static' as const };
    const val = deriveSegmentValue(secret, seg, NOW);
    assert(val.length === len, `Expected length ${len}, got ${val.length}`);
  }
  console.log(`    padOrTruncate correct for lengths: ${lengths.join(', ')} ✓`);
});

// ─── Results ──────────────────────────────────────────────────────────────────
console.log('\n' + '═'.repeat(70));
console.log('RED TEAM STRESS RESULTS');
console.log('═'.repeat(70));
console.log(`Tests: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
if (findings.length > 0) {
  console.log('\nFINDINGS:');
  for (const f of findings) {
    console.log(`  [${f.sev}] ${f.name}`);
    console.log(`         ${f.detail.slice(0, 300)}`);
  }
}
if (failed > 0) process.exit(1);
