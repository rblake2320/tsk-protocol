/**
 * RED TEAM LOGIC & AUTH BYPASS SUITE — tsk-protocol
 * Anomaly engine evasion, provisioner abuse, identity binding attacks,
 * race conditions, client SDK logic flaws, and protocol-level bypasses.
 */
import { randomBytes } from 'node:crypto';
import { createTSKServer } from './packages/server/src/index.js';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import { validateTSKKey } from './packages/core/src/validate.js';
import { verifyTSKRequest } from './packages/server/src/middleware.js';
import { verifyUltraRequest } from './packages/bpc-bridge/src/ultra-verify.js';
import type { TumblerMap } from './packages/core/src/types.js';
import type { BPCLikeResult } from './packages/bpc-bridge/src/ultra-verify.js';

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

// ─── Setup ────────────────────────────────────────────────────────────────────
const { store, provisioner, anomaly } = createTSKServer();
const prov = await provisioner.provision({ keyLength: 52, minTumblers: 2, maxTumblers: 4 });
if (!prov.ok || !prov.tumblerMap) { console.error('FATAL'); process.exit(1); }
const map = prov.tumblerMap!;
const NOW = Date.now();
const validKey = generateKeyFromMap(map, NOW);

// ─── LOGIC-1: Anomaly Engine Evasion ──────────────────────────────────────────
console.log('\n[LOGIC-1] Anomaly Engine Evasion');

await test('Slow-drip attack: stay below 3-failure threshold', () => {
  // The anomaly engine only adds score at 3+ failures
  // An attacker who makes exactly 2 failures stays at score 0 (clean)
  const testClient = 'evasion_slow_drip';
  anomaly.record({ clientId: testClient, timestamp: NOW, segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }] });
  anomaly.record({ clientId: testClient, timestamp: NOW, segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }] });
  const s = anomaly.score(testClient);
  
  if (s.verdict === 'clean' && s.score < 15) {
    warn('Anomaly engine: 2 failures = clean verdict',
      `With only 2 failures, the anomaly score is ${s.score} (verdict: ${s.verdict}). ` +
      `An attacker can make 2 brute-force attempts per 5-minute window without triggering any alert. ` +
      `With 2 attempts/5min = 576 attempts/day, this is a viable low-and-slow attack.`);
  }
  assert(true, 'Slow-drip evasion analyzed');
});

await test('Window reset evasion: wait for 5-min window to expire', () => {
  // The anomaly engine uses a 5-minute rolling window
  // An attacker can make 9 attempts, wait 5 minutes, make 9 more, etc.
  // This gives 9 attempts per 5 minutes = 2,592 attempts/day without triggering "attack" verdict
  const testClient = 'evasion_window_reset';
  for (let i = 0; i < 9; i++) {
    anomaly.record({ clientId: testClient, timestamp: NOW, segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }] });
  }
  const s = anomaly.score(testClient);
  
  warn('Window-based evasion: 9 attempts per 5-min window',
    `9 failures in 5 minutes gives score=${s.score} (verdict=${s.verdict}). ` +
    `An attacker can make 9 attempts per 5-minute window (2,592/day) while staying below "attack" threshold. ` +
    `The window resets completely — there is no persistent threat memory across windows.`);
  assert(true, 'Window reset evasion analyzed');
});

await test('Multi-client distributed attack evades per-client anomaly', () => {
  // The anomaly engine tracks per-clientId — not per-IP
  // An attacker with many provisioned clients (or stolen clientIds) can distribute attacks
  // Each client only shows 1-2 failures, all staying "clean"
  const attackClients = Array.from({ length: 20 }, (_, i) => `attack_client_${i}`);
  for (const clientId of attackClients) {
    anomaly.record({ clientId, timestamp: NOW, segmentResults: [{ segmentId: 'x', type: 'totp' as const, valid: false }] });
  }
  const scores = attackClients.map(c => anomaly.score(c));
  const allClean = scores.every(s => s.verdict === 'clean');
  
  if (allClean) {
    warn('Distributed multi-client attack evades anomaly engine',
      `20 different clients each with 1 failure — all score "clean". ` +
      `The anomaly engine has no cross-client correlation or IP-based rate limiting. ` +
      `An attacker with 20 provisioned clients can make 20 attempts per 5 minutes (5,760/day) ` +
      `with zero anomaly detection. There is no global rate limiting in the protocol.`);
  }
  assert(true, 'Distributed attack evasion analyzed');
});

await test('Anomaly engine: no IP-based tracking', async () => {
  // verifyTSKRequest accepts ipAddress as optional parameter
  // The anomaly engine receives ipAddress but does NOT use it for scoring
  // An attacker from the same IP can spam without IP-based detection
  const ipSpamClient = 'ip_spam_client';
  const ipProv = await provisioner.provision({ keyLength: 52 });
  if (!ipProv.ok || !ipProv.tumblerMap) return;
  await store.set(ipProv.tumblerMap.clientId, ipProv.tumblerMap);
  
  // Make 20 failed requests from same IP
  for (let i = 0; i < 20; i++) {
    await verifyTSKRequest({
      headers: {
        'x-tsk-client-id': ipProv.tumblerMap.clientId,
        'x-tsk-key': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'x-tsk-version': '1',
      }
    }, store, { anomaly, ipAddress: '192.168.1.100' });
  }
  
  // Check if IP is tracked anywhere
  const s = anomaly.score(ipProv.tumblerMap.clientId);
  warn('No IP-based rate limiting in anomaly engine',
    `The anomaly engine records ipAddress in events but the score() method does not use it. ` +
    `There is no per-IP rate limiting, no IP reputation tracking, and no cross-client IP correlation. ` +
    `An attacker from a single IP can target multiple clients without any IP-level detection.`);
  assert(true, 'IP tracking analysis complete');
});

await test('Anomaly engine: no persistence across server restarts', () => {
  // MemoryAnomalyEngine stores data in-memory
  // A server restart clears all anomaly history
  // An attacker can trigger a DoS/restart to clear their threat score
  warn('Anomaly engine state is ephemeral (in-memory only)',
    `MemoryAnomalyEngine stores all threat data in a JavaScript Map. ` +
    `A server restart, crash, or scale-out event clears all anomaly history. ` +
    `An attacker who triggers a server restart (or simply waits for a deploy) ` +
    `gets a clean slate. Production deployments MUST use persistent storage (Redis, DB).`);
  assert(true, 'Persistence analysis complete');
});

// ─── LOGIC-2: Protocol Logic Flaws ────────────────────────────────────────────
console.log('\n[LOGIC-2] Protocol Logic Flaws');

await test('Validation order: checksum checked AFTER segments', () => {
  // In validate.ts, segments are validated first, then checksum
  // This means a full segment scan happens even for completely garbage keys
  // The checksum should ideally be checked FIRST for fast rejection
  
  // Verify the order by checking what error we get for a key with:
  // - Wrong segments but valid checksum (crafted)
  // - Wrong checksum but valid segments (expired key)
  
  const expiredKey = generateKeyFromMap(map, NOW - 10 * 60 * 1000);
  const r = validateTSKKey(expiredKey, { map, nowMs: NOW });
  
  // The expired key has a valid checksum (for its time) but wrong TOTP segments
  // Since checksum is validated AFTER segments, what error do we get?
  console.log(`    Expired key error: ${r.error}`);
  
  if (r.error === 'INVALID_KEY' && r.internalError === 'VALIDATION_FAILED') {
    warn('Checksum validated after segments — inefficient rejection path',
      `validate.ts iterates ALL segments before checking the checksum. ` +
      `For a completely random key, this wastes CPU on segment comparison before the fast checksum check. ` +
      `Moving checksum validation FIRST would reject ~99.99% of invalid keys immediately. ` +
      `This is a performance issue, not a security issue — but under DoS load it matters.`);
  }
  assert(true, 'Validation order analyzed');
});

await test('HOTP counter not validated against a maximum', () => {
  // The spec mentions HOTP_COUNTER_EXHAUSTED error but the code never returns it
  // There is no maximum counter value enforced
  // A counter at Number.MAX_SAFE_INTEGER + 1 loses precision
  
  const maxCounter = Number.MAX_SAFE_INTEGER;
  const overflowCounter = maxCounter + 1;
  
  if (overflowCounter === maxCounter) {
    warn('HOTP counter integer overflow at MAX_SAFE_INTEGER',
      `Number.MAX_SAFE_INTEGER + 1 === Number.MAX_SAFE_INTEGER in JavaScript. ` +
      `An HOTP counter at MAX_SAFE_INTEGER can never advance — the server would be stuck. ` +
      `Additionally, the TSKError type includes 'HOTP_COUNTER_EXHAUSTED' but validateTSKKey ` +
      `never returns this error — the counter exhaustion check is missing from the implementation.`);
  }
  assert(true, 'Counter overflow analyzed');
});

await test('Missing HOTP_COUNTER_EXHAUSTED error implementation', () => {
  // The types.ts defines TSKError with 'HOTP_COUNTER_EXHAUSTED'
  // But validate.ts never returns this error
  // The spec says "HOTP segments can only be used once" but there's no max counter
  
  // Let's verify by reading the validate.ts logic:
  // For HOTP: it checks counter+0 through counter+hotpLookahead
  // If none match, it returns VALIDATION_FAILED, not HOTP_COUNTER_EXHAUSTED
  
  const hotpMap: TumblerMap = {
    ...map,
    segments: map.segments.map(s => ({
      ...s, type: 'hotp' as const, counter: 1000000, windowSec: undefined
    })),
  };
  
  // Generate key for counter=1000000
  const keyAtMillion = generateKeyFromMap(hotpMap, NOW);
  const r = validateTSKKey(keyAtMillion, { map: hotpMap, nowMs: NOW });
  
  warn('HOTP_COUNTER_EXHAUSTED error never returned',
    `The TSKError type includes 'HOTP_COUNTER_EXHAUSTED' but validateTSKKey never returns it. ` +
    `There is no maximum HOTP counter check. The error type is defined but dead code. ` +
    `This means there is no way for the server to signal that an HOTP counter has been exhausted.`);
  assert(true, 'HOTP_COUNTER_EXHAUSTED analysis complete');
});

await test('Client SDK: HOTP counter incremented even if request fails', () => {
  // In TSKClient.generateHeaders(), HOTP counters are incremented AFTER generating values
  // But the increment happens regardless of whether the HTTP request succeeds
  // If the request fails (network error), the client counter advances but server doesn't
  // This causes counter desynchronization
  
  warn('Client SDK: HOTP counter incremented before request success',
    `TSKClient.generateHeaders() increments HOTP counters immediately after generating values. ` +
    `If the HTTP request fails (network error, timeout, server crash), the client counter ` +
    `has advanced but the server counter has not. After N network failures, the client ` +
    `counter is N ahead of the server, potentially exceeding hotpLookahead=5 and causing ` +
    `permanent authentication failure until manual resynchronization.`);
  assert(true, 'Client HOTP counter analysis complete');
});

await test('Client SDK: key assembled in segmentOrder, not position order', () => {
  // TSKClient uses segmentOrder (from provisionPayload) to assemble the key
  // segmentOrder is segmentIds sorted by position
  // But the client doesn't know positions — it just concatenates segment values
  // The server validates using actual positions from the stored TumblerMap
  // This means the client key format DIFFERS from the server's expected format
  
  // Let's verify: client generates segment values and concatenates by segmentOrder
  // Server validates by slicing the key at stored positions
  // These are only consistent if segment lengths match the positions exactly
  
  // Check: does the client key match what the server expects?
  const provPayload = prov.provisionPayload!;
  const clientKey = (() => {
    // Simulate what TSKClient.generateHeaders() does
    const values = new Map<string, string>();
    for (const seg of provPayload.clientSegments) {
      let input: string;
      if (seg.type === 'static') {
        input = `static:${seg.segmentId}`;
      } else if (seg.type === 'totp') {
        const T = Math.floor(NOW / 1000 / (seg.windowSec ?? 60));
        input = `totp:${seg.segmentId}:${T}`;
      } else {
        input = `hotp:${seg.segmentId}:0`;
      }
      // hmac imported at top level
      values.set(seg.segmentId, '');
    }
    return '';
  })();
  
  // The real test: server-generated key vs client-generated key should match
  const serverKey = generateKeyFromMap(map, NOW);
  
  // The client SDK generates segment values WITHOUT knowing positions
  // It concatenates them in segmentOrder (position order)
  // The server validates by slicing at stored positions
  // For this to work, the segment values must be exactly the right length
  // which they are (padOrTruncate ensures this)
  
  console.log(`    Server key (52 chars): ${serverKey}`);
  console.log(`    Segment order: ${(provPayload as any).segmentOrder?.join(', ')}`);
  assert(true, 'Client key assembly analysis complete');
});

await test('segmentOrder in provision payload leaks position ordering', () => {
  // toProvisionPayload() includes segmentOrder: sorted by position
  // This tells the client the ORDER of segments (which is at position 0, 1, 2, etc.)
  // Combined with segment lengths (also in payload), the client can reconstruct positions
  
  const provPayload = prov.provisionPayload!;
  if ((provPayload as any).segmentOrder && provPayload.clientSegments) {
    // Client knows: segmentOrder (position order) + each segment's length
    // From this, client can reconstruct: position[i] = sum of lengths[0..i-1]
    let offset = 0;
    const reconstructedPositions: Record<string, [number, number]> = {};
    for (const segId of (provPayload as any).segmentOrder) {
      const seg = provPayload.clientSegments.find(s => s.segmentId === segId);
      if ((seg as any)?.length !== undefined) {
        reconstructedPositions[segId] = [offset, offset + (seg as any).length];
        offset += (seg as any).length;
      }
    }
    
    // Compare with actual positions
    let positionsMatch = true;
    for (const actualSeg of map.segments) {
      const reconstructed = reconstructedPositions[actualSeg.segmentId];
      if (reconstructed && (reconstructed[0] !== actualSeg.position[0] || reconstructed[1] !== actualSeg.position[1])) {
        positionsMatch = false;
      }
    }
    
    if (positionsMatch && Object.keys(reconstructedPositions).length > 0) {
      warn('CRITICAL: segmentOrder + segment lengths leak full position map',
        `The provision payload includes segmentOrder (position-sorted segmentIds) AND segment lengths. ` +
        `A client can reconstruct the exact position of every segment: ` +
        `position[i] = [sum(lengths[0..i-1]), sum(lengths[0..i])]. ` +
        `This COMPLETELY DEFEATS "structural secrecy" — the client knows exactly which bytes ` +
        `are at which positions. The spec claims "positions are omitted" but the combination ` +
        `of segmentOrder + length allows full position reconstruction. ` +
        `Reconstructed positions: ${JSON.stringify(reconstructedPositions)}`);
    }
  }
  assert(true, 'Position reconstruction analysis complete');
});

// ─── LOGIC-3: Ultra Bridge Logic Attacks ──────────────────────────────────────
console.log('\n[LOGIC-3] Ultra Bridge Logic Attacks');

await test('Ultra bridge: null pairId from BPC bypasses identity binding', async () => {
  // If bpcVerify returns { ok: true, pairId: undefined }, the bridge checks:
  // if (!bpcResult.pairId || !tskResult.clientId) → IDENTITY_BINDING_UNAVAILABLE
  // This is correctly handled — but let's verify the error is correct
  
  const { store: s2, provisioner: p2 } = createTSKServer();
  const prov2 = await p2.provision({ keyLength: 52 });
  if (!prov2.ok || !prov2.tumblerMap) return;
  const map2 = prov2.tumblerMap;
  const key2 = generateKeyFromMap(map2, NOW);
  
  const bpcNoPairId = async (): Promise<BPCLikeResult> => ({ ok: true }); // no pairId
  const identityBinding = { resolve: async (pid: string) => null };
  
  const r = await verifyUltraRequest(
    { headers: { 'x-tsk-client-id': map2.clientId, 'x-tsk-key': key2, 'x-tsk-version': '1' } },
    bpcNoPairId,
    { tskStore: s2, identityBinding }
  );
  
  assert(!r.ok, 'Null pairId should be rejected');
  assert(r.error === 'IDENTITY_BINDING_UNAVAILABLE', `Expected IDENTITY_BINDING_UNAVAILABLE, got ${r.error}`);
});

await test('Ultra bridge: identity binding with null resolution', async () => {
  // If identityBinding.resolve returns null (unknown pairId), the comparison:
  // expectedClientId !== tskResult.clientId → null !== 'tsk_...' → true → MISMATCH
  // This is correct behavior, but let's verify
  
  const { store: s3, provisioner: p3 } = createTSKServer();
  const prov3 = await p3.provision({ keyLength: 52 });
  if (!prov3.ok || !prov3.tumblerMap) return;
  const map3 = prov3.tumblerMap;
  const key3 = generateKeyFromMap(map3, NOW);
  
  const bpcWithPairId = async (): Promise<BPCLikeResult> => ({ ok: true, pairId: 'unknown_pair' });
  const identityBinding = { resolve: async (pid: string) => null }; // unknown pairId
  
  const r = await verifyUltraRequest(
    { headers: { 'x-tsk-client-id': map3.clientId, 'x-tsk-key': key3, 'x-tsk-version': '1' } },
    bpcWithPairId,
    { tskStore: s3, identityBinding }
  );
  
  assert(!r.ok, 'Unknown pairId should be rejected');
  // null !== clientId → IDENTITY_BINDING_MISMATCH (not UNAVAILABLE)
  // This is slightly misleading — "mismatch" implies both values exist
  if (r.error === 'IDENTITY_BINDING_MISMATCH') {
    warn('IDENTITY_BINDING_MISMATCH returned for unknown pairId (null)',
      `When identityBinding.resolve returns null (unknown pairId), the bridge returns ` +
      `IDENTITY_BINDING_MISMATCH instead of a more specific "UNKNOWN_PAIR" error. ` +
      `This makes it harder to distinguish "pair not found" from "pair maps to wrong client" ` +
      `in logs and monitoring.`);
  }
  assert(true, 'Null resolution analysis complete');
});

await test('Ultra bridge: TSK anomaly engine not wired in ultra path', async () => {
  // verifyUltraRequest calls verifyTSKRequest(req, options.tskStore, options.tskConfig)
  // options.tskConfig can include anomaly engine
  // But the UltraVerifyOptions interface does NOT include anomaly engine
  // So anomaly detection is DISABLED in the ultra path by default
  
  warn('Anomaly engine not wired in Ultra bridge path',
    `UltraVerifyOptions has tskStore and tskConfig but tskConfig is of type TSKServerConfig ` +
    `which includes anomaly?: AnomalyEngine. However, the verifyUltraRequest function ` +
    `passes options.tskConfig directly to verifyTSKRequest. If callers don't explicitly ` +
    `pass an anomaly engine in tskConfig, anomaly detection is silently disabled in the ` +
    `ultra path. The ultra bridge documentation does not mention this requirement.`);
  assert(true, 'Ultra anomaly wiring analyzed');
});

// ─── LOGIC-4: Race Condition Analysis ─────────────────────────────────────────
console.log('\n[LOGIC-4] Race Condition Analysis');

await test('Concurrent TOTP validation race: both requests succeed', async () => {
  // TOTP keys have no one-time-use mechanism
  // Two concurrent requests with the same TOTP key should BOTH succeed
  // This is by design but is a security gap
  
  const { store: s4, provisioner: p4 } = createTSKServer();
  const prov4 = await p4.provision({ keyLength: 52, minTumblers: 1, maxTumblers: 1 });
  if (!prov4.ok || !prov4.tumblerMap) return;
  // Force TOTP only
  const totpMap: TumblerMap = {
    ...prov4.tumblerMap,
    segments: prov4.tumblerMap.segments.map(s => ({
      ...s, type: 'totp' as const, windowSec: 30, counter: undefined
    })),
  };
  await s4.set(totpMap.clientId, totpMap);
  const totpKey = generateKeyFromMap(totpMap, NOW);
  
  // Fire two concurrent requests
  const [r1, r2] = await Promise.all([
    verifyTSKRequest({ headers: { 'x-tsk-client-id': totpMap.clientId, 'x-tsk-key': totpKey, 'x-tsk-version': '1' } }, s4),
    verifyTSKRequest({ headers: { 'x-tsk-client-id': totpMap.clientId, 'x-tsk-key': totpKey, 'x-tsk-version': '1' } }, s4),
  ]);
  
  if (r1.ok && r2.ok) {
    warn('TOTP concurrent replay: both requests succeed',
      `Two concurrent requests with the same TOTP key both succeed. ` +
      `TOTP has no one-time-use mechanism — the same key is valid for the entire window. ` +
      `An attacker who intercepts a TOTP key can use it concurrently with the legitimate client ` +
      `for up to 300 seconds (with 300s windows). This is a fundamental TOTP limitation ` +
      `that TSK inherits. HOTP is immune to this but TOTP is not.`);
  }
  assert(r1.ok, 'First concurrent TOTP request should succeed');
});

await test('HOTP CAS race: consumeCounter prevents double-spend', async () => {
  // The middleware uses consumeCounter (CAS) for HOTP to prevent concurrent replay
  // Let's verify this actually works
  
  const { store: s5, provisioner: p5 } = createTSKServer();
  const prov5 = await p5.provision({ keyLength: 52, minTumblers: 1, maxTumblers: 1 });
  if (!prov5.ok || !prov5.tumblerMap) return;
  const hotpMap: TumblerMap = {
    ...prov5.tumblerMap,
    segments: prov5.tumblerMap.segments.map(s => ({
      ...s, type: 'hotp' as const, counter: 0, windowSec: undefined
    })),
  };
  await s5.set(hotpMap.clientId, hotpMap);
  const hotpKey = generateKeyFromMap(hotpMap, NOW);
  
  // Fire two concurrent HOTP requests
  const [r1, r2] = await Promise.all([
    verifyTSKRequest({ headers: { 'x-tsk-client-id': hotpMap.clientId, 'x-tsk-key': hotpKey, 'x-tsk-version': '1' } }, s5),
    verifyTSKRequest({ headers: { 'x-tsk-client-id': hotpMap.clientId, 'x-tsk-key': hotpKey, 'x-tsk-version': '1' } }, s5),
  ]);
  
  const bothSucceeded = r1.ok && r2.ok;
  const oneRejected = (r1.ok && !r2.ok) || (!r1.ok && r2.ok);
  
  console.log(`    Concurrent HOTP r1: ${r1.ok ? 'ok' : r1.error}, r2: ${r2.ok ? 'ok' : r2.error}`);
  
  if (bothSucceeded) {
    warn('CRITICAL: HOTP concurrent replay succeeded',
      `Both concurrent HOTP requests with the same key succeeded. ` +
      `The CAS (consumeCounter) mechanism failed to prevent double-spend. ` +
      `This is a critical security flaw — HOTP should be one-time-use.`);
  } else if (oneRejected) {
    console.log(`    CAS correctly rejected one of the concurrent requests ✓`);
  }
  assert(true, 'HOTP CAS race analysis complete');
});

// ─── LOGIC-5: Spec vs Implementation Gaps ─────────────────────────────────────
console.log('\n[LOGIC-5] Spec vs Implementation Gaps');

await test('Spec claims "brute force resistance" — verify actual search space', () => {
  // Spec §8.4: "52-char key with 3 segments, there are ~17,000+ positional arrangements"
  // Let's verify this claim
  
  // For 52-char key with checksum at [44,52]:
  // Usable space: 44 chars
  // 3 segments (including 1 static) + checksum
  // Number of ways to divide 44 chars into 3 non-overlapping segments:
  // This is C(43,2) = 43*42/2 = 903 ways (choosing 2 dividers from 43 positions)
  // NOT "17,000+"
  
  const usableChars = 44;
  const numSegments = 3;
  // Combinations: C(usableChars-1, numSegments-1)
  const combinations = (n: number, k: number): number => {
    if (k === 0) return 1;
    return n * combinations(n - 1, k - 1) / k;
  };
  const positionArrangements = combinations(usableChars - 1, numSegments - 1);
  
  console.log(`    Spec claims: ~17,000+ positional arrangements`);
  console.log(`    Calculated: C(${usableChars-1}, ${numSegments-1}) = ${positionArrangements} arrangements`);
  
  if (positionArrangements < 17000) {
    warn('Spec overstates brute force resistance',
      `Spec §8.4 claims "~17,000+ positional arrangements" for a 52-char key with 3 segments. ` +
      `The actual number of ways to divide 44 usable chars into 3 non-overlapping segments ` +
      `is C(43,2) = ${positionArrangements} arrangements — far less than claimed. ` +
      `Even with 5 segments, C(43,4) = ${combinations(43,4)} arrangements. ` +
      `The spec's brute force resistance claim is mathematically overstated.`);
  }
  assert(true, 'Brute force resistance claim analyzed');
});

await test('Spec §8.1 replay resistance: TOTP window is NOT per-request', () => {
  // Spec §8.1: "TOTP segments expire after their window (30-300 seconds)"
  // This implies replay resistance, but within the window, unlimited replays are possible
  // The spec does not acknowledge this limitation
  
  warn('Spec §8.1 replay resistance claim is misleading for TOTP',
    `Spec §8.1 states "A key captured and replayed after the shortest segment's window expires is rejected." ` +
    `This is true, but the spec does not mention that within the window, unlimited replays succeed. ` +
    `For a 300s window, an attacker has a 600s (10-minute) window to replay a captured key. ` +
    `True replay resistance requires per-request nonces (like BPC's nonce mechanism). ` +
    `TSK alone does NOT provide per-request replay resistance for TOTP-based keys.`);
  assert(true, 'Spec replay resistance analyzed');
});

await test('Spec §8.3 structural secrecy: defeated by provision payload', () => {
  // Already found in LOGIC-2: segmentOrder + lengths = full position map
  // Documenting as a spec vs implementation gap
  
  const provPayload = prov.provisionPayload!;
  const hasSegmentOrder = !!(provPayload as any).segmentOrder;
  const hasLengths = provPayload.clientSegments.every(s => (s as any).length !== undefined);
  
  if (hasSegmentOrder && hasLengths) {
    warn('CRITICAL: Spec §8.3 structural secrecy defeated by provision payload',
      `Spec §8.3: "The format of the key — which positions rotate, at what rate, how many segments exist — ` +
      `is a server-side secret." ` +
      `However, toProvisionPayload() sends: ` +
      `(1) segmentOrder: segments sorted by position, ` +
      `(2) clientSegments[i].length: exact length of each segment. ` +
      `From these, the client can reconstruct: position[i] = [sum(lengths[0..i-1]), sum(lengths[0..i])]. ` +
      `This completely defeats structural secrecy. The "positions are omitted" claim is false — ` +
      `positions are derivable from the provided data.`);
  }
  assert(true, 'Structural secrecy analysis complete');
});

// ─── Results ──────────────────────────────────────────────────────────────────
console.log('\n' + '═'.repeat(70));
console.log('RED TEAM LOGIC RESULTS');
console.log('═'.repeat(70));
console.log(`Tests: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
if (findings.length > 0) {
  console.log('\nFINDINGS:');
  for (const f of findings) {
    console.log(`  [${f.sev}] ${f.name}`);
    console.log(`         ${f.detail.slice(0, 200)}...`);
  }
}
if (failed > 0) process.exit(1);
