/**
 * TSK + BPC Ultra Bridge — Integration Test Suite
 *
 * Tests every logical branch of verifyUltraRequest:
 *   - Happy path (BPC pass + TSK pass + identity match)
 *   - BPC layer failure
 *   - TSK layer failure after BPC passes
 *   - Identity binding mismatch (pairId → wrong clientId)
 *   - Identity binding unavailable (pairId or clientId absent)
 *   - Null identity resolution (unknown pairId)
 *   - Real TSK key generation and validation (no mocked TSK)
 *   - ULTRA_SECURITY_LAYERS contract (7 layers, correct metadata)
 *
 * Run with: npx tsx ultra-bridge-test.mts
 */

import { verifyUltraRequest, ULTRA_SECURITY_LAYERS } from './packages/bpc-bridge/src/ultra-verify.js';
import { createTSKServer } from './packages/server/src/index.js';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import { generateSharedSecret, generateClientId, generateSegmentId } from './packages/core/src/crypto.js';
import { MemoryTumblerStore } from './packages/server/src/store.js';
import type { TumblerMap } from './packages/core/src/types.js';
import type { TSKRequestData } from './packages/server/src/middleware.js';
import type { BPCLikeResult } from './packages/bpc-bridge/src/ultra-verify.js';

// ─── Test harness ─────────────────────────────────────────────────────────────

type TestResult = { name: string; passed: boolean; detail: string };
const results: TestResult[] = [];

function assert(name: string, condition: boolean, detail = '') {
  results.push({ name, passed: condition, detail });
  console.log(`  ${condition ? '✓' : '✗'} ${name}`);
  if (!condition) console.log(`    FAIL: ${detail}`);
}

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const { store, provisioner } = createTSKServer();

// Provision a real client
const provResult = await provisioner.provision({ keyLength: 52, minTumblers: 2, maxTumblers: 4 });
if (!provResult.ok || !provResult.tumblerMap) {
  console.error('FATAL: provisioner failed:', provResult.error);
  process.exit(1);
}
const map = provResult.tumblerMap;
const clientId = map.clientId;
const pairId = 'bpc_pair_test_001';

// Identity map: pairId → clientId
const identityMap = new Map<string, string>([[pairId, clientId]]);
const identityBinding = {
  resolve: async (pid: string) => identityMap.get(pid) ?? null,
};

// Build valid TSK headers for a given time
function tskHeaders(nowMs = Date.now()): Record<string, string> {
  const key = generateKeyFromMap(map, nowMs);
  return {
    'x-tsk-client-id': clientId,
    'x-tsk-key': key,
    'x-tsk-version': '1',
  };
}

// Build a request object with both BPC and TSK headers (BPC headers are fake — verified by mock)
function makeReq(extraHeaders: Record<string, string> = {}): TSKRequestData {
  return {
    headers: {
      'x-bpc-pair-id': pairId,
      'x-bpc-signature': 'fake_sig',
      'x-bpc-signed-data': 'fake_data',
      ...tskHeaders(),
      ...extraHeaders,
    },
  };
}

// BPC mock stubs
function bpcPass(pid = pairId): () => Promise<BPCLikeResult> {
  return async () => ({ ok: true, pairId: pid });
}
function bpcFail(error = 'INVALID_SIGNATURE'): () => Promise<BPCLikeResult> {
  return async () => ({ ok: false, error });
}
function bpcPassNoPairId(): () => Promise<BPCLikeResult> {
  return async () => ({ ok: true }); // pairId absent
}

// ─── Test groups ──────────────────────────────────────────────────────────────

const NOW = Date.now();

// ── Group 1: Happy path ────────────────────────────────────────────────────────
console.log('\n[1] Happy Path — BPC pass + TSK pass + identity match');
{
  const req = makeReq(tskHeaders(NOW));
  const r = await verifyUltraRequest(req, bpcPass(), { tskStore: store, identityBinding });

  assert('result.ok is true', r.ok, `Got ok=${r.ok}, error=${r.error}`);
  assert('pairId returned', r.pairId === pairId, `Got: ${r.pairId}`);
  assert('clientId returned', r.clientId === clientId, `Got: ${r.clientId}`);
  assert("layers includes 'bpc' and 'tsk'",
    r.layers.includes('bpc') && r.layers.includes('tsk'),
    `Got: ${JSON.stringify(r.layers)}`);
  assert('no error field on success', r.error === undefined, `Got error: ${r.error}`);
}

// ── Group 2: BPC layer failure ────────────────────────────────────────────────
console.log('\n[2] BPC Layer Failure — TSK never called');
{
  const req = makeReq();
  const r = await verifyUltraRequest(req, bpcFail('SIGNATURE_INVALID'), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error starts with 'BPC:'", r.error?.startsWith('BPC:') ?? false, `Got: ${r.error}`);
  assert("error includes the BPC error code", r.error?.includes('SIGNATURE_INVALID') ?? false, `Got: ${r.error}`);
  assert("layers is empty (TSK not reached)", r.layers.length === 0, `Got: ${JSON.stringify(r.layers)}`);
  assert('pairId absent when BPC fails', r.pairId === undefined, `Got: ${r.pairId}`);
}

// ── Group 3: TSK failure after BPC passes ────────────────────────────────────
console.log('\n[3] TSK Layer Failure — BPC passes, TSK key is expired');
{
  // Build a deterministic map with all-TOTP rotating segments (no HOTP randomness).
  // generateTumblerMap() has a ~9% chance of all-HOTP segments; HOTP is counter-based,
  // not time-based, so a "15-min-old" key would still be valid for all-HOTP maps.
  // We construct the map directly with known TOTP segments to guarantee expiry.
  const expiredStore = new MemoryTumblerStore();
  const expiredMap: TumblerMap = {
    clientId: generateClientId(),
    sharedSecret: generateSharedSecret(),
    keyLength: 52,
    segments: [
      { segmentId: generateSegmentId('id'),  position: [0, 12],  type: 'static' },
      { segmentId: generateSegmentId('seg'), position: [12, 24], type: 'totp', windowSec: 30 },
      { segmentId: generateSegmentId('seg'), position: [24, 36], type: 'totp', windowSec: 60 },
      { segmentId: generateSegmentId('seg'), position: [36, 44], type: 'totp', windowSec: 30 },
    ],
    checksum: { position: [44, 52] },
    createdAt: Date.now(),
    version: '1',
  };
  await expiredStore.set(expiredMap.clientId, expiredMap);

  // Generate a key 15 minutes in the past (900s >> ±1 window tolerance for 30s or 60s windows)
  const staleKey = generateKeyFromMap(expiredMap, NOW - 15 * 60_000);
  const req: TSKRequestData = {
    headers: {
      'x-tsk-client-id': expiredMap.clientId,
      'x-tsk-key': staleKey,
      'x-tsk-version': '1',
    },
  };
  const r = await verifyUltraRequest(req, bpcPass(), { tskStore: expiredStore, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error starts with 'TSK:'", r.error?.startsWith('TSK:') ?? false, `Got: ${r.error}`);
  assert("pairId preserved from BPC", r.pairId === pairId, `Got: ${r.pairId}`);
  assert("layers is ['bpc'] — BPC layer reached but TSK did not",
    r.layers.length === 1 && r.layers[0] === 'bpc',
    `Got: ${JSON.stringify(r.layers)}`);
}

// ── Group 4: TSK failure — missing TSK headers entirely ──────────────────────
console.log('\n[4] TSK Headers Missing — request has BPC headers but no TSK layer');
{
  const req: TSKRequestData = {
    headers: {
      'x-bpc-pair-id': pairId,
      'x-bpc-signature': 'fake',
      // No TSK headers
    },
  };
  const r = await verifyUltraRequest(req, bpcPass(), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error starts with 'TSK:'", r.error?.startsWith('TSK:') ?? false, `Got: ${r.error}`);
  assert("error includes HEADERS_MISSING",
    r.error?.includes('HEADERS_MISSING') ?? false, `Got: ${r.error}`);
  assert("layers is ['bpc']",
    r.layers.length === 1 && r.layers[0] === 'bpc',
    `Got: ${JSON.stringify(r.layers)}`);
}

// ── Group 5: Identity binding mismatch ───────────────────────────────────────
console.log('\n[5] Identity Binding Mismatch — BPC pairId maps to different clientId');
{
  // Provision a second client
  const prov2 = await provisioner.provision();
  const map2 = prov2.tumblerMap!;
  const key2 = generateKeyFromMap(map2, NOW);

  // Request uses pairId→clientId1 binding, but TSK key is for clientId2
  const req: TSKRequestData = {
    headers: {
      'x-tsk-client-id': map2.clientId, // legitimate key for client2
      'x-tsk-key': key2,
      'x-tsk-version': '1',
    },
  };
  // BPC says pairId→clientId (client1), but TSK clientId is client2
  const r = await verifyUltraRequest(req, bpcPass(pairId), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error is IDENTITY_BINDING_MISMATCH",
    r.error === 'IDENTITY_BINDING_MISMATCH', `Got: ${r.error}`);
  assert("layers includes both bpc and tsk (both passed individually)",
    r.layers.includes('bpc') && r.layers.includes('tsk'),
    `Got: ${JSON.stringify(r.layers)}`);
}

// ── Group 6: Identity binding — pairId resolves to null (unknown pair) ───────
console.log('\n[6] Identity Binding — pairId unknown (resolves to null)');
{
  const req = makeReq(tskHeaders(NOW));
  const unknownPairId = 'bpc_pair_unknown_9999';
  const r = await verifyUltraRequest(req, bpcPass(unknownPairId), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error is IDENTITY_BINDING_MISMATCH (null !== clientId)",
    r.error === 'IDENTITY_BINDING_MISMATCH', `Got: ${r.error}`);
}

// ── Group 7: Identity binding unavailable — BPC returns no pairId ─────────────
console.log('\n[7] Identity Binding Unavailable — BPC result missing pairId');
{
  const req = makeReq(tskHeaders(NOW));
  const r = await verifyUltraRequest(req, bpcPassNoPairId(), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error is IDENTITY_BINDING_UNAVAILABLE",
    r.error === 'IDENTITY_BINDING_UNAVAILABLE', `Got: ${r.error}`);
  assert("layers includes both (both layers validated individually)",
    r.layers.includes('bpc') && r.layers.includes('tsk'),
    `Got: ${JSON.stringify(r.layers)}`);
}

// ── Group 8: Tampered TSK key — single character mutation ────────────────────
console.log('\n[8] Tampered TSK Key — 1-char mutation at position 10');
{
  const validKey = generateKeyFromMap(map, NOW);
  const tampered = validKey.slice(0, 10) + (validKey[10] === 'A' ? 'Z' : 'A') + validKey.slice(11);
  const req: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': tampered,
      'x-tsk-version': '1',
    },
  };
  const r = await verifyUltraRequest(req, bpcPass(), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error starts with 'TSK:'", r.error?.startsWith('TSK:') ?? false, `Got: ${r.error}`);
  assert("layers is ['bpc'] — TSK rejected",
    r.layers.length === 1 && r.layers[0] === 'bpc',
    `Got: ${JSON.stringify(r.layers)}`);
}

// ── Group 9: Wrong TSK client ID — valid key for different client ─────────────
console.log('\n[9] Wrong TSK Client ID — valid key but wrong clientId header');
{
  const req: TSKRequestData = {
    headers: {
      'x-tsk-client-id': 'tsk_nonexistent_client',
      'x-tsk-key': generateKeyFromMap(map, NOW),
      'x-tsk-version': '1',
    },
  };
  const r = await verifyUltraRequest(req, bpcPass(), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error starts with 'TSK:'", r.error?.startsWith('TSK:') ?? false, `Got: ${r.error}`);
  assert("error includes CLIENT_NOT_FOUND",
    r.error?.includes('CLIENT_NOT_FOUND') ?? false, `Got: ${r.error}`);
}

// ── Group 10: ULTRA_SECURITY_LAYERS contract ─────────────────────────────────
console.log('\n[10] ULTRA_SECURITY_LAYERS Contract');
{
  assert('7 layers defined', ULTRA_SECURITY_LAYERS.length === 7,
    `Got: ${ULTRA_SECURITY_LAYERS.length}`);
  assert('layers 1-5 are BPC',
    ULTRA_SECURITY_LAYERS.slice(0, 5).every(l => l.source === 'BPC'),
    `Got sources: ${ULTRA_SECURITY_LAYERS.slice(0, 5).map(l => l.source)}`);
  assert('layers 6-7 are TSK',
    ULTRA_SECURITY_LAYERS.slice(5).every(l => l.source === 'TSK'),
    `Got sources: ${ULTRA_SECURITY_LAYERS.slice(5).map(l => l.source)}`);
  assert('layer IDs are 1-7 in order',
    ULTRA_SECURITY_LAYERS.every((l, i) => l.id === i + 1),
    `Got IDs: ${ULTRA_SECURITY_LAYERS.map(l => l.id)}`);
  assert('Layer 7 describes structural secrecy',
    ULTRA_SECURITY_LAYERS[6].property.toLowerCase().includes('structural'),
    `Got: ${ULTRA_SECURITY_LAYERS[6].property}`);
}


// ── Group 11: HIGH-03 — BPC scope propagated to UltraVerifyResult ─────────────
console.log('\n[11] BPC Scope Propagation (HIGH-03)');
{
  // Test 1: scope field set directly on BPCLikeResult
  const bpcWithScope = async () => ({ ok: true, pairId, scope: 'read' });
  const req11a: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': generateKeyFromMap(map, NOW),
      'x-tsk-version': '1',
    },
  };
  const r11a = await verifyUltraRequest(req11a, bpcWithScope, { tskStore: store, identityBinding });
  assert('scope=read propagated from bpcResult.scope', r11a.scope === 'read', `Got: ${r11a.scope}`);

  // Test 2: scope extracted from bpcResult.pair.scope
  const bpcWithPair = async () => ({ ok: true, pairId, pair: { scope: 'read-write', id: pairId } });
  const req11b: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': generateKeyFromMap(map, NOW),
      'x-tsk-version': '1',
    },
  };
  const r11b = await verifyUltraRequest(req11b, bpcWithPair, { tskStore: store, identityBinding });
  assert('scope=read-write extracted from bpcResult.pair.scope', r11b.scope === 'read-write', `Got: ${r11b.scope}`);

  // Test 3: no scope — result.scope is undefined (not a failure, just not set)
  const req11c: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': generateKeyFromMap(map, NOW),
      'x-tsk-version': '1',
    },
  };
  const r11c = await verifyUltraRequest(req11c, bpcPass(), { tskStore: store, identityBinding });
  assert('scope=undefined when BPC does not return scope', r11c.scope === undefined, `Got: ${r11c.scope}`);

  // Test 4: scope field takes priority over pair.scope
  const bpcBoth = async () => ({ ok: true, pairId, scope: 'admin', pair: { scope: 'read', id: pairId } });
  const req11d: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': generateKeyFromMap(map, NOW),
      'x-tsk-version': '1',
    },
  };
  const r11d = await verifyUltraRequest(req11d, bpcBoth, { tskStore: store, identityBinding });
  assert('scope field takes priority over pair.scope', r11d.scope === 'admin', `Got: ${r11d.scope}`);
}
// ─── Results ──────────────────────────────────────────────────────────────────

const passed = results.filter(r => r.passed).length;
const total = results.length;
const failed = results.filter(r => !r.passed);

console.log('\n' + '─'.repeat(68));
console.log(`Ultra Bridge Test Suite: ${passed}/${total} passed`);

if (failed.length > 0) {
  console.log('\nFailed tests:');
  for (const f of failed) {
    console.log(`  ✗ ${f.name}`);
    if (f.detail) console.log(`      ${f.detail}`);
  }
  process.exit(1);
} else {
  console.log('ALL TESTS PASSED — Ultra Bridge fully verified');
}
