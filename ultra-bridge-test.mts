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
import { authenticateBpcTskHttpRequest } from './packages/node-http/src/adapter.js';
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

// Build valid TSK headers from the authoritative counter state. Validation
// advances HOTP counters, so reusing the originally provisioned map would
// create a stale key and prevent later cases from reaching the branch they
// actually assert.
async function currentMap(): Promise<TumblerMap> {
  const stored = await store.get(clientId);
  if (!stored) throw new Error('shared TSK fixture disappeared');
  return stored;
}

async function tskHeaders(nowMs = Date.now()): Promise<Record<string, string>> {
  const key = generateKeyFromMap(await currentMap(), nowMs);
  return {
    'x-tsk-client-id': clientId,
    'x-tsk-key': key,
    'x-tsk-version': '1',
  };
}

async function requestCount(id: string): Promise<number> {
  const stored = await store.get(id);
  if (!stored) throw new Error(`TSK fixture disappeared: ${id}`);
  return stored.requestCount ?? 0;
}

// Build a request object with both BPC and TSK headers (BPC headers are fake — verified by mock)
async function makeReq(
  extraHeaders: Record<string, string> = {},
  nowMs = Date.now(),
): Promise<TSKRequestData> {
  return {
    headers: {
      'x-bpc-pair-id': pairId,
      'x-bpc-signature': 'fake_sig',
      'x-bpc-signed-data': 'fake_data',
      ...await tskHeaders(nowMs),
      ...extraHeaders,
    },
  };
}

// BPC mock stubs
function bpcPass(pid = pairId): () => Promise<BPCLikeResult> {
  return async () => ({ ok: true, pairId: pid, pair: { scope: 'read-write' } });
}
function bpcFail(error = 'INVALID_SIGNATURE'): () => Promise<BPCLikeResult> {
  return async () => ({ ok: false, error });
}
function bpcPassNoPairId(): () => Promise<BPCLikeResult> {
  return async () => ({ ok: true, pair: { scope: 'read-write' } }); // pairId absent
}

// ─── Test groups ──────────────────────────────────────────────────────────────

const NOW = Date.now();

// ── Group 1: Happy path ────────────────────────────────────────────────────────
console.log('\n[1] Happy Path — BPC pass + TSK pass + identity match');
{
  const req = await makeReq({}, NOW);
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
  const req = await makeReq();
  const before = await requestCount(clientId);
  const r = await verifyUltraRequest(req, bpcFail('REPLAY_DETECTED'), { tskStore: store, identityBinding });
  const after = await requestCount(clientId);

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error starts with 'BPC:'", r.error?.startsWith('BPC:') ?? false, `Got: ${r.error}`);
  assert("error includes the BPC error code", r.error?.includes('REPLAY_DETECTED') ?? false, `Got: ${r.error}`);
  assert("layers is empty (TSK not reached)", r.layers.length === 0, `Got: ${JSON.stringify(r.layers)}`);
  assert('pairId absent when BPC fails', r.pairId === undefined, `Got: ${r.pairId}`);
  assert('BPC replay rejection leaves TSK request count unchanged', after === before, `Before=${before}, after=${after}`);
  const retry = await verifyUltraRequest(req, bpcPass(), { tskStore: store, identityBinding });
  assert('same TSK key remains usable after BPC replay rejection', retry.ok, `Got: ${retry.error}`);
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
  const expiredBinding = { resolve: async (_pid: string) => expiredMap.clientId };
  const r = await verifyUltraRequest(req, bpcPass(), { tskStore: expiredStore, identityBinding: expiredBinding });

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
  assert("error is IDENTITY_BINDING_UNAVAILABLE before TSK",
    r.error === 'IDENTITY_BINDING_UNAVAILABLE', `Got: ${r.error}`);
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
  const before = await requestCount(map2.clientId);
  // BPC says pairId→clientId (client1), but TSK clientId is client2
  const r = await verifyUltraRequest(req, bpcPass(pairId), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error is IDENTITY_BINDING_MISMATCH",
    r.error === 'IDENTITY_BINDING_MISMATCH', `Got: ${r.error}`);
  assert("layers is ['bpc'] because mismatch is rejected before TSK",
    r.layers.length === 1 && r.layers[0] === 'bpc',
    `Got: ${JSON.stringify(r.layers)}`);
  assert('binding mismatch leaves TSK request count unchanged',
    await requestCount(map2.clientId) === before, `Before=${before}, after=${await requestCount(map2.clientId)}`);
  const boundPairId = 'bpc_pair_test_002';
  identityMap.set(boundPairId, map2.clientId);
  const bound = await verifyUltraRequest(req, bpcPass(boundPairId), { tskStore: store, identityBinding });
  assert('genuinely bound TSK request consumes once', bound.ok && await requestCount(map2.clientId) === before + 1,
    `Got ok=${bound.ok}, count=${await requestCount(map2.clientId)}`);
}

// ── Group 6: Identity binding — pairId resolves to null (unknown pair) ───────
console.log('\n[6] Identity Binding — pairId unknown (resolves to null)');
{
  const req = await makeReq({}, NOW);
  const unknownPairId = 'bpc_pair_unknown_9999';
  const before = await requestCount(clientId);
  const r = await verifyUltraRequest(req, bpcPass(unknownPairId), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error is IDENTITY_BINDING_UNAVAILABLE",
    r.error === 'IDENTITY_BINDING_UNAVAILABLE', `Got: ${r.error}`);
  assert('absent pair binding leaves TSK request count unchanged',
    await requestCount(clientId) === before, `Before=${before}, after=${await requestCount(clientId)}`);
  const retry = await verifyUltraRequest(req, bpcPass(), { tskStore: store, identityBinding });
  assert('same TSK key remains usable after absent binding', retry.ok, `Got: ${retry.error}`);
}

// ── Group 7: Identity binding unavailable — BPC returns no pairId ─────────────
console.log('\n[7] Identity Binding Unavailable — BPC result missing pairId');
{
  const req = await makeReq({}, NOW);
  const r = await verifyUltraRequest(req, bpcPassNoPairId(), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error is IDENTITY_BINDING_UNAVAILABLE",
    r.error === 'IDENTITY_BINDING_UNAVAILABLE', `Got: ${r.error}`);
  assert("layers is ['bpc'] because missing pairId is rejected before TSK",
    r.layers.length === 1 && r.layers[0] === 'bpc',
    `Got: ${JSON.stringify(r.layers)}`);
}

// ── Group 8: Tampered TSK key — single character mutation ────────────────────
console.log('\n[8] Tampered TSK Key — 1-char mutation at position 10');
{
  const validKey = generateKeyFromMap(await currentMap(), NOW);
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
console.log('\n[9] Wrong TSK Client ID — claimed client conflicts with authoritative pair binding');
{
  const req: TSKRequestData = {
    headers: {
      'x-tsk-client-id': 'tsk_nonexistent_client',
      'x-tsk-key': generateKeyFromMap(await currentMap(), NOW),
      'x-tsk-version': '1',
    },
  };
  const r = await verifyUltraRequest(req, bpcPass(), { tskStore: store, identityBinding });

  assert('result.ok is false', !r.ok, `Got ok=${r.ok}`);
  assert("error is IDENTITY_BINDING_MISMATCH before TSK",
    r.error === 'IDENTITY_BINDING_MISMATCH', `Got: ${r.error}`);
  assert("layers is ['bpc'] because wrong claimed client is rejected before TSK",
    r.layers.length === 1 && r.layers[0] === 'bpc', `Got: ${JSON.stringify(r.layers)}`);
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
  assert('Layer 7 describes atomic lifecycle enforcement',
    ULTRA_SECURITY_LAYERS[6].property.toLowerCase().includes('atomic'),
    `Got: ${ULTRA_SECURITY_LAYERS[6].property}`);
}


// ── Group 11: HIGH-03 — BPC scope propagated to UltraVerifyResult ─────────────
console.log('\n[11] BPC Scope Propagation (HIGH-03)');
{
  // Test 1: scope field set directly on BPCLikeResult
  const bpcWithScope = async (): Promise<BPCLikeResult> => ({ ok: true, pairId, scope: 'read' });
  const req11a: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': generateKeyFromMap(await currentMap(), NOW),
      'x-tsk-version': '1',
    },
  };
  const r11a = await verifyUltraRequest(req11a, bpcWithScope, { tskStore: store, identityBinding });
  assert('scope=read propagated from bpcResult.scope', r11a.scope === 'read', `Got: ${r11a.scope}`);

  // Test 2: scope extracted from bpcResult.pair.scope
  const bpcWithPair = async (): Promise<BPCLikeResult> => (
    { ok: true, pairId, pair: { scope: 'read-write', id: pairId } }
  );
  const req11b: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': generateKeyFromMap(await currentMap(), NOW),
      'x-tsk-version': '1',
    },
  };
  const r11b = await verifyUltraRequest(req11b, bpcWithPair, { tskStore: store, identityBinding });
  assert('scope=read-write extracted from bpcResult.pair.scope', r11b.scope === 'read-write', `Got: ${r11b.scope}`);

  // Test 3: a successful verifier with no scope violates the BPC 0.2 contract.
  // Reuse the exact TSK key afterward to prove the invalid BPC result did not
  // consume TSK counter state.
  const req11c: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': generateKeyFromMap(await currentMap(), NOW),
      'x-tsk-version': '1',
    },
  };
  const missingScope = async () => ({ ok: true, pairId }) as BPCLikeResult;
  const r11c = await verifyUltraRequest(req11c, missingScope, { tskStore: store, identityBinding });
  assert('missing BPC scope is rejected', !r11c.ok && r11c.error === 'BPC: INVALID_SCOPE', `Got: ${r11c.error}`);
  assert('missing BPC scope fails before TSK', r11c.layers.length === 0, `Got: ${JSON.stringify(r11c.layers)}`);
  const r11cRetry = await verifyUltraRequest(req11c, bpcPass(), { tskStore: store, identityBinding });
  assert('same TSK key remains usable after invalid BPC scope', r11cRetry.ok, `Got: ${r11cRetry.error}`);

  // Test 4: contradictory authenticated scope representations fail closed.
  const bpcBoth = async (): Promise<BPCLikeResult> => (
    { ok: true, pairId, scope: 'admin', pair: { scope: 'read', id: pairId } }
  );
  const req11d: TSKRequestData = {
    headers: {
      'x-tsk-client-id': clientId,
      'x-tsk-key': generateKeyFromMap(await currentMap(), NOW),
      'x-tsk-version': '1',
    },
  };
  const r11d = await verifyUltraRequest(req11d, bpcBoth, { tskStore: store, identityBinding });
  assert('direct and pair scope disagreement is rejected',
    !r11d.ok && r11d.error === 'BPC: SCOPE_MISMATCH', `Got: ${r11d.error}`);
  assert('scope disagreement fails before TSK', r11d.layers.length === 0, `Got: ${JSON.stringify(r11d.layers)}`);

  // Test 5: runtime validation rejects values that bypass TypeScript typing.
  const req11e = await makeReq({}, NOW);
  const wildcardScope = async () => ({ ok: true, pairId, scope: 'read:*' }) as unknown as BPCLikeResult;
  const r11e = await verifyUltraRequest(req11e, wildcardScope, { tskStore: store, identityBinding });
  assert('wildcard BPC scope is rejected',
    !r11e.ok && r11e.error === 'BPC: INVALID_SCOPE', `Got: ${r11e.error}`);

  const namespacedScope = async () => (
    { ok: true, pairId, pair: { scope: 'read:quotes' } }
  ) as unknown as BPCLikeResult;
  const r11f = await verifyUltraRequest(req11e, namespacedScope, { tskStore: store, identityBinding });
  assert('namespaced BPC scope is rejected',
    !r11f.ok && r11f.error === 'BPC: INVALID_SCOPE', `Got: ${r11f.error}`);

const matchingAdmin = async () => (
    { ok: true, pairId, scope: 'admin', pair: { scope: 'admin', id: pairId } }
  ) satisfies BPCLikeResult;
  const r11g = await verifyUltraRequest(req11e, matchingAdmin, { tskStore: store, identityBinding });
  assert('matching closed admin scope is accepted', r11g.ok && r11g.scope === 'admin', `Got: ${r11g.error}`);
}

// ── Group 12: dependency exceptions are contained and never become retryable denials ──
console.log('\n[12] Dependency Exception Containment');
{
  const beforeBpcThrow = await requestCount(clientId);
  const bpcThrow = await verifyUltraRequest(await makeReq(), async () => {
    throw new Error('bpc verifier secret: never expose');
  }, { tskStore: store, identityBinding });
  assert('BPC verifier exception is contained as unknown',
    !bpcThrow.ok && bpcThrow.error === 'BPC: VERIFICATION_UNKNOWN' && bpcThrow.outcomeUnknown === true,
    `Got: ${JSON.stringify(bpcThrow)}`);
  assert('BPC verifier exception exposes no thrown text',
    !JSON.stringify(bpcThrow).includes('secret'), `Got: ${JSON.stringify(bpcThrow)}`);
  assert('BPC verifier exception does not reach TSK in this injected boundary',
    await requestCount(clientId) === beforeBpcThrow, `Before=${beforeBpcThrow}, after=${await requestCount(clientId)}`);

  const { store: bindingStore, provisioner: bindingProvisioner } = createTSKServer();
  const bindingProvisioned = await bindingProvisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  if (!bindingProvisioned.ok || !bindingProvisioned.tumblerMap) throw new Error('binding exception fixture provision failed');
  const bindingMap = bindingProvisioned.tumblerMap;
  const bindingReq: TSKRequestData = { headers: {
    'x-tsk-client-id': bindingMap.clientId,
    'x-tsk-key': generateKeyFromMap(bindingMap),
    'x-tsk-version': '1',
  } };
  const bindingThrow = await verifyUltraRequest(bindingReq, bpcPass('pair-binding-throw'), {
    tskStore: bindingStore,
    identityBinding: { resolve: async () => { throw new Error('directory credential: never expose'); } },
  });
  assert('binding resolver exception is contained as unknown',
    !bindingThrow.ok && bindingThrow.error === 'IDENTITY_BINDING_UNKNOWN' && bindingThrow.outcomeUnknown === true,
    `Got: ${JSON.stringify(bindingThrow)}`);
  assert('binding resolver exception exposes no thrown text',
    !JSON.stringify(bindingThrow).includes('credential'), `Got: ${JSON.stringify(bindingThrow)}`);
  assert('binding resolver exception does not reach TSK',
    (await bindingStore.get(bindingMap.clientId))?.requestCount === 0, 'TSK request count changed');

  const { store: afterCommitStore, provisioner: afterCommitProvisioner } = createTSKServer();
  const afterCommitProvisioned = await afterCommitProvisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  if (!afterCommitProvisioned.ok || !afterCommitProvisioned.tumblerMap) throw new Error('after-commit exception fixture provision failed');
  const afterCommitMap = afterCommitProvisioned.tumblerMap;
  const actualCommit = afterCommitStore.commitValidation.bind(afterCommitStore);
  afterCommitStore.commitValidation = async (id, input) => {
    await actualCommit(id, input);
    throw new Error('store receipt secret: never expose');
  };
  const afterCommit = await verifyUltraRequest({ headers: {
    'x-tsk-client-id': afterCommitMap.clientId,
    'x-tsk-key': generateKeyFromMap(afterCommitMap),
    'x-tsk-version': '1',
  } }, bpcPass('pair-after-commit'), {
    tskStore: afterCommitStore,
    identityBinding: { resolve: async pair => pair === 'pair-after-commit' ? afterCommitMap.clientId : null },
  });
  assert('TSK/store exception after commit is contained as unknown',
    !afterCommit.ok && afterCommit.error === 'TSK: VERIFICATION_UNKNOWN' && afterCommit.outcomeUnknown === true,
    `Got: ${JSON.stringify(afterCommit)}`);
  assert('TSK/store exception exposes no thrown text',
    !JSON.stringify(afterCommit).includes('secret'), `Got: ${JSON.stringify(afterCommit)}`);
  assert('post-commit exception retains exactly one observed TSK consumption',
    (await afterCommitStore.get(afterCommitMap.clientId))?.requestCount === 1, 'Expected one consumed request');

  const response = new class {
    headersSent = false; statusCode = 0; payload = ''; readonly headers = new Map<string, unknown>();
    setHeader(name: string, value: unknown) { this.headers.set(name, value); }
    writeHead(status: number) { this.statusCode = status; this.headersSent = true; return this; }
    end(body?: unknown) { this.payload = String(body ?? ''); }
  }();
  const httpResult = await authenticateBpcTskHttpRequest(
    { headers: { 'x-request-id': 'exception-boundary-test' }, socket: { remoteAddress: '127.0.0.1' } } as any,
    response as any,
    {
      store: new MemoryTumblerStore(),
      bpcVerify: async () => { throw new Error('HTTP boundary secret: never expose'); },
      identityBinding: { resolve: async () => null },
    },
  );
  assert('HTTP adapter retains generic 401 failure shape for contained exception',
    httpResult === null && response.statusCode === 401 && response.payload.includes('BPC_TSK_AUTHENTICATION_FAILED'),
    `Got: ${response.statusCode} ${response.payload}`);
  assert('HTTP adapter response exposes no thrown text', !response.payload.includes('secret'), `Got: ${response.payload}`);
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
  console.log('Named Ultra Bridge cases passed');
}
