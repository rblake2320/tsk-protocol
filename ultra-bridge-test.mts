/**
 * Strict BPC/TSK composition tests.
 *
 * Every preflight denial is followed by a successful retry with the same TSK
 * key. That proves malformed BPC evidence and identity-binding failures cannot
 * consume HOTP or lifecycle state.
 */

import {
  ULTRA_SECURITY_LAYERS,
  verifyUltraRequest,
  type BPCAuthSnapshot,
  type BPCLikeResult,
  type UltraVerifyOptions,
} from './packages/bpc-bridge/src/ultra-verify.js';
import { authenticateBpcTskHttpRequest } from './packages/node-http/src/adapter.js';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import { createTSKServer, MemoryTumblerStore } from './packages/server/src/index.js';
import type { TumblerMap } from './packages/core/src/types.js';
import type { TSKRequestData } from './packages/server/src/middleware.js';

type AsyncTest = () => Promise<void>;

const tests: Array<{ name: string; run: AsyncTest }> = [];

function test(name: string, run: AsyncTest): void {
  tests.push({ name, run });
}

function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function snapshot(
  pairId: string,
  scope: BPCAuthSnapshot['scope'] = 'read-write',
): BPCAuthSnapshot {
  return Object.freeze({
    pairId,
    scope,
    mode: 'production' as const,
    kind: 'legitimate' as const,
    verifiedAt: Date.now(),
  });
}

function bpcPass(pairId: string, scope: BPCAuthSnapshot['scope'] = 'read-write') {
  return async (): Promise<BPCLikeResult> => ({
    ok: true,
    pairId,
    snapshot: snapshot(pairId, scope),
  });
}

interface Fixture {
  pairId: string;
  clientId: string;
  key: string;
  request: TSKRequestData;
  store: MemoryTumblerStore;
  identityBinding: UltraVerifyOptions['identityBinding'];
}

async function fixture(): Promise<Fixture> {
  const server = createTSKServer();
  const provisioned = await server.provisioner.provision({
    keyLength: 64,
    minTumblers: 2,
    maxTumblers: 2,
  });
  if (!provisioned.ok || !provisioned.tumblerMap) throw new Error('TSK provisioning failed');
  const map = provisioned.tumblerMap;
  const pairId = `bpc_pair_${map.clientId}`;
  const key = generateKeyFromMap(map);
  return {
    pairId,
    clientId: map.clientId,
    key,
    request: {
      headers: {
        'x-tsk-client-id': map.clientId,
        'x-tsk-key': key,
        'x-tsk-version': '1',
      },
    },
    store: server.store,
    identityBinding: {
      resolve: async candidate => candidate === pairId ? map.clientId : null,
    },
  };
}

async function retrySameKey(f: Fixture): Promise<void> {
  const retry = await verifyUltraRequest(
    f.request,
    bpcPass(f.pairId),
    { tskStore: f.store, identityBinding: f.identityBinding },
  );
  expect(retry.ok, `same TSK key was not reusable: ${retry.error}`);
}

async function expectPreflightDenial(
  expectedError: string,
  bpc: (f: Fixture) => (req: TSKRequestData) => Promise<unknown>,
  mutate?: (f: Fixture) => void,
  options?: (f: Fixture) => Partial<UltraVerifyOptions>,
): Promise<void> {
  const f = await fixture();
  mutate?.(f);
  const override = options?.(f);
  const denied = await verifyUltraRequest(
    f.request,
    bpc(f) as (req: TSKRequestData) => Promise<BPCLikeResult>,
    {
      tskStore: override?.tskStore ?? f.store,
      tskConfig: override?.tskConfig,
      bpcSnapshotMaxAgeMs: override?.bpcSnapshotMaxAgeMs,
      now: override?.now,
      identityBinding: override?.identityBinding ?? f.identityBinding,
    },
  );
  expect(!denied.ok, 'preflight unexpectedly succeeded');
  if (['BPC: CALLBACK_EXCEPTION', 'IDENTITY_BINDING_RESOLVER_EXCEPTION'].includes(expectedError)) expect(denied.outcomeUnknown === true, 'dependency uncertainty lost');
  expect(denied.error === expectedError, `expected ${expectedError}, got ${denied.error}`);

  // Restore the valid claimed identity without changing the TSK key.
  f.request.headers['x-tsk-client-id'] = f.clientId;
  await retrySameKey(f);
}

test('accepts a frozen, closed-scope BPC AuthSnapshot and matching TSK identity', async () => {
  const f = await fixture();
  const result = await verifyUltraRequest(
    f.request,
    bpcPass(f.pairId, 'admin'),
    { tskStore: f.store, identityBinding: f.identityBinding },
  );
  expect(result.ok, `composed verification failed: ${result.error}`);
  expect(result.pairId === f.pairId, 'pair identity was not preserved');
  expect(result.clientId === f.clientId, 'TSK identity was not preserved');
  expect(result.scope === 'admin', 'closed BPC scope was not preserved');
  expect(result.layers.join(',') === 'bpc,tsk', 'both layers were not recorded');
});

test('rejects a null BPC result before TSK state consumption', async () => {
  await expectPreflightDenial('BPC: VERIFICATION_FAILED', () => async () => null);
});

test('requires the BPC ok field to be boolean true', async () => {
  await expectPreflightDenial(
    'BPC: VERIFICATION_FAILED',
    f => async () => ({ ok: 'true', pairId: f.pairId, snapshot: snapshot(f.pairId) }),
  );
});

test('catches BPC verifier exceptions without reaching TSK', async () => {
  await expectPreflightDenial('BPC: CALLBACK_EXCEPTION', () => async () => {
    throw new Error('untrusted verifier failure');
  });
});

test('preserves a bounded BPC denial code', async () => {
  await expectPreflightDenial(
    'BPC: signature_invalid',
    () => async () => ({ ok: false, error: 'signature_invalid' }),
  );
});

test('does not reflect an unbounded BPC error into the bridge result', async () => {
  await expectPreflightDenial(
    'BPC: VERIFICATION_FAILED',
    () => async () => ({ ok: false, error: 'invalid\r\nforged-log-entry' }),
  );
});

test('converts hostile BPC proxy inspection into a denial', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_RESULT_OBJECT',
    () => async () => new Proxy({ ok: true }, {
      getOwnPropertyDescriptor: () => { throw new Error('hostile proxy'); },
    }),
  );
});

test('rejects a missing BPC pair ID before TSK', async () => {
  await expectPreflightDenial(
    'BPC: MISSING_OR_INVALID_PAIR_ID',
    () => async () => ({ ok: true, snapshot: snapshot('unbound') }),
  );
});

test('rejects malformed BPC pair identifiers', async () => {
  await expectPreflightDenial(
    'BPC: MISSING_OR_INVALID_PAIR_ID',
    () => async () => ({ ok: true, pairId: '../other', snapshot: snapshot('../other') }),
  );
});

test('requires the immutable AuthSnapshot', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_AUTH_SNAPSHOT',
    f => async () => ({ ok: true, pairId: f.pairId }),
  );
});

test('rejects a mutable AuthSnapshot', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_AUTH_SNAPSHOT',
    f => async () => ({
      ok: true,
      pairId: f.pairId,
      snapshot: {
        pairId: f.pairId,
        scope: 'read',
        mode: 'production',
        kind: 'legitimate',
        verifiedAt: Date.now(),
      },
    }),
  );
});

test('rejects disagreement between result and snapshot pair IDs', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_AUTH_SNAPSHOT',
    f => async () => ({ ok: true, pairId: f.pairId, snapshot: snapshot('other_pair') }),
  );
});

// Deterministic snapshot age/skew boundary tests under a FIXED injected clock. The old
// tests used Date.now() for BOTH the snapshot and the (later) internal Date.now(), so a
// few ms of elapsed time shrank a +60_001 future skew back inside the 60_000 window and
// the future test flaked. A fixed clock removes the race and lets us test exact edges.
const AGE_CLOCK = 1_700_000_000_000; // fixed reference "now"
const MAX_AGE = 60_000;
const snapshotAt = (f: Fixture, verifiedAt: number) => async () => ({
  ok: true,
  pairId: f.pairId,
  snapshot: Object.freeze({ pairId: f.pairId, scope: 'read', mode: 'production', kind: 'legitimate', verifiedAt }),
});
const fixedNow = () => ({ now: () => AGE_CLOCK });

test('rejects a snapshot 1ms past the max age (stale edge, fixed clock)', async () => {
  await expectPreflightDenial('BPC: INVALID_AUTH_SNAPSHOT', f => snapshotAt(f, AGE_CLOCK - MAX_AGE - 1), undefined, fixedNow);
});

test('rejects a future-dated snapshot 1ms past the max skew (future edge, fixed clock)', async () => {
  await expectPreflightDenial('BPC: INVALID_AUTH_SNAPSHOT', f => snapshotAt(f, AGE_CLOCK + MAX_AGE + 1), undefined, fixedNow);
});

test('accepts a snapshot exactly at the max age/skew edges (fixed clock)', async () => {
  for (const verifiedAt of [AGE_CLOCK - MAX_AGE, AGE_CLOCK + MAX_AGE]) {
    const f = await fixture();
    const result = await verifyUltraRequest(
      f.request,
      snapshotAt(f, verifiedAt) as never,
      { tskStore: f.store, now: () => AGE_CLOCK, identityBinding: f.identityBinding },
    );
    expect(result.ok, `expected acceptance at edge verifiedAt=${verifiedAt}, got ${result.ok ? 'ok' : result.error}`);
  }
});

test('rejects an unsafe snapshot-age configuration', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_SNAPSHOT_MAX_AGE',
    f => bpcPass(f.pairId),
    undefined,
    () => ({ bpcSnapshotMaxAgeMs: Number.POSITIVE_INFINITY }),
  );
});

for (const scope of ['read:*', 'read:quotes', '*', 'owner']) {
  test(`rejects non-closed BPC scope ${scope}`, async () => {
    await expectPreflightDenial(
      'BPC: INVALID_AUTH_SNAPSHOT',
      f => async () => ({
        ok: true,
        pairId: f.pairId,
        snapshot: Object.freeze({
          pairId: f.pairId,
          scope,
          mode: 'production',
          kind: 'legitimate',
          verifiedAt: Date.now(),
        }),
      }),
    );
  });
}

test('rejects an unknown BPC mode', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_AUTH_SNAPSHOT',
    f => async () => ({
      ok: true,
      pairId: f.pairId,
      snapshot: Object.freeze({
        pairId: f.pairId,
        scope: 'read',
        mode: 'staging',
        kind: 'legitimate',
        verifiedAt: Date.now(),
      }),
    }),
  );
});

test('rejects ghost authorization evidence', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_AUTH_SNAPSHOT',
    f => async () => ({
      ok: true,
      pairId: f.pairId,
      snapshot: Object.freeze({
        pairId: f.pairId,
        scope: 'read',
        mode: 'production',
        kind: 'ghost',
        canaryClass: 'docs',
        verifiedAt: Date.now(),
      }),
    }),
  );
});

test('hard-denies shadow verdicts', async () => {
  await expectPreflightDenial(
    'BPC: SHADOW_DENIED',
    f => async () => ({
      ok: true,
      pairId: f.pairId,
      snapshot: snapshot(f.pairId),
      shadow: true,
    }),
  );
});

test('rejects legacy mutable pair objects even with a valid snapshot', async () => {
  await expectPreflightDenial(
    'BPC: LEGACY_MUTABLE_RESULT',
    f => async () => ({
      ok: true,
      pairId: f.pairId,
      snapshot: snapshot(f.pairId),
      pair: { id: f.pairId, scope: 'admin' },
    }),
  );
});

test('rejects legacy direct scope even with a valid snapshot', async () => {
  await expectPreflightDenial(
    'BPC: LEGACY_MUTABLE_RESULT',
    f => async () => ({
      ok: true,
      pairId: f.pairId,
      snapshot: snapshot(f.pairId),
      scope: 'admin',
    }),
  );
});

test('catches identity resolver exceptions before TSK', async () => {
  await expectPreflightDenial(
    'IDENTITY_BINDING_RESOLVER_EXCEPTION',
    f => bpcPass(f.pairId),
    undefined,
    () => ({ identityBinding: { resolve: async () => { throw new Error('binding unavailable'); } } }),
  );
});

test('rejects a missing identity binding before TSK', async () => {
  await expectPreflightDenial(
    'IDENTITY_BINDING_NOT_FOUND',
    f => bpcPass(f.pairId),
    undefined,
    () => ({ identityBinding: { resolve: async () => null } }),
  );
});

test('rejects a claimed TSK client mismatch before store lookup', async () => {
  await expectPreflightDenial(
    'IDENTITY_BINDING_MISMATCH',
    f => bpcPass(f.pairId),
    f => { f.request.headers['x-tsk-client-id'] = 'tsk_other_client'; },
  );
});

test('rejects duplicate TSK client headers before TSK', async () => {
  await expectPreflightDenial(
    'TSK: CLIENT_ID_MISSING_OR_AMBIGUOUS',
    f => bpcPass(f.pairId),
    f => { f.request.headers['x-tsk-client-id'] = [f.clientId, f.clientId]; },
  );
});

test('rejects a missing TSK client header before TSK', async () => {
  await expectPreflightDenial(
    'TSK: CLIENT_ID_MISSING_OR_AMBIGUOUS',
    f => bpcPass(f.pairId),
    f => { delete f.request.headers['x-tsk-client-id']; },
  );
});

test('rejects duplicate TSK key headers without consuming state', async () => {
  const f = await fixture();
  f.request.headers['x-tsk-key'] = [f.key, f.key];
  const denied = await verifyUltraRequest(
    f.request,
    bpcPass(f.pairId),
    { tskStore: f.store, identityBinding: f.identityBinding },
  );
  expect(!denied.ok && denied.error === 'TSK: TSK_HEADERS_MISSING', `unexpected error: ${denied.error}`);
  f.request.headers['x-tsk-key'] = f.key;
  await retrySameKey(f);
});

test('rejects duplicate TSK version headers without consuming state', async () => {
  const f = await fixture();
  f.request.headers['x-tsk-version'] = ['1', '1'];
  const denied = await verifyUltraRequest(
    f.request,
    bpcPass(f.pairId),
    { tskStore: f.store, identityBinding: f.identityBinding },
  );
  expect(!denied.ok && denied.error === 'TSK: TSK_VERSION_MISSING', `unexpected error: ${denied.error}`);
  f.request.headers['x-tsk-version'] = '1';
  await retrySameKey(f);
});

test('TSK key failure records only the completed BPC layer', async () => {
  const f = await fixture();
  f.request.headers['x-tsk-key'] = `${f.key.slice(0, -1)}${f.key.endsWith('A') ? 'B' : 'A'}`;
  const result = await verifyUltraRequest(
    f.request,
    bpcPass(f.pairId),
    { tskStore: f.store, identityBinding: f.identityBinding },
  );
  expect(!result.ok, 'tampered TSK key unexpectedly succeeded');
  expect(result.error?.startsWith('TSK: ') === true, `unexpected error: ${result.error}`);
  expect(result.layers.join(',') === 'bpc', 'TSK was incorrectly recorded as successful');
});

test('TSK store exceptions fail closed at the bridge boundary', async () => {
  const f = await fixture();
  const throwingStore = {
    ...f.store,
    get: async () => { throw new Error('authority unavailable'); },
  } as unknown as MemoryTumblerStore;
  const result = await verifyUltraRequest(
    f.request,
    bpcPass(f.pairId),
    { tskStore: throwingStore, identityBinding: f.identityBinding },
  );
  expect(result.outcomeUnknown === true, 'post-verifier uncertainty lost');
  expect(!result.ok && result.error === 'TSK: VERIFIER_EXCEPTION', `unexpected error: ${result.error}`);
  await retrySameKey(f);
});

test('post-verification identity mismatch is a hard denial', async () => {
  const base = await fixture();
  const stored = await base.store.get(base.clientId);
  if (!stored) throw new Error('fixture map missing');

  const mismatchedMap: TumblerMap = { ...stored, clientId: 'tsk_authenticated_other' };
  const mismatchStore = new MemoryTumblerStore();
  await mismatchStore.set(base.clientId, mismatchedMap);
  base.request.headers['x-tsk-key'] = generateKeyFromMap(mismatchedMap);

  const result = await verifyUltraRequest(
    base.request,
    bpcPass(base.pairId),
    { tskStore: mismatchStore, identityBinding: base.identityBinding },
  );
  expect(!result.ok, 'postcheck mismatch unexpectedly succeeded');
  expect(result.outcomeUnknown === true, 'post-verifier uncertainty lost');
  expect(result.error === 'IDENTITY_BINDING_POSTCHECK_MISMATCH', `unexpected error: ${result.error}`);
  expect(result.layers.join(',') === 'bpc,tsk', 'completed layers were not reported accurately');
});

test('security layer metadata remains bounded to seven stated properties', async () => {
  expect(ULTRA_SECURITY_LAYERS.length === 7, 'security layer count changed');
  expect(ULTRA_SECURITY_LAYERS.slice(0, 5).every(layer => layer.source === 'BPC'), 'BPC layer metadata changed');
  expect(ULTRA_SECURITY_LAYERS.slice(5).every(layer => layer.source === 'TSK'), 'TSK layer metadata changed');
  expect(
    ULTRA_SECURITY_LAYERS.every((layer, index) => layer.id === index + 1),
    'security layer IDs are not ordered',
  );
});

test('immutable input and HTTP unknown disposition under AuthSnapshot', async () => {
  const assert = (name: string, condition: unknown, detail = '') => expect(condition, `${name}: ${detail}`);
// ── Group 13: one immutable request snapshot spans every awaited dependency ──
console.log('\n[13] Immutable Request Binding Across Awaits');
{
  const { store: mutationStore, provisioner: mutationProvisioner } = createTSKServer();
  const provisionedA = await mutationProvisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  const provisionedB = await mutationProvisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  if (!provisionedA.ok || !provisionedA.tumblerMap || !provisionedB.ok || !provisionedB.tumblerMap) {
    throw new Error('mutation fixture provision failed');
  }
  const mapA = provisionedA.tumblerMap;
  const mapB = provisionedB.tumblerMap;
  const sharedRequest: TSKRequestData = { headers: {
    'x-tsk-client-id': mapA.clientId,
    'x-tsk-key': generateKeyFromMap(mapA),
    'x-tsk-version': '1',
  } };
  const beforeB = JSON.stringify(await mutationStore.get(mapB.clientId));
  const mutationResult = await verifyUltraRequest(sharedRequest, bpcPass('pair-mutation-a'), {
    tskStore: mutationStore,
    identityBinding: {
      resolve: async pair => {
        if (pair !== 'pair-mutation-a') return null;
        // Reproduce the reviewed shared-request mutation while resolution is
        // awaited. The bridge must still verify the original A snapshot.
        sharedRequest.headers = {
          'x-tsk-client-id': mapB.clientId,
          'x-tsk-key': generateKeyFromMap(mapB),
          'x-tsk-version': '1',
        };
        return mapA.clientId;
      },
    },
  });
  const afterB = JSON.stringify(await mutationStore.get(mapB.clientId));
  assert('resolver-side request mutation cannot redirect TSK verification',
    mutationResult.ok && mutationResult.clientId === mapA.clientId, `Got: ${JSON.stringify(mutationResult)}`);
  assert('mutation negative leaves alternate client map byte-equivalent', beforeB === afterB, 'Client B map changed');
  assert('mutation negative consumes the original bound client once',
    (await mutationStore.get(mapA.clientId))?.requestCount === 1, 'Client A request count was not one');

  const { store: positiveStore, provisioner: positiveProvisioner } = createTSKServer();
  const positiveProvisioned = await positiveProvisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  if (!positiveProvisioned.ok || !positiveProvisioned.tumblerMap) throw new Error('immutable positive fixture provision failed');
  const positiveMap = positiveProvisioned.tumblerMap;
  const positive = await verifyUltraRequest({ headers: {
    'x-tsk-client-id': positiveMap.clientId,
    'x-tsk-key': generateKeyFromMap(positiveMap),
    'x-tsk-version': '1',
  } }, bpcPass('pair-immutable-positive'), {
    tskStore: positiveStore,
    identityBinding: { resolve: async pair => pair === 'pair-immutable-positive' ? positiveMap.clientId : null },
  });
  assert('unchanged bound request remains accepted once',
    positive.ok && (await positiveStore.get(positiveMap.clientId))?.requestCount === 1, `Got: ${JSON.stringify(positive)}`);
}

// ── Group 14: invalid runtime request values fail closed before BPC invocation ──
console.log('\n[14] Invalid Request Snapshot Containment');
{
  const malformed: Array<{ name: string; request: unknown }> = [
    { name: 'missing headers', request: {} },
    { name: 'null headers', request: { headers: null } },
    { name: 'throwing headers getter', request: Object.defineProperty({}, 'headers', {
      get: () => { throw new Error('malformed request secret: never expose'); },
    }) },
  ];
  for (const test of malformed) {
    let bpcCalls = 0;
    const result = await verifyUltraRequest(test.request as TSKRequestData, async () => {
      bpcCalls++;
      return { ok: true, pairId: 'never-reached', snapshot: snapshot('never-reached', 'read') };
    }, { tskStore: new MemoryTumblerStore(), identityBinding: { resolve: async () => null } });
    assert(`${test.name} returns stable request-invalid result`,
      !result.ok && result.error === 'BPC: REQUEST_INVALID' && result.layers.length === 0 && result.outcomeUnknown === undefined,
      `Got: ${JSON.stringify(result)}`);
    assert(`${test.name} exposes no thrown text and skips BPC`,
      bpcCalls === 0 && !JSON.stringify(result).includes('secret'), `Calls=${bpcCalls}, result=${JSON.stringify(result)}`);
  }
}

// ── Group 15: adapter preserves the bridge snapshot and public disposition ──
console.log('\n[15] BPC + TSK HTTP Adapter Boundary');
{
  const responseFor = () => new class {
    headersSent = false; statusCode = 0; payload = ''; readonly headers = new Map<string, unknown>();
    setHeader(name: string, value: unknown) { this.headers.set(name, value); }
    writeHead(status: number) { this.statusCode = status; this.headersSent = true; return this; }
    end(body?: unknown) { this.payload = String(body ?? ''); }
  }();

  const denialResponse = responseFor();
  const denial = await authenticateBpcTskHttpRequest(
    { headers: { 'x-request-id': 'adapter-denial-test' }, socket: { remoteAddress: '127.0.0.1' } } as any,
    denialResponse as any,
    { store: new MemoryTumblerStore(), bpcVerify: async () => ({ ok: false, error: 'REPLAY_DETECTED' }), identityBinding: { resolve: async () => null } },
  );
  assert('ordinary BPC denial retains generic 401 contract',
    denial === null && denialResponse.statusCode === 401 && denialResponse.payload.includes('BPC_TSK_AUTHENTICATION_FAILED') && !denialResponse.payload.includes('retryable'),
    `Got: ${denialResponse.statusCode} ${denialResponse.payload}`);

  const { store: unknownStore, provisioner: unknownProvisioner } = createTSKServer();
  const unknownProvisioned = await unknownProvisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  if (!unknownProvisioned.ok || !unknownProvisioned.tumblerMap) throw new Error('adapter unknown fixture provision failed');
  const unknownMap = unknownProvisioned.tumblerMap;
  const actualUnknownCommit = unknownStore.commitValidation.bind(unknownStore);
  unknownStore.commitValidation = async (id, input) => { await actualUnknownCommit(id, input); throw new Error('adapter store secret: never expose'); };
  const unknownResponse = responseFor();
  const unknown = await authenticateBpcTskHttpRequest(
    { headers: { 'x-request-id': 'adapter-unknown-test', 'x-tsk-client-id': unknownMap.clientId, 'x-tsk-key': generateKeyFromMap(unknownMap), 'x-tsk-version': '1' }, socket: { remoteAddress: '127.0.0.1' } } as any,
    unknownResponse as any,
    { store: unknownStore, bpcVerify: async () => ({ ok: true, pairId: 'adapter-unknown-pair', snapshot: snapshot('adapter-unknown-pair', 'read') }), identityBinding: { resolve: async () => unknownMap.clientId } },
  );
  assert('post-commit unknown reaches HTTP as non-retryable 409',
    unknown === null && unknownResponse.statusCode === 409 && unknownResponse.payload.includes('BPC_TSK_OUTCOME_UNKNOWN') && unknownResponse.payload.includes('"retryable":false'),
    `Got: ${unknownResponse.statusCode} ${unknownResponse.payload}`);
  assert('HTTP unknown result retains one consumption and no secret text',
    (await unknownStore.get(unknownMap.clientId))?.requestCount === 1 && !unknownResponse.payload.includes('secret'),
    `Got: ${unknownResponse.payload}`);

  const { store: adapterStore, provisioner: adapterProvisioner } = createTSKServer();
  const adapterA = await adapterProvisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  const adapterB = await adapterProvisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  if (!adapterA.ok || !adapterA.tumblerMap || !adapterB.ok || !adapterB.tumblerMap) throw new Error('adapter mutation fixture provision failed');
  const adapterRequest: any = { headers: {
    'x-request-id': 'adapter-snapshot-test',
    'x-tsk-client-id': adapterA.tumblerMap.clientId,
    'x-tsk-key': generateKeyFromMap(adapterA.tumblerMap),
    'x-tsk-version': '1',
  }, socket: { remoteAddress: '127.0.0.1' } };
  const adapterBeforeB = JSON.stringify(await adapterStore.get(adapterB.tumblerMap.clientId));
  let bpcObservedClient = '';
  const adapterResponse = responseFor();
  const adapterAuth = await authenticateBpcTskHttpRequest(adapterRequest, adapterResponse as any, {
    store: adapterStore,
    bpcVerify: async incoming => {
      adapterRequest.headers = {
        'x-request-id': 'adapter-snapshot-test',
        'x-tsk-client-id': adapterB.tumblerMap!.clientId,
        'x-tsk-key': generateKeyFromMap(adapterB.tumblerMap!),
        'x-tsk-version': '1',
      };
      bpcObservedClient = incoming.headers['x-tsk-client-id']?.toString() ?? '';
      return { ok: true, pairId: 'adapter-snapshot-pair', snapshot: snapshot('adapter-snapshot-pair', 'read') };
    },
    identityBinding: { resolve: async () => adapterA.tumblerMap!.clientId },
  });
  assert('adapter BPC verifier receives bridge snapshot, not mutable IncomingMessage headers',
    bpcObservedClient === adapterA.tumblerMap.clientId && adapterAuth?.clientId === adapterA.tumblerMap.clientId,
    `Observed=${bpcObservedClient}, auth=${JSON.stringify(adapterAuth)}`);
  assert('adapter mutation leaves alternate client byte-equivalent',
    JSON.stringify(await adapterStore.get(adapterB.tumblerMap.clientId)) === adapterBeforeB,
    'Adapter client B map changed');
}

});

let passed = 0;
for (const candidate of tests) {
  try {
    await candidate.run();
    passed++;
    console.log(`  PASS ${candidate.name}`);
  } catch (error) {
    console.error(`  FAIL ${candidate.name}`);
    console.error(error);
  }
}

console.log(`Ultra bridge strict composition suite: ${passed}/${tests.length} passed`);
if (passed !== tests.length) process.exit(1);
