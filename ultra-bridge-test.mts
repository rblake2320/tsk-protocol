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
      identityBinding: override?.identityBinding ?? f.identityBinding,
    },
  );
  expect(!denied.ok, 'preflight unexpectedly succeeded');
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

test('rejects stale authorization snapshots before TSK', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_AUTH_SNAPSHOT',
    f => async () => ({
      ok: true,
      pairId: f.pairId,
      snapshot: Object.freeze({
        pairId: f.pairId,
        scope: 'read',
        mode: 'production',
        kind: 'legitimate',
        verifiedAt: Date.now() - 60_001,
      }),
    }),
  );
});

test('rejects future-dated authorization snapshots before TSK', async () => {
  await expectPreflightDenial(
    'BPC: INVALID_AUTH_SNAPSHOT',
    f => async () => ({
      ok: true,
      pairId: f.pairId,
      snapshot: Object.freeze({
        pairId: f.pairId,
        scope: 'read',
        mode: 'production',
        kind: 'legitimate',
        verifiedAt: Date.now() + 60_001,
      }),
    }),
  );
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
