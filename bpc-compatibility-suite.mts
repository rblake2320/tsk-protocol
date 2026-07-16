import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// Cross-repository compatibility must exercise the built package boundaries,
// not TypeScript source paths that consumers cannot import.
import { verifyUltraRequest } from './packages/bpc-bridge/dist/index.js';
import { generateKeyFromMap } from './packages/core/dist/index.js';
import { createTSKServer, type TSKRequestData } from './packages/server/dist/index.js';

const bpcRepo = path.resolve(process.env['BPC_PROTOCOL_PATH'] ?? '../bpc-protocol');
const emptyBodyHash = 'sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';
let passed = 0;

function assert(condition: unknown, name: string): asserts condition {
  if (!condition) throw new Error(name);
  passed++;
  console.log(`  PASS ${name}`);
}

async function manifest(relativePath: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path.join(bpcRepo, relativePath), 'utf8')) as Record<string, unknown>;
}

async function importBPC(relativePath: string): Promise<Record<string, any>> {
  const url = pathToFileURL(path.join(bpcRepo, relativePath)).href;
  return import(url) as Promise<Record<string, any>>;
}

const bpcRoot = await manifest('package.json');
const bpcServerManifest = await manifest('packages/server/package.json');
const bridgeManifest = JSON.parse(
  await readFile(path.resolve('packages/bpc-bridge/package.json'), 'utf8'),
) as { peerDependencies?: Record<string, string> };

assert(bpcRoot['version'] === '0.2.0', 'BPC root is the reviewed 0.2.0 package line');
assert(bpcServerManifest['version'] === '0.2.0', '@bpc/server is version 0.2.0');
assert(
  bridgeManifest.peerDependencies?.['@bpc/server'] === '^0.2.0',
  'TSK bridge peer range matches the reviewed BPC 0.2 package line',
);

const bpcCore = await importBPC('packages/core/dist/index.js');
const bpcServer = await importBPC('packages/server/dist/index.js');
const bpcClientPackage = await importBPC('packages/client-sdk/dist/index.js');

const bpc = bpcServer['createBPCServer']();
const secret = 'BPC-TSK-compatibility-secret-2026';
const keypair = await bpcCore['generateKeypair']();
const secretHash = await bpcCore['hashSecret'](secret);
const pairId = await bpc.registry.registerDirect({
  name: 'bpc-tsk-compatibility',
  scope: 'read',
  mode: 'development',
  secretHash,
  pubJwk: keypair.pubJwk,
});

let wildcardRejected = false;
try {
  await bpc.registry.updatePair(pairId, { scope: 'read:*' });
} catch {
  wildcardRejected = true;
}
assert(wildcardRejected, 'actual BPC package rejects wildcard scope updates');

const client = new bpcClientPackage['BPCClient']({
  serverUrl: 'http://127.0.0.1',
  pairId,
  keypair,
  secret,
});

function bpcRequest(headers: Record<string, string>) {
  return {
    pairId: headers['X-BPC-Pair-ID'],
    signedData: headers['X-BPC-Signed-Data'],
    signature: headers['X-BPC-Signature'],
    version: headers['X-BPC-Version'],
    method: 'GET',
    path: '/api/data',
    bodyHash: emptyBodyHash,
    ip: '127.0.0.1',
  };
}

let observedBpcResult: Record<string, any> | undefined;

function verifyBPC(headers: Record<string, string>) {
  const request = bpcRequest(headers);
  return async () => {
    const result = await bpcServer['verifyBPCRequest'](
      request,
      bpc.registry,
      bpc.nonceStore,
      bpc.anomaly,
      { sigWindowMs: 60_000, enableTarpit: false, auditLog: bpc.auditLog },
    );
    observedBpcResult = result;
    return result;
  };
}

const tsk = createTSKServer();
const provisioned = await tsk.provisioner.provision({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
if (!provisioned.ok || !provisioned.tumblerMap) throw new Error('TSK provisioning failed');
const tskMap = provisioned.tumblerMap;
const identityBinding = {
  resolve: async (candidatePairId: string) => candidatePairId === pairId ? tskMap.clientId : null,
};

function tskRequest(key: string): TSKRequestData {
  return {
    headers: {
      'x-tsk-client-id': tskMap.clientId,
      'x-tsk-key': key,
      'x-tsk-version': '1',
    },
  };
}

const firstBpcHeaders = await client.signRequest('GET', '/api/data');
const firstTSKKey = generateKeyFromMap(tskMap);
const first = await verifyUltraRequest(
  tskRequest(firstTSKKey),
  verifyBPC(firstBpcHeaders),
  { tskStore: tsk.store, identityBinding },
);
assert(first.ok, 'real BPC and TSK packages accept one identity-bound request');
assert(first.scope === 'read', 'real BPC closed scope propagates through the TSK bridge');
assert(observedBpcResult?.['pairId'] === pairId, 'real BPC result identifies the registered pair');
assert(observedBpcResult?.['snapshot']?.pairId === pairId, 'real BPC snapshot identity agrees with result identity');
assert(Object.isFrozen(observedBpcResult?.['snapshot']), 'real BPC authorization snapshot is runtime-frozen');
assert(!('pair' in (observedBpcResult ?? {})), 'real BPC result does not expose a mutable legacy pair');

const initialAudit = bpc.auditLog.snapshot();
const firstPass = initialAudit.at(-1);
assert(firstPass?.action === 'verify_pass', 'real BPC success emits verify_pass');
assert(firstPass?.pairId === pairId, 'BPC success audit identifies the authenticated pair');
assert(firstPass?.method === 'GET' && firstPass?.path === '/api/data', 'BPC success audit binds method and path');

const currentMap = await tsk.store.get(tskMap.clientId);
if (!currentMap) throw new Error('TSK state disappeared after composed verification');
const reusableTSKKey = generateKeyFromMap(currentMap);
const replayedBpcHeaders = await client.signRequest('GET', '/api/data');
const replayedRequest = bpcRequest(replayedBpcHeaders);
const consumed = await bpcServer['verifyBPCRequest'](
  replayedRequest,
  bpc.registry,
  bpc.nonceStore,
  bpc.anomaly,
  { sigWindowMs: 60_000, enableTarpit: false, auditLog: bpc.auditLog },
);
assert(consumed.ok, 'actual BPC package consumes the first use of a signed nonce');

const replay = await verifyUltraRequest(
  tskRequest(reusableTSKKey),
  verifyBPC(replayedBpcHeaders),
  { tskStore: tsk.store, identityBinding },
);
assert(!replay.ok && replay.error === 'BPC: replay_detected', 'composed verifier rejects an actual BPC replay');
assert(replay.layers.length === 0, 'BPC replay rejection occurs before TSK validation');

const replayAudit = bpc.auditLog.snapshot();
const replayFailure = replayAudit.at(-1);
assert(replayFailure?.action === 'verify_fail', 'real BPC replay emits verify_fail');
assert(replayFailure?.error === 'replay_detected', 'BPC replay audit records the bounded denial reason');
assert(replayFailure?.pairId === pairId, 'BPC replay audit identifies the denied pair');
assert(replayFailure?.method === 'GET' && replayFailure?.path === '/api/data', 'BPC replay audit binds method and path');
assert((await bpc.auditLog.verifyChain()).valid, 'real BPC audit chain verifies after success and replay denial');

const replacementBpcHeaders = await client.signRequest('GET', '/api/data');
const afterReplay = await verifyUltraRequest(
  tskRequest(reusableTSKKey),
  verifyBPC(replacementBpcHeaders),
  { tskStore: tsk.store, identityBinding },
);
assert(afterReplay.ok, 'TSK key remains usable after BPC rejects a replay');

console.log(`BPC/TSK package compatibility suite: ${passed}/${passed} passed`);
