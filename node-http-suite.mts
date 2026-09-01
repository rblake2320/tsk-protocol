import { createServer } from 'node:http';
import { once } from 'node:events';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import { MemoryTumblerStore } from './packages/server/src/store.js';
import { TSKProvisioner } from './packages/server/src/provisioner.js';
import {
  authenticateBpcTskHttpRequest,
  authenticateTSKHttpRequest,
  createCredentialAdminHandler,
} from './packages/node-http/src/index.js';

let passed = 0;
function assert(condition: unknown, name: string): asserts condition {
  if (!condition) throw new Error(name);
  passed++;
  console.log(`  PASS ${name}`);
}

const store = new MemoryTumblerStore();
const provisioner = new TSKProvisioner(store, { lifecycleAuthorizer: async () => true });
const delivered: Array<{ clientId: string; sharedSecret: string }> = [];
const admin = createCredentialAdminHandler({
  provisioner,
  authenticateOperator: async request => request.headers.authorization === 'Bearer operator-test-token' ? { operatorId: 'test-operator' } : null,
  deliverCredential: async credential => { delivered.push({ clientId: credential.clientId, sharedSecret: credential.sharedSecret }); },
});

const server = createServer(async (request, response) => {
  if (await admin(request, response)) return;
  if (request.url === '/protected') {
    const auth = await authenticateTSKHttpRequest(request, response, { store });
    if (!auth) return;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ clientId: auth.clientId }));
    return;
  }
  if (request.url === '/bpc-protected') {
    const auth = await authenticateBpcTskHttpRequest(request, response, {
      store,
      bpcVerify: async () => ({ ok: true, pairId: 'bpc-pair-test', scope: 'read' }),
      identityBinding: { resolve: async pairId => pairId === 'bpc-pair-test' ? request.headers['x-tsk-client-id']?.toString() ?? null : null },
    });
    if (!auth) return;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ clientId: auth.clientId, pairId: auth.pairId, scope: auth.scope }));
    return;
  }
  response.writeHead(404).end();
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const address = server.address();
if (!address || typeof address === 'string') throw new Error('test server did not bind');
const base = `http://127.0.0.1:${address.port}`;

try {
  const unauthenticated = await fetch(`${base}/v1/credentials`);
  assert(unauthenticated.status === 401, 'admin routes require deployment-owned operator authentication');

  const provision = await fetch(`${base}/v1/credentials`, {
    method: 'POST',
    headers: { authorization: 'Bearer operator-test-token', 'content-type': 'application/json' },
    body: JSON.stringify({ keyLength: 64, minTumblers: 2, maxTumblers: 2, label: 'customer-a' }),
  });
  const provisionBody = await provision.json() as { data?: { clientId?: string }; meta?: { requestId?: string } };
  assert(provision.status === 201 && !!provisionBody.data?.clientId, 'authorized operator provisions a credential');
  assert(!!provisionBody.meta?.requestId, 'admin response has a request id');
  assert(!JSON.stringify(provisionBody).includes('sharedSecret'), 'admin HTTP response never contains a shared secret');
  assert(delivered.length === 1 && delivered[0].clientId === provisionBody.data?.clientId, 'credential is delivered only through the configured secure callback');

  const listed = await fetch(`${base}/v1/credentials`, { headers: { authorization: 'Bearer operator-test-token' } });
  const listedText = await listed.text();
  assert(listed.status === 200 && !listedText.includes(delivered[0].sharedSecret), 'credential listing contains no secret material');

  const map = await store.get(provisionBody.data!.clientId!);
  if (!map) throw new Error('provisioned map missing');
  const key = generateKeyFromMap(map);
  const protectedResponse = await fetch(`${base}/protected`, {
    headers: { 'x-tsk-client-id': map.clientId, 'x-tsk-key': key, 'x-tsk-version': '1' },
  });
  assert(protectedResponse.status === 200, 'protected route accepts a valid TSK credential');
  assert(protectedResponse.headers.get('x-tsk-authenticated') === '1', 'protected response confirms authenticated TSK use');

  const updatedMap = await store.get(map.clientId);
  if (!updatedMap) throw new Error('authenticated map missing');
  const bpcResponse = await fetch(`${base}/bpc-protected`, {
    headers: { 'x-tsk-client-id': updatedMap.clientId, 'x-tsk-key': generateKeyFromMap(updatedMap), 'x-tsk-version': '1' },
  });
  const bpcBody = await bpcResponse.json() as { scope?: string; pairId?: string };
  assert(bpcResponse.status === 200 && bpcBody.scope === 'read' && bpcBody.pairId === 'bpc-pair-test', 'BPC and TSK authenticate together with an identity binding');
  assert(bpcResponse.headers.get('x-tsk-authenticated') === '1', 'BPC+TSK response confirms TSK authentication for the client SDK');

  const rejected = await fetch(`${base}/protected`);
  const rejectedBody = await rejected.json() as { error?: { code?: string } };
  assert(rejected.status === 401 && rejectedBody.error?.code === 'TSK_AUTHENTICATION_FAILED', 'protected route returns a generic failure without credential detail');
} finally {
  server.close();
  await once(server, 'close');
}

console.log(`TSK Node HTTP integration suite: ${passed}/${passed} passed`);
