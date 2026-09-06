# BPC + TSK integration

Use the two protocols together when an API needs both BPC's signed-pair proof
and TSK's server-authoritative, rotating credential state. The bridge requires
both checks and binds the BPC `pairId` to exactly one TSK `clientId`.

The deployment supplies the request/response, stores, and identity directory below.
Use the BPC revision pinned by this repository's compatibility gate; older mutable
verifier results are rejected. For requests with bodies, compute the body hash from
the received bytes and validate it against the signed value before authorization;
a client-supplied hash alone does not bind the actual payload.

```ts
import { authenticateBpcTskHttpRequest } from '@tsk/node-http';
import { verifyBPCRequest } from '@bpc/server';

const auth = await authenticateBpcTskHttpRequest(request, response, {
  store: tskStore,
  bpcVerify: request =>
    verifyBPCRequest(
      {
        pairId: request.headers['x-bpc-pair-id']?.toString() ?? null,
        signedData: request.headers['x-bpc-signed-data']?.toString() ?? null,
        signature: request.headers['x-bpc-signature']?.toString() ?? null,
        version: request.headers['x-bpc-version']?.toString() ?? null,
        method: request.method ?? 'GET',
        path: request.url ?? '/',
        bodyHash: request.headers['x-bpc-body-hash']?.toString() ?? null,
        ip: request.socket.remoteAddress,
      },
      registry,
      nonceStore,
      anomaly,
    ),
  identityBinding: {
    resolve: pairId => customerDirectory.lookupTskClientId(pairId),
  },
});
if (!auth) return;

// BPC's closed scope travels with the authenticated identity. Enforce it here.
if (auth.scope === 'read' && request.method !== 'GET') {
  response.writeHead(403).end();
  return;
}
```

The integration must meet these invariants:

- Reject BPC failure before TSK counter state is consumed.
- Reject a missing or mismatched `pairId → clientId` binding.
- Treat `read`, `read-write`, and `admin` as closed BPC scopes; never promote a
  scope based on a client-supplied string.
- Apply normal resource authorization after protocol authentication.
- Provision and rotate the BPC pair and TSK credential through separate,
  audited ceremonies; neither protocol delivers the other's secret material.

`authenticateBpcTskHttpRequest` performs the first three checks and returns the
verified BPC scope. Resource authorization remains the customer application's
responsibility by design.
