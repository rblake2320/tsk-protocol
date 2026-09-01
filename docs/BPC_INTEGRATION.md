# BPC + TSK integration

Use the two protocols together when an API needs both BPC's signed-pair proof
and TSK's server-authoritative, rotating credential state. The bridge requires
both checks and binds the BPC `pairId` to exactly one TSK `clientId`.

```ts
import { authenticateBpcTskHttpRequest } from '@tsk/node-http';

const auth = await authenticateBpcTskHttpRequest(request, response, {
  store: tskStore,
  bpcVerify: request => verifyBPCRequest(toBpcRequest(request), registry, nonceStore, anomaly),
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
