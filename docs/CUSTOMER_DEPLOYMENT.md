# Customer deployment guide

TSK is an **embedded authentication component** for a Node.js API. It is not a
hosted identity provider and does not replace TLS, customer identity, endpoint
authorization, or secret-vault controls.

## What a customer installs

Publish the four packages to the customer's private npm registry (or hand over
the workspace tarballs produced by `npm pack --workspaces`):

```text
@tsk/core        credential derivation and validation primitives
@tsk/server      authoritative credential state and lifecycle logic
@tsk/client-sdk  client request generation and counter persistence
@tsk/node-http   secure Node HTTP authentication and lifecycle adapter
```

For BPC composition, also install the reviewed `@bpc/*` packages and
`@tsk/bpc-bridge`. They are separate products with separately managed release
and support boundaries.

## Supported deployment shape today

The bounded local deployment uses an encrypted host volume and `FileTumblerStore`.
Each operation acquires an exclusive file lock and reloads persisted authority;
successful writes fsync the candidate before rename and live publication. Tested
Windows cases cover restart, failed rename, competing instances/processes, malformed
state and inherited object-property names. See `FILE_STORE_EVIDENCE.md` for scope.

Contended or abandoned locks fail closed without automatic retry or age-based
removal. No stale-lock recovery command is shipped: an operator must resolve the
owning process and retained state before reuse. Power-loss/directory-fsync,
network-filesystem, malicious filesystem replacement, and sustained multi-process
deployment are not certified by these tests. Do not deploy behind multiple replicas
on the strength of the two-process contention check.

For a multi-replica deployment, the customer needs a durable store that
implements `TumblerMapStore.commitValidation()` and `replaceCredential()` as
single database transactions, plus the separately tested Redis fencing path.
Do not market that topology as supported until the selected store has a live
integration transcript and recovery drill.

## Required customer controls

| Control | Customer responsibility |
|---|---|
| Transport | Terminate TLS before the application; redirect/reject plaintext HTTP. |
| Operator identity | Implement `authenticateOperator` with their OIDC, mTLS, or gateway identity. |
| Credential delivery | Implement `deliverCredential` to write the generated secret to their vault or protected onboarding channel. Do not return it from an API response. |
| Server-state protection | Use an encrypted host volume; restrict the TSK data directory to the service identity. |
| Authorization | After TSK authentication, authorize the resolved client against the requested resource. TSK alone authenticates a client; it does not grant application permissions. |
| Logging | Send request IDs and lifecycle audit events to the customer's protected log system. Never log TSK keys or shared secrets. |

## Minimal Node integration

```ts
import { createServer } from 'node:http';
import { FileTumblerStore, TSKProvisioner } from '@tsk/server';
import { authenticateTSKHttpRequest, createCredentialAdminHandler } from '@tsk/node-http';

const store = new FileTumblerStore(process.env.TSK_STATE_FILE!); // absolute encrypted-volume path
const provisioner = new TSKProvisioner(store, {
  lifecycleAuthorizer: async request => customerPolicyAllows(request),
});

const admin = createCredentialAdminHandler({
  provisioner,
  authenticateOperator: async request => validateCustomerOidcOrMtls(request),
  deliverCredential: async (credential, operator) => {
    await customerVault.writeOnboardingCredential(credential, operator.operatorId);
  },
});

createServer(async (request, response) => {
  if (await admin(request, response)) return;
  if (request.url?.startsWith('/api/')) {
    const auth = await authenticateTSKHttpRequest(request, response, { store });
    if (!auth) return;
    if (!await customerAuthorizer.can(auth.clientId, request.method!, request.url!)) {
      response.writeHead(403).end();
      return;
    }
    response.end('customer application response');
    return;
  }
  response.writeHead(404).end();
}).listen(Number(process.env.PORT ?? 8080), '127.0.0.1');
```

`TSK_STATE_FILE`, TLS termination, OIDC/mTLS configuration, and the secret-vault
integration are mandatory deployment inputs. The sample intentionally has no
default operator token and no secret-returning route.

## Release acceptance checklist

Before a customer production release, retain the following evidence:

1. `npm ci`, build, typecheck, full test, HA, Redis, and BPC compatibility
   transcripts for the exact release commit.
2. A clean-consumer tarball install and a customer application smoke test.
3. A vault-delivery test proving credential material does not enter HTTP
   responses or ordinary logs.
4. Restore, rotation, and revocation drills against the customer's selected
   durable store.
5. A security review covering their TLS termination, operator authentication,
   authorization policy, and secret custody.

## Commercial decision gates

The repository has no explicit commercial license, support policy, SLA, data
processing terms, or vulnerability-disclosure commitment. Those are legal and
commercial decisions for the owner; do not represent them as present.
