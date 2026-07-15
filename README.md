# TSK Protocol

TSK is a beta reference implementation of shared-secret API credentials made
from independently derived static, time-window, and counter-based segments.
The server retains authoritative counter and lifecycle state.

## Established Behavior

- HMAC-SHA-256 derives every segment and a 12-character truncated integrity tag.
- Generated maps contain at least one counter-based segment.
- One atomic store commit advances all matched counters and the credential usage
  count; a concurrent duplicate is denied.
- Expiry, revocation, hard request caps, and a pre-cap rotation signal are
  enforced by the server middleware.
- Wire v1 bounds every HOTP counter to `0..2,147,483,647`. The maximum is an
  exhausted persisted sentinel, lookahead never crosses it, and the segment
  closest to exhaustion drives a separate rotation warning.
- Replacement requires a deployment-supplied authorizer and atomically creates
  the new credential while revoking the old one.
- File-backed client storage persists counters across restarts with atomic file
  replacement.
- The BPC bridge denies when independently verified BPC and TSK identities do
  not resolve to the same principal.
- HA envelopes are signed, hash-linked, ordered, and checked for freshness.
- `FencedTumblerStore` makes shared writer leases mandatory at the store
  mutation boundary; `RedisFencingStore` provides an atomic cross-process
  authority verified against Redis 7.4.

These are bounded properties established by named tests. They are not a claim
that the protocol, host, deployment, or product is compliant or unbreakable.

## Important Boundaries

- TSK is a symmetric protocol. Provisioning transfers the shared secret to the
  client through a deployment-controlled protected channel.
- Ordered segment lengths reveal cumulative segment boundaries. Layout is not a
  secret authentication factor.
- The checksum is a truncated HMAC-SHA-256 tag, not Ed25519 and not a digital
  signature.
- The time/counter schedules are inspired by TOTP/HOTP, but segment derivation
  uses project-specific HMAC-SHA-256 inputs and does not emit RFC OTP codes.
- TLS, endpoint authorization, secret custody, durable distributed stores,
  monitoring, and recovery are deployment responsibilities.
- Promotion evidence is unavailable by default. A deployment must prove that
  primary mutations, replication operations, receiver applies, and checkpoints
  are transactionally durable before supplying the promotion durability hook.
- Algorithm selection does not establish FIPS 140 validation. Tests and control
  mappings do not create an ATO or DoD Impact Level authorization.

See [SECURITY.md](SECURITY.md), [WHY.md](WHY.md), and [PARKED.md](PARKED.md).

## Packages

- `@tsk/core`: map generation, key assembly, and validation.
- `@tsk/server`: stores, verification, lifecycle, replacement, HA, and promotion.
- `@tsk/client-sdk`: client key generation and persistent counter handling.
- `@tsk/bpc-bridge`: composed BPC/TSK verification with identity binding.

## HTTP Adapter Contract

After `verifyTSKRequest()` succeeds, apply the headers returned by
`buildTSKResponseHeaders()` to the final response, including non-2xx application
responses. The client advances counters only when it receives
`X-TSK-Authenticated: 1`; a bare `2xx` is not sufficient.

When `X-TSK-Rotation-Required: 1` is present, provision an authorized
replacement before either `X-TSK-Requests-Remaining` or
`X-TSK-HOTP-Counters-Remaining` reaches zero. The usage-cap header is omitted
when no `maxRequests` cap exists. There is no post-cap or post-counter grace
mode.

## Verification

Validation baseline: Node 24 LTS.

```powershell
npm ci
npm run build
npm run typecheck
npm test
npm run test:ha
npm run test:redis
npm run test:pack
npm audit
```

Current package version: `0.1.0` (beta reference implementation). Wire protocol
version: `1`.
