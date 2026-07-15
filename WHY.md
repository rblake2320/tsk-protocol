# Design Decisions

## 2026-07-15: Security does not depend on layout secrecy

Ordered lengths reveal cumulative boundaries. The client contract and active
claims now say so. The security boundary is shared-secret possession plus
server-authoritative rotating state.

## 2026-07-15: Commit validation state atomically

Multiple HOTP counters, `requestCount`, and cap state represent one accepted
request. Partial writes can desynchronize clients or cross a cap. Stores must
commit the vector as one transaction or fail closed.

## 2026-07-15: Warn before the cap; never permit grace after it

The server returns a rotation-required signal inside a configured window.
Replacement requires an external authorizer and atomically revokes the old key.
Automatic issuance or post-cap acceptance was rejected.

## 2026-07-15: Treat numeric HOTP exhaustion as a separate lifecycle boundary

`maxRequests` limits credential usage by policy; the moving-factor counter has
its own finite representation. Wire v1 keeps its existing 31-bit project limit:
MAX is an exhausted stored sentinel, the last legal derivation commits MAX, and
lookahead never crosses it. The segment with the least capacity governs the
warning. Replacement remains externally authorized and atomic; normal traffic
cannot auto-issue a credential. Expanding to RFC 4226's 8-byte counter would
require BigInt/canonical encoding and is therefore a wire-v2 decision.

## 2026-07-15: Authentication acceptance controls client counters

Business status and authentication status are different. An authenticated
request can legitimately produce HTTP 500 after the server consumed its
counter. Explicit response confirmation prevents permanent counter drift.

## 2026-07-15: Separate implementation evidence from authorization claims

Tests establish finite propositions. FIPS validation, compliance, Impact Level
authorization, patent status, and legal conclusions require external evidence.

## 2026-07-15: Enforce fencing at the store boundary

A promotion controller that callers may bypass is not a control. All
authoritative mutation methods are now available through `FencedTumblerStore`,
which rechecks the shared lease before delegating. Redis Lua transitions provide
an atomic multi-process reference authority; deployments still own Redis
security, persistence, and topology.

## 2026-07-15: Volatile replication can never authorize promotion

An in-memory retry queue cannot prove recovery after process loss, and a Redis
list beside a separate primary database would introduce an unfixable dual-write
window. Promotion therefore returns no checkpoint unless the deployment binds
the mutation/outbox and apply/checkpoint pairs into durable transactions and
supplies the explicit durability check.

## 2026-07-15: Release evidence must not depend on floating CI inputs

Major-version action tags and mutable container tags can change without a
repository commit. The protocol workflow pins GitHub Actions by commit and the
Redis service by digest so a repeated run resolves the same reviewed inputs.

## 2026-07-15: Keep only maintained production-code tests in the release gate

Historical red-team scripts remain useful for understanding how earlier flaws
were discovered, but several duplicated protocol logic or expected behavior
that was deliberately removed. They are parked rather than deleted. Active
security evidence must call current packages, have deterministic pass
conditions, and run in CI.

## 2026-07-15: Test on a supported LTS runtime

Node 20 no longer receives upstream security fixes. TSK now uses Node 24 LTS as
its explicit build, type, test, and CI baseline so a green release gate does not
depend on an end-of-life runtime.

## 2026-07-15: Package entry points are executable release boundaries

A successful source-tree build does not prove an installable package. Each
workspace now rebuilds before packing, publishes only `dist`, and has its
declared runtime and type entry points checked for existence and runtime import.
This prevents a tarball from passing a dry run while omitting or misplacing the
files that consumers load.
