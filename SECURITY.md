# TSK Security Policy

## Status

TSK `0.1.x` is a beta reference implementation. Report vulnerabilities through
[GitHub Security Advisories](https://github.com/rblake2320/tsk-protocol/security/advisories/new),
not a public issue.

## Current Security Properties

| Property | Executable evidence | Boundary |
|---|---|---|
| Secret and time-input validation | `attack-suite.mts` | Requires exactly 32 random bytes encoded as 64 hex characters and rejects non-finite authentication times. |
| Integrity tag | `test-suite.mts`, `attack-suite.mts` | Truncated HMAC-SHA-256 detects tested mutations; it is not a signature. |
| Counter replay rejection | `lifecycle-suite.mts`, `adversarial-proof.mts` | Requires a store with atomic `commitValidation()`. |
| Usage cap | `lifecycle-suite.mts` | Atomic with all counter updates in bundled stores. |
| Pre-cap replacement | `lifecycle-suite.mts` | Disabled unless a deployment supplies an authorizer. No grace mode. |
| Numeric HOTP exhaustion | `hotp-exhaustion-suite.mts` | Wire v1 uses a project-specific 31-bit counter ceiling; MAX is an exhausted sentinel, not a usable derivation input. |
| Authentication header ambiguity | `ultra-bridge-test.mts` | Client, key, and version headers must each contain exactly one value; duplicates fail before validation commits state. |
| Restart persistence | `client-lifecycle-suite.mts` | File store is single-process and relies on host file protections. |
| HA replication | `npm run test:ha` | Signed ordered streams fail closed on gaps; metadata-only replicas and volatile checkpoints cannot qualify for promotion. |
| Writer fencing | `failover-promotion-suite.mts`, `redis-fencing-integration.mts` | Every authority must use `FencedTumblerStore`; Redis durability/topology remains deployment-specific. |
| Cross-protocol identity and scope | `ultra-bridge-test.mts`, `bpc-compatibility-suite.mts` | Requires a fresh, frozen BPC 0.2 `AuthSnapshot`; rejects legacy mutable results, ghost/shadow evidence, non-closed scopes, malformed identifiers, resolver failures, and claimed-identity mismatches before TSK state consumption. Application authorization remains separate. CI tests the exact BPC commit pinned in the workflow. |
| Bridge dependency failure | `ultra-bridge-test.mts` | BPC callback, identity resolver, and TSK verifier/store exceptions return explicit denials; durable store recovery and availability remain deployment responsibilities. |
| Package entry integrity | `package-boundary-suite.mts`, `npm run test:pack` | Verifies declared local entry points and dry-run tarball contents; it does not establish registry provenance or consumer deployment policy. |

Passing finite tests establishes only the named propositions and inputs. It does
not prove the absence of other attacks.

## Corrected Claims

- The provisioned client receives ordered segment lengths and can reconstruct
  the boundaries. Earlier structural-secrecy wording was false and is parked.
- The integrity tag is truncated HMAC-SHA-256, not Ed25519.
- TSK segment derivation is not RFC 4226/6238 HOTP/TOTP interoperability.
- Node's cryptographic API does not by itself establish that a deployment uses a
  CMVP-validated module in an approved mode and environment.
- No repository test establishes DoD Impact Level authorization, an ATO,
  regulatory compliance, legal admissibility, or production readiness.

## Deployment Requirements

1. Protect provisioning with authenticated, authorized administration and a
   confidential transport.
2. Store the shared secret in deployment-approved secret storage.
3. Use a durable store whose `commitValidation()` is atomic across every counter
   and lifecycle field. The bundled memory and file stores are single-process.
4. Apply `buildTSKResponseHeaders()` to final HTTP responses so clients commit
   counters on authentication acceptance rather than business status.
5. Configure request caps and replace credentials before the warning window
   closes. Also monitor `X-TSK-HOTP-Counters-Remaining`; this counter-capacity
   signal exists even when `maxRequests` is unset. Do not add a post-expiry
   permissive grace path.
6. Protect replica endpoints, promotion credentials, persistence, backups, and
   recovery operations as separate authorization boundaries.
7. Put the primary mutation and replication outbox in one durable transaction,
   and persist receiver state plus its checkpoint atomically. The in-memory
   queue is not a production transactional outbox.
8. Wrap every authoritative store reference with `FencedTumblerStore` and use a
   shared atomic `FencingStore`. The Redis implementation retains expired epoch
   tombstones intentionally; configure Redis persistence, ACLs, TLS, and HA.
9. Treat anomaly scores as telemetry, not proof that a request is safe.
10. Enforce the returned BPC scope at the application authorization boundary.
    Bridge success authenticates a closed coarse scope; it does not authorize
    arbitrary application actions by itself.
11. Treat BPC `verify_pass` and `verify_fail` audit entries as evidence of the
    BPC stage only. The deployment must durably record the final Ultra decision
    and downstream authorization result; this bridge does not provide a
    transactional cross-protocol audit store.

## Known Limits

- A compromised client or server that exposes the shared secret can generate
  credential values.
- Application authorization remains mandatory after authentication.
- The file stores do not coordinate multiple processes or hosts.
- The default metadata-only replica cannot take over cryptographic validation.
- The bundled replication queue and checkpoint fields are volatile. Promotion
  stays disabled unless the deployment supplies positive durability evidence.
- The library does not supply TLS termination, operator identity, an HSM/TPM
  integration, external ledger anchoring, or an authorization package.
- BPC audit events do not assert that identity binding, TSK verification, or
  application authorization succeeded. Those later decisions require their
  own deployment evidence.
- Wire v1 intentionally uses a JavaScript-safe project counter ceiling rather
  than RFC 4226's full 8-byte moving-factor range. A wider counter requires a
  new wire/storage version and migration; it cannot be enabled in place.

Historical findings remain in
`parked/legacy-redteam/Adversarial_Break_Report.md`; superseded claims,
simulations, and restoration criteria are recorded in `PARKED.md`.
