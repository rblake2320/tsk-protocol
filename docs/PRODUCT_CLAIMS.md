# Product claims and evidence boundary

Status: release-facing policy. Marketing, demos, sales material, and generated
reports must use the supported claims below and must not use the prohibited
claims.

## Supported claims

| Claim | Evidence required for a release |
|---|---|
| TSK is Node.js software; it has no LLM or AI-harness runtime dependency. | `npm ci && npm run build && npm test` under a normal Node shell. |
| TSK derives HMAC-SHA-256-based credential segments from a shared secret, time windows, and counter state. | Core suite and `live-demo.mts`; source is `@tsk/core`. |
| The server can reject malformed, expired, revoked, capped, and previously consumed counter-based credentials when its state store provides the required atomic commit. | Lifecycle and adversarial suites plus a store-specific integration test. |
| `@tsk/node-http` requires deployment-owned operator authentication and a secure credential-delivery callback; it does not return the shared secret in its lifecycle HTTP response. | `npm run test:http`. |
| The BPC bridge checks BPC before TSK and requires a `pairId → clientId` binding. | `npm run test:bpc-compat` against the reviewed BPC release and `npm run test:http`. |

These are implementation claims, not a warranty. They are true only for the
tested release, configured options, and supported deployment topology.

## Prohibited claims

Do **not** say TSK is “unbreakable,” “100% secure,” “guaranteed replay-proof,”
“phishing-resistant,” “FIPS validated,” “NIST compliant/certified,” “HIPAA,
PCI, FedRAMP, or DoD approved,” “patented,” “patent-pending,” “novel,” or
“free of third-party patent rights” unless independent evidence specifically
establishes that exact claim.

Do **not** call TSK an RFC 4226/6238 implementation. It uses project-specific
HMAC-SHA-256 segment construction inspired by counter/time moving factors; it
does not emit the standardized HOTP/TOTP OTP wire format.

Do **not** say every test uses a live external system. Unit/contract suites use
in-process stores, callbacks, and test doubles where stated. Redis, BPC, and
any customer-selected durable store need their own release evidence.

## Security boundary

HOTP/TOTP-style counter/time moving factors and shared-secret verification are
established techniques, not a claim of invention. RFC 4226 requires counter
synchronization and secure shared-secret management; RFC 6238 calls for a
protected channel and secure key storage. NIST’s current guidance likewise
requires a protected channel and distinguishes replay resistance from phishing
resistance and verifier-compromise resistance. TSK therefore requires TLS,
secure provisioning, secret storage, rate limiting, authorization, monitoring,
and a transactionally correct state store supplied by the deployment.

## Patent and legal position

This repository contains no patent grant, application, opinion, clearance, or
freedom-to-operate determination. The use of HMAC, shared secrets, time-based
and counter-based credentials is visibly covered by substantial prior art,
including RFC 4226 and RFC 6238. A preliminary public search also identified
published work concerning time-/counter-based expiring HMACs. That does not
answer whether a particular product design infringes an in-force claim.

Before filing or selling on a patent-related statement, the owner must engage a
registered patent practitioner for a claim-by-claim prior-art and
freedom-to-operate review. Use USPTO Patent Public Search and the controlling
application/assignment records; do not treat a web search or this document as a
legal opinion.

## Release evidence bundle

Attach the exact commit, package checksums, Node version, all test transcripts,
dependency audit, BPC revision, store integration transcript, and a redacted
secret-delivery test. A failed, skipped, mocked, or unavailable integration
must be labelled as such—not converted into a pass in sales material.
