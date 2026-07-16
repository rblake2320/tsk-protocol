# Change Log

## 2026-07-15 - Strict BPC/TSK composition closure

- Rebased the coordinated BPC/TSK bridge work onto TSK `master` after the
  numeric HOTP boundary fix, preserving that counter hardening.
- Replaced mutable BPC `pair` and direct-scope fallbacks with the runtime-frozen
  BPC 0.2 `AuthSnapshot` contract pinned at BPC commit
  `005c461dbacfc079f3a559110e6fb5486fcfd200`.
- Added fail-closed runtime checks for hostile result objects, stale or
  future-dated snapshots, malformed pair/client IDs, unknown modes,
  ghost/shadow evidence, wildcard/namespaced scopes, resolver failures, and
  duplicate or mismatched TSK client headers.
- Closed an adjacent header-ambiguity path: duplicate TSK key and version
  values are now denied instead of accepting the first adapter-provided value,
  with same-key retry evidence that denial does not consume state.
- Moved identity resolution and the claimed-client comparison before TSK
  verification. Every preflight denial test retries the same TSK key and must
  succeed, proving HOTP and lifecycle state were not consumed.
- The cross-repository suite now imports built TSK package entry points, checks
  the real frozen BPC snapshot, verifies success/replay audit event semantics,
  and verifies the BPC audit hash chain. BPC audit is documented as BPC-stage
  evidence only, not proof of a final Ultra or application decision.
- Verification: build and typecheck passed; 180/180 maintained protocol,
  lifecycle, client, store, anomaly, adversarial, bridge, and runtime assertions
  passed; 26/26 HA assertions passed; 22/22 real BPC/TSK compatibility
  assertions passed; 6/6 digest-pinned live Redis fencing assertions passed;
  4/4 package boundaries and workspace dry runs passed; `npm audit` reported
  zero known vulnerabilities.
- Rollback: revert the dedicated strict-composition commit. Do not restore
  mutable BPC result fallbacks or move identity resolution after TSK validation.

## 2026-07-15 - Numeric HOTP boundary hardening

- Re-audited closed issue #1 and confirmed its stated `maxRequests` lifecycle
  was completed by PR #2; preserved that issue as closed rather than expanding
  its history.
- Opened issue #7 for the distinct numeric moving-factor boundary found in the
  post-merge audit.
- Added one canonical wire-v1 counter ceiling, an exhausted MAX sentinel,
  clipped lookahead, complete-vector atomic commits, counter-capacity rotation
  signaling, and server/client/file/replica range enforcement.
- Added `hotp-exhaustion-suite.mts`; the final focused run passed 17/17 named
  cases. Full build, typecheck, release tests, HA tests, digest-pinned live
  Redis fencing, package dry runs, and the dependency audit passed before
  publication.
- Rollback: revert the dedicated HOTP-boundary commit. Do not partially revert
  only client or server enforcement because their counter contracts must match.

## 2026-07-15

- Re-audited closed BPC issue #1 rather than assuming its earlier closure meant
  every shipped surface enforced the decision. BPC TypeScript rejected
  wildcard scopes, but BPC Python accepted arbitrary scope strings at intake.
  The companion BPC correction was independently tested and merged as BPC PR
  #5 at `d306aadeb33141fffffafacf28781a41c1e92664`.
- Found that the generic TSK BPC bridge also trusted any scope supplied by an
  `ok: true` BPC-like verifier. The bridge now accepts only `read`,
  `read-write`, or `admin`, rejects missing or contradictory scope evidence,
  and fails before TSK validation so malformed BPC results cannot consume TSK
  counter state.
- Added a real package compatibility suite and a CI checkout pinned to the BPC
  merge commit. The suite builds BPC and checks version alignment, wildcard
  rejection, BPC signing and verification, replay ordering, closed-scope
  propagation, TSK identity binding, and TSK state preservation after a BPC
  denial.
- Verification after the companion changes: build and typecheck passed;
  176/176 maintained protocol, lifecycle, client, store, anomaly, adversarial,
  bridge, and runtime assertions passed; 25/25 HA assertions passed; 10/10 real
  BPC/TSK package compatibility assertions passed; 6/6 live Redis fencing
  assertions passed; 4/4 package boundaries passed; 33/33 live browser/backend
  assertions passed; `npm audit` reported zero known vulnerabilities.

- Post-merge review confirmed PR #2 was already merged at `0d22a93` with both
  hosted checks green; the earlier draft/open status was stale.
- Found CI still using EOL Node 20 and legacy root-level red-team scripts that
  were not CI gates and asserted behavior superseded by current hardening.
- Moved historical diagnostics and a simulation-only rotation suite under
  `parked/`, upgraded the baseline to Node 24 LTS, and added a fail-closed guard
  plus maintained assertions for non-finite authentication times.
- A clean package dry run found that all workspaces omitted the `dist` files
  referenced by their manifests; the client SDK also emitted its entry point at
  a nested, incompatible path. Added prepack builds, explicit package file
  boundaries, corrected TypeScript dependency boundaries, and a 4/4 executable
  package-entry test.
- Bounded all internal dependency ranges to `^0.1.0`, corrected the bridge peer
  from the nonexistent tested `@bpc/server ^1.0.0` line to the validated BPC
  `^0.2.0` line, and applied the Node 24 engine contract to every package.
- Reworked variable per-segment lifecycle reporting into two aggregate
  all-segment assertions; the maintained suite now has a stable 170-case count
  regardless of randomized map composition.
- Final verification after these corrections: build and typecheck passed;
  170/170 maintained protocol, lifecycle, client, store, anomaly, adversarial,
  bridge, and runtime assertions passed; 25/25 HA assertions passed; 6/6 live
  Redis fencing assertions passed; 4/4 package boundaries passed with all
  tarballs containing their declared entry points; 33/33 live browser/backend
  assertions passed; `npm audit` reported zero known vulnerabilities.

- Audited open issue #1, draft PR #2, build/typecheck/test gates, HA behavior,
  client persistence, lifecycle authority, and public claims.
- Added pre-cap rotation signaling and authorized atomic replacement.
- Combined all server counter and lifecycle mutations into one validation commit.
- Required authorization callbacks for replacement, update, and revocation.
- Guaranteed generated credentials contain a counter-based segment.
- Added explicit response authentication confirmation and atomic client counter
  vector persistence across restarts.
- Replaced the duplicated attack model with bounded adversarial cases that call
  the production implementation and never print credentials or secrets.
- Added signed, ordered replication with strict receiver validation, secret
  unsealing gates, writer leases, monotonic fencing epochs, and a store-boundary
  mutation wrapper.
- Added an atomic Redis 7.4 fencing authority and live integration suite.
- Made promotion evidence fail closed unless both source and receiver
  checkpoints have deployment-supplied transactional durability evidence.
- Added checksum-failure anomaly telemetry and verified the real browser attack
  path reaches server scoring.
- Removed unused Jest dependencies and their deprecated transitive packages.
- Pinned the CI actions and Redis service image to immutable upstream commits
  and a tested container digest.
- Corrected active documentation/demo claims; parked superseded wording and
  restoration evidence.
- Verification: build and typecheck passed; 170/170 core/lifecycle/client/store/
  anomaly/adversarial/bridge/runtime cases passed; 25/25 HA cases passed; 6/6
  live Redis fencing cases passed against Redis 7.4; 33/33 browser demo checks
  passed; `npm audit` reported zero vulnerabilities.
- Rollback: revert the final hardening commit. `PARKED.md`, `WHY.md`, and Git
  history retain the removed claims and design rationale.
