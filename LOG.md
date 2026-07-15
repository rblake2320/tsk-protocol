# Change Log

## 2026-07-15

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
