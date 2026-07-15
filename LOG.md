# Change Log

## 2026-07-15

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
- Corrected active documentation/demo claims; parked superseded wording and
  restoration evidence.
- Verification: build and typecheck passed; 170/170 core/lifecycle/client/store/
  anomaly/adversarial/bridge/runtime cases passed; 25/25 HA cases passed; 6/6
  live Redis fencing cases passed against Redis 7.4; 33/33 browser demo checks
  passed; `npm audit` reported zero vulnerabilities.
- Rollback: revert the final hardening commit. `PARKED.md`, `WHY.md`, and Git
  history retain the removed claims and design rationale.
