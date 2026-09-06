# Changelog

## Unreleased - 2026-07-15

- CI and package type baselines now use Node 24 LTS instead of EOL Node 20.
- Validation now rejects NaN and infinite authentication times, with maintained
  production-code adversarial coverage for time and secret inputs.
- Superseded red-team runners and a reimplemented rotation simulation moved to
  `parked/`; they remain historical material but are not release evidence.
- Package publishing now rebuilds from source, includes only declared `dist`
  artifacts, and verifies every advertised JavaScript and type entry point.
- Corrected the client SDK build boundary so its published `dist/index.js` and
  `dist/index.d.ts` are emitted at the paths declared by its manifest.
- Replaced wildcard internal package dependencies with the tested `0.1.x`
  range, aligned the BPC bridge peer with BPC `0.2.x`, and declared Node 24 on
  every publishable workspace.
- Enforced the immutable BPC 0.2 `AuthSnapshot` contract at the BPC/TSK
  composition boundary. Mutable legacy results, stale snapshots, malformed
  identities, ghost/shadow evidence, resolver failures, and non-closed scopes
  are denied before TSK can consume counter or lifecycle state.
- Moved BPC-to-TSK identity resolution and claimed-header comparison ahead of
  TSK verification, retained an authenticated-identity postcheck, and proved
  same-key reuse after every preflight denial.
- Rejected duplicate TSK client, key, and version headers instead of accepting
  the first adapter-provided value; duplicate rejection does not consume state.
- Converted TSK store/verifier exceptions into an explicit bridge denial rather
  than leaving fail-closed behavior to an HTTP adapter.
- Added a cross-repository compatibility gate that builds a commit-pinned BPC
  checkout and exercises real BPC signing, verification, replay rejection,
  frozen-snapshot propagation, TSK identity binding, and stage-correct BPC audit
  events through built package entry points.
- Made client lifecycle evidence counts deterministic while still asserting
  every generated counter-based segment.
- Added `@tsk/node-http`, a Node HTTP authentication and lifecycle-
  administration adapter. It requires deployment-owned operator authentication
  and a secure credential-delivery callback, and does not return the shared
  secret in its lifecycle HTTP response (`npm run test:http`).

### Security

- Made source activation a signed, append-only head/history chain so repeated
  promotions on one stream cannot overwrite or replay an earlier activation.
- Added governed return-site activation: a returning target supplies its exact
  signed, terminal lease high-water and receives the next guard-signed lease
  transition instead of an un-installable second genesis grant. Control schema
  version 2 is intentionally required for this history-bearing layout.
- Added an owned, crash-atomic receiver-to-source activation authority that
  rebuilds only persisted finalized staging, re-verifies both export signatures
  and the complete ledger, then installs rows, fence, checkpoint, and lease in
  one serializable target transaction. Manual multi-transaction import is not
  an activation path.
- Closed numeric HOTP rollover paths across core derivation, lookahead, atomic
  stores, client persistence, and replica input. Wire v1 now commits MAX only as
  an exhausted sentinel and never writes or derives MAX+1.
- Added an independent HOTP-capacity warning and response header; the segment
  closest to exhaustion governs rotation even without `maxRequests`.
- Required atomic validation commits to contain the complete HOTP counter
  vector, preventing partial lifecycle commits.
- Enforced writer fencing at every `TumblerMapStore` mutation through
  `FencedTumblerStore` and added atomic Redis-backed fencing transitions.
- Authenticated and hash-linked replication operations; rejected stale,
  replayed, gapped, malformed, rolled-back, or lifecycle-resurrecting state.
- Required secret unsealing, exact stream convergence, and explicit durable
  checkpoint evidence before a replica can qualify for promotion.
- Added atomic multi-counter and lifecycle usage commits.
- Guaranteed at least one counter-based segment in generated maps and rejected
  maps without one.
- Added pre-cap rotation signaling and fail-closed authorized replacement that
  atomically revokes the prior credential.
- Required external authorization for lifecycle update and revocation.
- Changed client counter commit to require explicit authentication acceptance,
  independent of downstream HTTP business status.
- Added atomic persistent counter-vector storage and restart tests.
- Recorded checksum-first rejections in anomaly telemetry.
- Removed unused Jest dependencies.
- Corrected layout, checksum, FIPS, Impact Level, device identity, and compliance
  descriptions to match implemented evidence.
- Closed a real Windows file-store race: a failed rename could previously
  advance the live counter while disk retained the prior value, two cached
  instances could accept the same counter, and missing timestamps could bypass
  TTL. Writes now publish a validated candidate only after fsync/rename, and an
  exclusive file transaction reloads authority before every operation. Own-key
  membership prevents inherited object names from bypassing capacity or
  appearing as stored clients.

### Evidence

- Added maintained numeric-boundary tests for warning thresholds, final-use
  concurrency, lookahead clipping, corrupt persistence, client restart, and
  replica rejection.
- Replaced duplicated attack logic with production-backed bounded cases and
  removed secret/key logging and unsupported statistical/performance claims.
- Added live Redis fencing and browser attack-path verification.
- Added named concurrent-cap, replacement, application-error, restart, and
  no-confirmation cases.
- Added repository CI/typecheck/HA commands to the release gate.
- Added an installed-package Windows file-store evidence gate
  (`scripts/verify_file_store_install.py`) exercising real sharing-lock write
  failures, two-instance/two-process counter competition, and malformed-
  state/TTL checks against a fresh npm tarball install; CI retains the Windows
  evidence artifacts and runs a Linux authority counterpart. This does not
  cover power failure, network filesystems, hostile local filesystem
  mutation, high sustained load, or automatic resolution of abandoned locks,
  and store failures after a possible commit remain outcome-unknown -- the
  BPC HTTP adapter preserves that distinction with a non-retryable unknown
  result.

## 0.1.0

Initial beta reference implementation. Historical descriptions that called the
integrity tag Ed25519, treated layout as secret, or asserted compliance are
superseded and preserved in Git history and `PARKED.md`.
