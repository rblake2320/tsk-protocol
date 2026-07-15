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
- Enforced the BPC 0.2 closed scope contract at the BPC/TSK composition
  boundary. Missing, wildcard, namespaced, and contradictory scopes are denied
  before TSK can consume counter or lifecycle state.
- Added a cross-repository compatibility gate that builds a commit-pinned BPC
  checkout and exercises real BPC signing, verification, replay rejection,
  closed-scope propagation, and TSK identity binding.
- Made client lifecycle evidence counts deterministic while still asserting
  every generated counter-based segment.

### Security

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

### Evidence

- Replaced duplicated attack logic with production-backed bounded cases and
  removed secret/key logging and unsupported statistical/performance claims.
- Added live Redis fencing and browser attack-path verification.
- Added named concurrent-cap, replacement, application-error, restart, and
  no-confirmation cases.
- Added repository CI/typecheck/HA commands to the release gate.

## 0.1.0

Initial beta reference implementation. Historical descriptions that called the
integrity tag Ed25519, treated layout as secret, or asserted compliance are
superseded and preserved in Git history and `PARKED.md`.
