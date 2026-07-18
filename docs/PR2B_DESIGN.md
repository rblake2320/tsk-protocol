# PR2b — Source fence gate, accumulators, anchor chain, manifest, import + tail (toward closing TSK #10)

> **Status:** DESIGN ONLY (v2 — incorporates PR17 review pass-1 + agent-review blockers). No code
> ships from this doc. **#10 stays OPEN through PR2b.** PR2b makes a receiver B a *promotable
> candidate* via a verifiable snapshot-base `S` + tail to the frozen source head `N`, under the PR2a
> signed cutover head. It does **NOT** close #10 — two-phase `READY→ACTIVE` promotion,
> rehydrate-not-reclaim crash recovery, child-process SIGKILL matrix, a real 3-node Redis
> Sentinel/quorum, and measured RPO/RTO are **PR2c**.

Builds on merged **PR2a** (`ha-control-fencing.ts`) and **#10 PR12/13/14** (source outbox,
`NodePostgresTransactor`, receiver checkpoint, authenticated two-node transport A=5432 / B=5433).

Review corrections folded in and tagged: **B1** source gate (no control-clock/DB read in A's tx;
lock-based revoke; pre-commit recheck; restore witness), **B2** accumulators (event MMR *and*
authenticated state-map; leaf≠node; 3 lineages; canonical leaf), **B3** cross-authority saga (no
false cross-DB atomic snapshot; signed B checkpoint receipt; state-map completeness), **B4** key
registry (offline root, monotonic `registryVersion`, retirement vs compromise), **B5** import
(no C-authoritative flip before N; isolated generation + single pointer at N; signed anchor bundle;
B never reads control DB in-tx), **B6** old-epoch by exact digest not seq, **B7** topology honesty
(B = the PR14 PG @5433; Redis is a cross-checked coordinator, **not** a durable authority),
**B8** expanded failure matrix.

---

## 0. Slice order (source gate FRONT-LOADED)

| Slice | Ships | Does NOT claim |
|-------|-------|----------------|
| **PR2b-0** | Non-bypassable **source in-tx fence/lease gate** + lock-based revoke + **pre-commit recheck** + **restore witness** (§A) | no snapshot; enables a *provable* frozen `N` |
| **PR2b-1** | **Accumulator contracts + cross-impl vectors, then atomic A-PG integration**: event **MMR** (3 lineages) **and** authenticated **state-map** (§B) | no anchor/manifest |
| **PR2b-2** | **Control-DB anchor chain + signed key registry** (offline root, monotonic `registryVersion`) (§C) | no manifest/import |
| **PR2b-3** | **`SourceAuthoritySnapshot` manifest** (base `S` state-map root + frozen `N` + 3 anchored roots, proves `S≤N`) + **signed B checkpoint receipt** + **cross-authority saga** (§D) | no B import |
| **PR2b-4** | **Import into an ISOLATED GENERATION on B** (write-ahead IMPORTING; verify a signed anchor **bundle**, never read control DB in-tx) (§E) | **no C-authoritative flip; no tail/boundary** |
| **PR2b-5** | **Tail `C+1..N` chunked** + old-epoch classify + **generation pointer flip only at N** via a cross-DB signed READY saga (§F) | does NOT reach `ACTIVE` (PR2c) |

---

## A. PR2b-0 — Non-bypassable source in-tx fence/lease gate (B1)

**A-PG never reads the control clock or control DB in its tx.** All inputs are signed artifacts A
verifies locally; time is A's own clock with a bounded, measured, config-attested control↔A skew.

### A.1 Full DDL (source PG)
```
tsk_outbox_fence (
  stream_id            text PRIMARY KEY,
  lease_epoch          bigint NOT NULL CHECK (lease_epoch >= 0),
  lease_status         text   NOT NULL CHECK (lease_status IN ('active','revoked')),
  holder_node_id       text   NOT NULL,
  lease_id             text   NOT NULL,
  command_id           text   NOT NULL,                 -- promotion/grant command binding
  lease_expires_at_ms  bigint NOT NULL CHECK (lease_expires_at_ms >= 0),  -- signed absolute deadline (control clock)
  lease_grant_seq      bigint NOT NULL CHECK (lease_grant_seq >= 1),      -- strictly increasing
  grant_digest         text   NOT NULL,                 -- sha256 of the canonical signed grant/revoke tuple
  guard_key_id         text   NOT NULL,
  guard_signature      text   NOT NULL,
  updated_at           timestamptz NOT NULL DEFAULT now()
)
```
A guard-signed **`LeaseGrant`** and **`LeaseRevocation`** carry the full tuple
`(stream_id, lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms,
lease_grant_seq, prev_grant_digest)`; install verifies the guard signature over that exact framing,
requires a **strictly-increasing `lease_grant_seq`**, and forward-CAS's `grant_digest`.

### A.2 Lock-based freeze + true pre-commit recheck
- **Append (per source authority write, its own SERIALIZABLE tx):** `SELECT ... FROM tsk_outbox_fence
  WHERE stream_id=$1 FOR SHARE` **held through commit**; require `lease_status='active'`,
  `lease_epoch == expectedEpoch`, and A-clock `now < (lease_expires_at_ms − controlToASkewBoundMs)`;
  the tx deadline must fall within that bound. **A TRUE PRE-COMMIT RECHECK** re-reads the fence
  `FOR SHARE` as the **last statement before COMMIT** (a `NodePostgresTransactor` pre-commit hook) —
  "assert once at the start" is insufficient: a tx could pass the start check, stall past expiry,
  then commit. The recheck + the held `FOR SHARE` close that.
- **Fence/revoke:** `UPDATE tsk_outbox_fence SET lease_status='revoked', lease_epoch=E, ... WHERE
  stream_id=$1` takes the **conflicting row lock** — it **cannot commit until all in-flight `FOR
  SHARE` appends finish**; once it commits, every new append's `FOR SHARE` read sees `revoked` and
  **fails in-tx** (and the pre-commit recheck fails any that slipped through).

### A.3 Frozen `N` (provable) + restore witness
- **Frozen `N` is provable ONLY after the A-PG revoke UPDATE commits** (or a STONITH / session
  reaper of stale-epoch backends completes). Control-clock lease expiry is a *secondary* bound, never
  the freeze proof. `N` := the max committed source head sequence at the instant the revoke commits.
- **Restore witness (B1).** `lease_grant_seq` strictly-increasing is defeated by a **source-PG
  restore** that rolls `grant_seq` backward (a replayed grant could reinstall). Defense: a **durable
  external witness** of `(source system_identifier, max lease_grant_seq, max source head N)` on the
  control DB (append-only, signed); on source startup and before any grant install, A attests its
  live `system_identifier` + `grant_seq` + head vs the witness — a **regression (restore/rollback) →
  QUARANTINE** (no writes, governed unquarantine only). This also detects an equivocating/rolled-back
  source PG.

**PR2b-0 faults (§H):** stale-epoch append after revoke commit; in-flight append vs revoke (revoke
waits, next append rejects); pass-start-then-stall-past-expiry (pre-commit recheck rejects);
replayed/reordered/rolled-back `grant_seq`; forged grant/revoke sig or keyId; A-clock past
expiry−skew; **source-PG restore rolling back grant_seq/head** → witness quarantine;
Redis-precheck-passing but PG-fenced writer → in-tx reject.

---

## B. PR2b-1 — Accumulator contracts (B2), then atomic A-PG integration

Ship **versioned CONTRACTS + cross-implementation vectors FIRST**, then PG append. Our own **named
profile** (`accProfileVersion = 1`); the expired IETF **MMRIVER** draft is a WIP *reference only*,
not a conformance claim.

### B.1 Event MMR — three lineages, leaf ≠ node
- **`mmrSize` = NODE count, NOT the leaf sequence** (B2). Each lineage pins its own **`leafCount`**
  (0-based append index; leaf `i` maps to source `seq`) **and** `nodeCount` and `root`. `mmrSize=N`
  is generally **false**; the anchored proof binds `(leafCount, nodeCount, root)`.
- **Three independent lineages**, each its own root/size/anchor (no single composite unless a
  composite root is *also* pinned): **source-ledger** (1 leaf per committed source seq),
  **HOTP** (cardinality pinned: **exactly one leaf per source seq**; absent/multiple → reject), and
  **head** (1 leaf per signed head). Ordering pinned: head leaf appended after row+HOTP of the same
  seq. **All three advance ATOMICALLY in the same append tx.**
- **Canonical leaf** binds `{accProfileVersion, streamId, epoch, seq, lineage, position}` under a
  domain tag (leaf/node/peak/root domains distinct + framed). **Empty/genesis root** pinned
  (defined constant for `leafCount=0`). Peak-bag order high→low pinned. Bounds `0 ≤ x < 2^53`
  (or string-encoded u64) validated at every boundary.
- **Proofs:** inclusion (audit path: siblings + peak bag; **directions/count/encoding pinned**) and
  consistency `(size_a,root_a)→(size_b,root_b)` prefix proof. **Rejection vectors** (cross-impl):
  truncated/extended/wrong-sibling/wrong-peak-order path, size/root mismatch, non-prefix, out-of-range
  index, domain confusion, profile mismatch, wrong-lineage leaf, empty-root spoof.

### B.2 Authenticated STATE-MAP — completeness / non-omission (CRIT2)
Event-MMR inclusion proves an event happened; it does **NOT** prove the **tumbler STATE set is
complete** (no omitted keys). PR2b therefore maintains an **authenticated state-map**: a versioned
sparse/indexed Merkle map over tumbler `key → valueDigest`, its **signed root advanced ATOMICALLY**
with each mutation in the same tx. It supports **inclusion AND non-membership** proofs, so a snapshot
at base `S` proves its tumbler set is **exactly** the committed set at `S` (completeness). Alternative
(also acceptable, pinned): **deterministic genesis→S replay** verifying the resulting state-map root
— but the bounded proof B verifies is the **state-map root + membership/non-membership**, never
event-MMR inclusion alone. State-map node tables + root head are pinned with the same domain/bounds
discipline.

### B.3 A-PG integration (atomic)
Per-lineage node/head tables (`tsk_mmr_<lineage>_node/_head`) + `tsk_state_map_node/_head`. In the
**same SERIALIZABLE append tx** as the source row: insert the source row + new MMR leaf/nodes/peaks
for all three lineages + the state-map update + all roots forward-CAS (affected-row=1). No lazy roots.

---

## C. PR2b-2 — Anchor chain + signed key registry (B4)

### C.1 Key registry (offline root; monotonic version)
- **Offline bootstrap ROOT.** A registry **root key**, established OFFLINE, signs the registry head.
  The runtime never holds the root key.
- **Append-only head + history** on the control DB; a **monotonic `registryVersion`** is **bound into
  every signed artifact** (anchor, manifest) — an artifact names the `registryVersion` it was signed
  under; a verifier rejects an artifact whose named version is unknown or rolled back (rollback
  defense).
- Per keyId: `{keyId, alg, usage(source|guard|anchor), effective_from_seq, effective_until_seq,
  status ∈ active|retired|compromised, retired_at, compromised_at}`, root-signed.
- **Routine RETIREMENT = PROSPECTIVE:** artifacts signed while the key was effective **stay valid**;
  the key just stops signing new artifacts. **COMPROMISE = RETROACTIVE:** a `compromised_at` marks the
  key untrusted for **all** artifacts → the affected artifacts MUST be **re-anchored / re-signed** by
  a fresh key (explicit recovery path); a compromised keyId is rejected regardless of signing time.
  No circular trust: trust flows offline-root → registry head → per-key → artifact.

### C.2 Anchor chain
Genesis anchor (provisioned) → each signed anchor `{streamId, lineage, leafCount, nodeCount, root,
prevAnchorDigest, registryVersion, sourceSig, guardSig}` proves **consistency from its immediately
prior anchored `(size,root)`** → `genesis→latest` exact. Append-only, prev-digest-linked,
head==latest-history verified. **Synchronous promotion-time anchor of frozen `N`** (all 3 lineages)
+ consistency `latest→N` + inclusion of `N`.

---

## D. PR2b-3 — Manifest + cross-authority saga (B3)

**No false cross-DB atomic snapshot.** `C` (receiver-applied checkpoint) is owned by **B's DB** and
cannot be exported in an A-PG tx. The promotion is a **signed cross-authority SAGA**:

1. **Freeze `N`** (PR2b-0 revoke commits) + synchronous anchor of `N` (§C.2).
2. **A exports** (one A-PG SERIALIZABLE tx, dual source+guard signed) a `SourceAuthoritySnapshot`:
   `{manifestSchemaVersion, contractVersion, accProfileVersion, registryVersion, streamId, epoch,
   sourceNodeId, snapshotBase S, state-map root@S + the size-bounded authenticated state set@S,
   frozenHead N + the 3 anchored (leafCount,nodeCount,root), consistency proof S→N + inclusion of S
   and N, canonicalDigest}` — all **A-owned** (A owns its own state@S and ledger). `maxManifestBytes`
   + `maxTumblers` bound the **snapshot@S only**; the tail is unbounded/chunked.
3. **B produces a SIGNED receiver-checkpoint RECEIPT** of its applied `C` from **B's own DB**
   (`{streamId, epoch, appliedC, appliedHeadDigest, appliedStateMapRoot, B system_identifier, bSig}`).
4. The promotion **binds** manifest`(S,N)` + B's signed `C`, requiring **`S ≤ N`** and covering
   **`[C, N]`** by the tail (§F): if `C < S`, B imports snapshot@S then tail `S+1..N`; if `C ≥ S`, B
   skips the snapshot and imports tail `C+1..N`. `S ≤ C ≤ N` or `C < S ≤ N` — never `C > N`.
5. **Signed immutable anchor BUNDLE (B5):** B verifies everything against a **self-contained signed
   bundle** (control anchor head + registry head@version + signatures) transported to B — **B never
   transactionally reads the control DB.**

Key custody/rotation/revocation per §C.1 (evaluated by the artifact's named `registryVersion`).

---

## E. PR2b-4 — Import into an isolated generation on B (B5)

- **Write-ahead IMPORTING:** before importing, B durably records an `IMPORTING` intent binding the
  **manifest digest + anchor-bundle digest + generationId**; a crash resumes/aborts against it.
- **Isolated generation.** Staged snapshot@S + tail chunks land in a **candidate generation**
  (`tsk_import_generation` + staging tables keyed by `(streamId, epoch, command_id, generationId)`),
  **NOT visible as authority**. **No C-authoritative flip before N (CRIT).** A single **generation
  pointer** flips a generation live **only after the tail reaches `N`** and the boundary is anchored
  (§F) — until then the imported state is invisible (or explicitly read-only, all consumers
  **generation-bound**). No partial staged state is ever authority.
- **Chunk conflict/gap DDL:** each chunk records `(fromSeq, toSeq, chunkDigest)`; a **duplicate chunk
  digest that conflicts**, a **gap**, or an **overlap** → isolate/quarantine, never silently merge.
- **Attest (one B tx):** verify contract/schema/`manifestSchemaVersion`/layout; recompute
  `canonicalDigest`; verify dual sigs + keyIds against the bundle's `registryVersion` (retired ok if
  effective-at-signing, compromised rejected); verify **state-map root@S (completeness) + MMR
  consistency `S→N` + inclusion** against the **anchored roots in the signed bundle**; verify HOTP
  lineage; verify `epoch`/`streamId`/`sourceNodeId` + **B `system_identifier` distinct from A and
  control** (attested). Only a fully-attested generation is *eligible* for the pointer flip.
- **Authority meaning (B5):** a flipped generation is authoritative **receiver/candidate** state
  (B may serve reads / continue applying), **NOT writable SOURCE authority**. Source-write capability
  is minted **only at `ACTIVE` (PR2c)**.

---

## F. PR2b-5 — Tail chunked + old-epoch classify + pointer flip at N (B6)

- **Distinct authorities (H8):** SOURCE ledger (A, contiguous `1..N`, accumulator-proven) vs RECEIVER
  applied (B, `tsk_outbox_receiver_checkpoint`). `C` = B applied; `N` = frozen source head; tail =
  `C+1..N`.
- **Chunked resumable tail (H9):** bounded batches, monotonic cursor `(fromSeq,toSeq)` advancing
  `C+1→N`, each `maxBatchBytes`/`maxBatchItems`-bounded with a **bounded MMR inclusion proof against
  the anchored `N` root**, staged + applied **idempotently in order** into the candidate generation,
  resuming from B's applied checkpoint on crash. Never terminally rejected for size.
- **Old-epoch classify — ONLY after the signed boundary/anchor authority is verified (B6):**
  - `seq ≤ C` → **duplicate-ok ONLY on EXACT match of the applied-history record digest + head + HOTP
    at that seq** (NOT merely `seq ≤ C`); any mismatch → **isolate as fork**.
  - `C < seq ≤ N` → apply as tail **only as an EXACT contiguous MMR-proven** record; gap/mismatch →
    isolate.
  - After the boundary, any old-epoch record not proven in applied history → **isolate as fork
    evidence** (quarantined, no halt) — never silently dropped.
- **Cutover (cross-DB signed READY saga):** `FENCED → IMPORTING` (write-ahead bind manifest+anchor)
  `→ READY` (B reached `N`, boundary anchored, **generation pointer flipped**). `READY → ACTIVE` is
  **PR2c**. Each transition is a signed forward-CAS on the PR2a control cutover head; the READY step
  is a **cross-DB saga** (B's reached-N receipt + control's boundary anchor), not an atomic cross-DB
  write.

---

## G. Idempotent crash-resume

Import + tail replay idempotent (re-attest + duplicate-ok on exact digest). Crash mid-import (before
the pointer flip) → candidate generation only; resume against the write-ahead IMPORTING intent. Crash
mid-tail → resume from B's applied checkpoint. Every saga step is individually durable + resumable;
post-`READY` is PR2c (rehydrate-not-reclaim).

---

## H. Exact failure matrix (expanded, B8)

| # | Fault | Detected at | Response |
|---|-------|-------------|----------|
| 1 | stale-epoch append after revoke commit | source gate FOR SHARE (§A.2) | reject in-tx |
| 2 | append passes start-check then stalls past expiry | **pre-commit recheck** (§A.2) | reject before COMMIT |
| 3 | in-flight append concurrent with revoke | conflicting row lock (§A.2) | revoke waits; next append rejects |
| 4 | Redis precheck passes but PG fenced | source gate | reject in-tx (decisive) |
| 5 | replayed / reordered / rolled-back `grant_seq` | grant install (§A.1) | reject (strictly increasing) |
| 6 | **source-PG restore rolls back grant_seq / head** | **restore witness** (§A.3) | quarantine (external witness regression) |
| 7 | forged/expired/compromised lease grant or revoke | grant verify + registry (§A/§C) | reject |
| 8 | A-clock past `expiry − skew` (skew mis-set) | source gate + attested skew bound | reject; conservative skew |
| 9 | "frozen N" asserted before revoke commit | attestation (§A.3) | not attestable |
| 10 | MMR truncated/extended/wrong-sibling/peak-order | inclusion vector (§B.1) | reject |
| 11 | non-prefix / size-root mismatch consistency | consistency vector (§B.1) | reject |
| 12 | leaf≠node conflation / out-of-range / empty-root spoof | bounds + profile (§B.1) | reject |
| 13 | domain confusion / wrong-lineage / profile mismatch | domain check (§B.1) | reject |
| 14 | **partial / non-atomic 3-lineage or state-map update** | forward-CAS (§B.3) | reject (all-or-nothing) |
| 15 | **state omission (event proven, state incomplete)** | state-map non-membership (§B.2) | reject (completeness) |
| 16 | anchor chain gap / prev-digest break / **anchor-head rollback** | anchor verify + registryVersion (§C.2) | reject |
| 17 | **registry rollback / retro compromise / backdating** | monotonic registryVersion + offline root (§C.1) | reject; re-anchor path |
| 18 | manifest replay / wrong-source / wrong-epoch / tampered / oversize | attest (§D/§E) | reject before flip |
| 19 | **C authority mismatch (no signed B receipt / C>N)** | cross-authority saga (§D) | reject (need signed B `C`, `C≤N`) |
| 20 | B `system_identifier` == A or control | attest (§E) | reject (not independent) |
| 21 | **planted / conflicting / duplicate-digest / gap / overlap chunk** | chunk DDL (§E) | isolate/quarantine |
| 22 | **C flipped authoritative before tail N** | generation pointer (§E/§F) | impossible — pointer flips only at N |
| 23 | old-epoch `seq≤C` digest/head/HOTP mismatch | tail classify (§F) | isolate as fork (not dup-ok) |
| 24 | old-epoch `C<seq≤N` non-contiguous / unproven | tail classify (§F) | isolate |
| 25 | old-epoch post-boundary unproven | boundary classify (§F) | isolate as fork evidence (no halt) |
| 26 | boundary commit before B reaches N | cutover CAS (§F) | reject |
| 27 | **crash at any saga step** (freeze/anchor/export/receipt/import/tail/READY) | write-ahead + resume (§G) | idempotent resume or clean abort; no partial authority |
| 28 | source **equivocation** (two heads at a seq) | MMR consistency + restore witness | reject/quarantine |

---

## I. Topology + drill/CI (B7 — honest)

- **State authorities:** source **A-PG** (=5432, PR14), receiver **B-PG** (**= the PR14 B @ 5433 —
  REUSED, not a new node**; a genuinely fresh B is declared as such with an honest reset), control
  **PG @ 5434** (PR2a). **Distinct `system_identifier` attested** across A / B / control. **Redis is a
  cross-checked coordinator/witness, NOT a durable authority** (single instance = mechanism-only; real
  3-node Sentinel/quorum is PR2c).
- **Drills (fail-not-skip, real PG16 + real Redis):** b0 source-gate matrix (incl. pre-commit-recheck
  pass-then-stall, restore-witness rollback, Redis-passes-but-PG-fenced); b1 accumulator contract
  vectors (MMR + state-map, incl. completeness/non-omission) + real-PG atomic all-lineage append; b2
  anchor genesis→N + registry rotation(retire)/compromise + rollback; b3 manifest export + `S≤C≤N` +
  dual-sig + signed B receipt; b4 staged import into a candidate generation + no-flip-before-N +
  independence; b5 chunked tail resume + exact-digest old-epoch classify + pointer flip at N + cutover
  saga crash steps.

## J. PR2c (what closes #10)

`READY→ACTIVE` two-phase promotion (single epoch bump + unforgeable readiness capability,
rehydrate-not-reclaim crash recovery, epoch-separated streams, source-write capability minted here);
child-process **SIGKILL crash matrix** across A/control/B (prove NO writer after any crash); real
**3-node Redis Sentinel/quorum** (WAITAOF/CKQUORUM/AOF/min-replicas/old-master-refusal/rollback);
**measured RPO/RTO**. **#10 closes only when PR2c is green.**
