# PR2b — Source fence gate, payload-committing accumulators, anchored state, manifest, import + tail (toward closing TSK #10)

> **Status:** DESIGN ONLY (v3 — folds in PR17 pass-1 + agent + R2 blockers). No code ships from this
> doc. **#10 stays OPEN through PR2b.** PR2b makes a receiver B a *promotable candidate* via a
> verifiable, **payload-committing** snapshot + tail to the frozen source head `N`, under the PR2a
> signed cutover head. It does **NOT** close #10 — two-phase `READY→ACTIVE` promotion,
> rehydrate-not-reclaim recovery, SIGKILL matrix, a real 3-node Redis quorum, and measured RPO/RTO
> are **PR2c**.

Builds on merged **PR2a** (`ha-control-fencing.ts`) and **#10 PR12/13/14** (source outbox,
`NodePostgresTransactor`, receiver checkpoint, two-node transport **A=5432 / B=5433**).

**Canonical bytes.** Every signed artifact (manifest, proofs, state-map export, registry, anchor,
receipts) is serialized with a pinned canonical encoding — **JCS (RFC 8785) / I-JSON** — before
hashing/signing; a non-canonical byte stream is rejected. Exact JSON schemas + DDL are pinned per
slice (sketched here; full schemas land with each slice's contract).

Corrections tagged: **P** = payload commitment, **S** = persistent/anchored state, **G** = source
gate, **R** = registry, **I** = import/generation, **K** = cross-authority saga, **M** = matrix.

---

## 0. Slice order (source gate FRONT-LOADED)

| Slice | Ships | Does NOT claim |
|-------|-------|----------------|
| **PR2b-0** | Source in-tx fence/lease gate: signed head + append-only history + lock-based revoke + pre-commit recheck + external restore/fork witness (§A) | no snapshot; enables a *provable* frozen `N` |
| **PR2b-1** | Accumulator contracts + cross-impl/substitution vectors, then atomic A-PG: **payload-committing** event MMR (3 lineages) **and** persistent authenticated **state-map** (§B) | no anchor/manifest |
| **PR2b-2** | Control anchor chain + signed key registry (offline root, external max-version witness) (§C) | no manifest/import |
| **PR2b-3** | `SourceAuthoritySnapshot` manifest + signed B receipt + `importBase=max(C,S)` cross-authority saga (§D) | no B import |
| **PR2b-4** | Import into an isolated candidate generation on B (write-ahead; signed anchor bundle; no control read in-tx) (§E) | **no authoritative flip before N** |
| **PR2b-5** | Tail chunked (range multiproof) + old-epoch classify + generation pointer flip only at N via an exact durable READY saga (§F) | does NOT reach `ACTIVE` (PR2c) |

---

## A. PR2b-0 — Source in-tx fence/lease gate (G)

A-PG **never reads the control clock or control DB in its tx**; inputs are locally-verifiable signed
artifacts; time is A's own clock with a bounded, measured, attested control↔A skew.

### A.1 DDL — signed head + append-only history
`tsk_outbox_fence` (head) columns: `stream_id PK, lease_epoch, lease_status(active|revoked),
holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq(≥1), prev_grant_digest
(STORED, NULL@seq1), grant_digest, guard_key_id, guard_signature, updated_at`. Plus
`tsk_outbox_fence_history` (append-only) `PK(stream_id, lease_grant_seq)`,
`UNIQUE(stream_id, grant_digest)`, `UNIQUE(stream_id, command_id)`.
- A guard-signed **`LeaseGrant`/`LeaseRevocation`** carries the full tuple `(stream_id, lease_epoch,
  lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq,
  prev_grant_digest)`. Install verifies the signature over the exact framing; requires
  **strictly-increasing `lease_grant_seq`** with `prev_grant_digest == current head digest` (chain);
  **stores prev digest**; appends history; forward-CAS's the head.
- **Idempotent lost-ACK (G):** same `command_id` + identical tuple → no-op; same `command_id` with a
  different tuple → conflict/quarantine. Reads verify head==latest-history + continuous prev-chain.

### A.2 Lock-based freeze (the authority) + bounded pre-commit recheck
- **Append (own SERIALIZABLE tx):** `SELECT ... FOR SHARE` on the fence row **held to commit**;
  require `active` + `lease_epoch==expected` + A-clock `now < lease_expires_at_ms − skewBound`; tx
  deadline within bound. A **pre-commit recheck** re-reads the fence `FOR SHARE` as the last statement
  before COMMIT (transactor hook).
- **Fence/revoke** `UPDATE ... SET lease_status='revoked' ...` takes the **conflicting row lock** — it
  cannot commit until in-flight `FOR SHARE` appends finish; after it commits, new appends see
  `revoked` and fail in-tx.
- **Honest bound (P/G):** the pre-commit recheck does **NOT** guarantee the COMMIT lands before the
  time deadline (a commit can still race the clock). **The lock-based revoke is the authority**: it
  *linearizes* the freeze against all in-flight writers. Time expiry is only a secondary safety
  bound. Claims are bounded accordingly.

### A.3 Frozen `N` + external restore/fork witness
- **Frozen `N` provable ONLY after the A-PG revoke commits** (or STONITH/reaper completes). `N` :=
  max committed source head at that instant.
- **External witness (G).** A durable, signed, append-only witness (on the control DB **and** an
  out-of-control-DB pinned minimum) records `(source system_identifier, max lease_grant_seq, **max
  source head N + its anchored source-root digest + head digest**, checkpoint cadence, unanchored-tail
  RPO)`. Max-seq alone can't catch a **same-height fork** (a different head@same seq after restore) or
  an **unanchored rollback** — so the witness binds the **root/head digest** and an honest **checkpoint
  cadence / unanchored-tail RPO**. Any regression, digest divergence at equal height, or
  unanchored-suffix beyond RPO → **QUARANTINE**.

---

## B. PR2b-1 — Payload-committing accumulators (P, S)

Ship **versioned CONTRACTS + cross-impl vectors FIRST**, then PG append. Named profile
(`accProfileVersion=1`); expired IETF MMRIVER draft is a WIP *reference only*.

### B.1 Event MMR — leaves COMMIT the payload (CRIT-P)
`mmrSize` = **node count**, distinct from **`leafCount`** (0-based; leaf→source seq). Each lineage
pins its own `(leafCount, nodeCount, root)`; the anchored proof binds all three.
**Canonical leaf per lineage binds the PAYLOAD DIGEST (P)** — omitting it lets payload substitution
leave the root unchanged:
- **source-ledger** leaf `= H(leafDomain ‖ accProfileVersion ‖ streamId ‖ epoch ‖ seq ‖ lineage ‖
  position ‖ **opDigest** ‖ **stateRootAfter**)`, where `opDigest` = digest over the source op /
  fence **immutable fields**, and **`stateRootAfter` binds the state-map root after seq into the
  source lineage (S)** — one leaf per committed source seq.
- **HOTP** leaf binds `‖ tumblerId ‖ counter ‖ hotpDigest` — cardinality pinned: **exactly one leaf
  per source seq** (absent/multiple → reject).
- **head** leaf binds `‖ signedHeadDigest ‖ headSignature` — one per signed head.
All lineages advance **ATOMICALLY** in the append tx; ordering pinned (head after row+HOTP of the
same seq). Distinct framed domains for leaf/node/peak/root; **empty/genesis root** pinned; bounds
`0 ≤ x < 2^53` (or string u64). **Proofs:** inclusion (audit path — directions/count/encoding pinned)
+ consistency (prefix). **Rejection vectors (cross-impl, incl. SUBSTITUTION):** flip
opDigest/tumbler/counter/head-sig → root MUST change; truncated/extended/wrong-sibling/peak-order,
size/root mismatch, non-prefix, out-of-range, domain confusion, wrong-lineage, empty-root spoof,
profile mismatch.

### B.2 Persistent authenticated STATE-MAP — completeness (CRIT-S)
Indexed Merkle map over tumbler `key → valueDigest`. **Persistent VERSIONED nodes + a state-root
recorded at EVERY source seq** (a 4th anchored **`state-root` lineage**), with retained checkpoints —
the head does **not** merely hold the latest root; historical `root@S`/`root@C` are retrievable and
anchor-provable, and bound into the source leaf via `stateRootAfter` (§B.1).
**Completeness is proven by recomputing the canonical SORTED-SET root**, never by scattered
per-item membership/non-membership (which cannot prove no nonempty key was omitted):
1. **Canonical full-map enumeration** — the snapshot carries the entire nonempty key set in pinned
   sorted order; B **recomputes the exact state-root** and matches the anchored `root@S`
   (`maxTumblers`-bounded).
2. **Frontier completeness multiproof** — a formally-defined multiproof over the entire sparse
   frontier (pinned encoding + verifier) for the non-enumerated path.

### B.3 A-PG integration (atomic)
Per-lineage `tsk_mmr_<lineage>_node/_head` + persistent `tsk_state_map_node(version)` + per-seq
`tsk_state_root_history`. In the **same SERIALIZABLE append tx** as the source row: append row + MMR
leaf/nodes/peaks for all lineages + the versioned state-map update + `stateRootAfter` into the source
leaf + all roots forward-CAS (affected-row=1). No lazy roots.

---

## C. PR2b-2 — Anchor chain + signed key registry (R)

### C.1 Registry
- **Offline bootstrap ROOT** signs the registry head; runtime never holds it.
- **Append-only head + history** on the control DB; a **monotonic `registryVersion`** bound into
  every signed artifact — **AND an EXTERNAL pinned minimum `registryVersion` witness** (out of the
  rollbackable control DB): a monotonic version stored only in the same DB it protects is itself
  rollbackable, so B/control pin a minimum from an independent authority; an artifact naming a version
  `< external min` → reject.
- Per keyId: `{keyId, alg, usage(source|guard|anchor|receiver), streamId-scope, effective_from_seq,
  effective_until_seq, status(active|retired|compromised), retired_at, compromised_at}`, root-signed;
  **effective seq is stream+usage scoped**. **B signing key usage** is registered (receiver).
- **RETIREMENT = prospective** (pre-retirement artifacts stay valid). **COMPROMISE = retroactive**:
  affected artifacts MUST be **rebuilt/re-derived from the INDEPENDENTLY-ANCHORED ledger** (with
  quorum / uncompromised evidence) and re-signed by a fresh key — **never blindly re-signed** (blind
  re-sign launders compromised-key fabrications). A compromised keyId is rejected regardless of time.

### C.2 Anchor chain
Genesis anchor → each signed anchor `{streamId, lineage, leafCount, nodeCount, root, prevAnchorDigest,
registryVersion, sourceSig, guardSig}` proves consistency from its prior anchored `(size,root)` →
`genesis→latest` exact. Append-only, prev-linked, head==latest verified. **Synchronous
promotion-time anchor of frozen `N`** across all 4 lineages (source/HOTP/head/state-root) + latest→N
consistency + inclusion of `N`.

---

## D. PR2b-3 — Manifest + `importBase=max(C,S)` cross-authority saga (K)

**No false cross-DB atomic snapshot.** `C` (receiver-applied) is B's; `N`/`S` are A's.
1. **Freeze `N`** (§A revoke commits) + synchronous anchor of `N` (§C.2).
2. **A exports** (one A-PG tx, dual source+guard signed, canonical bytes) `SourceAuthoritySnapshot`:
   `{manifestSchemaVersion, contractVersion, accProfileVersion, registryVersion, streamId, epoch,
   sourceNodeId, snapshotBase S, canonical sorted state-set@S (maxTumblers/maxManifestBytes) +
   anchored stateRoot@S, frozen N head + the 4 anchored (leafCount,nodeCount,root), consistency S→N +
   inclusion of S and N, **applied-history material for [S, ...] needed for future dup/fork checks**,
   canonicalDigest}`.
3. **B signs a receiver-checkpoint RECEIPT** from B's DB: `bSig` binds
   `{streamId, commandId, targetEpoch, appliedC, appliedHeadDigest, **stateRootAfter@C**, generationId,
   manifestDigest, bundleDigest, registryVersion, freshnessNonce, B system_identifier}`.
4. **Normalize `importBase = max(C, S)` (K)** — ONLY after root equality/proof:
   - **`C ≥ S`:** the signed B receipt alone is insufficient — verify **B `stateRootAfter@C` EXACTLY
     equals A's anchored state-root@C** (and head@C); import base = `C`; tail = `C+1..N`.
   - **`C < S`:** import snapshot@S (must include the applied-history material for dup/fork checks);
     base = `S`; **tail = `S+1..N`** (not `C+1`).
   - Never `C > N`.
5. **Freshness/non-rollback (K):** the **anchor bundle digest + registryVersion are bound into the
   ACTIVE signed cutover command/head** — a self-contained old-but-valid bundle is otherwise
   replayable; B accepts only the bundle whose digest+version match the active command.

---

## E. PR2b-4 — Import into an isolated candidate generation on B (I)

- **Write-ahead IMPORTING** (control-side): a signed `IMPORTING` cutover state binds `{manifestDigest,
  bundleDigest, generationId, registryVersion}` before B imports.
- **Isolated generation.** Snapshot + tail land in a **candidate generation** (`tsk_import_generation`
  + `*_staging` keyed by `(streamId, epoch, command_id, generationId)`), **NOT visible as authority**.
  **No authoritative flip before `N`.** A single **generation pointer** flips **only** via the READY
  saga (§F). Until then imported state is invisible or explicitly read-only; **all consumers are
  generation-bound**. No partial staged state is ever authority.
- **Chunk conflict/gap DDL:** each chunk `(fromSeq, toSeq, chunkDigest, per-record payload digests)`;
  duplicate-conflict / gap / overlap → isolate, never merge.
- **Attest against a SIGNED ANCHOR BUNDLE (I) — B never reads the control DB in-tx.** The bundle is
  self-contained: anchor-chain head + registry head@version + the external-min-version witness +
  freshness (bound to the active command per §D.5). B verifies: canonical bytes + schema/layout;
  dual sigs + keyIds against the bundle's `registryVersion ≥ external min` (retired-ok-if-effective,
  compromised rejected); **completeness recompute of stateRoot@S** + MMR consistency `S→N` + inclusion
  vs the **anchored roots in the bundle**; HOTP lineage; `epoch`/`streamId`/`sourceNodeId` + **B
  `system_identifier` distinct from A and control** (attested). A flipped generation is authoritative
  **receiver/candidate** state, **NOT writable SOURCE** (that's PR2c).

---

## F. PR2b-5 — Tail chunked + old-epoch classify + exact READY saga (K, M)

- **Distinct authorities:** SOURCE ledger (A, `1..N`, accumulator-proven) vs RECEIVER applied (B).
  `C`=B applied; `N`=frozen source head; base=`max(C,S)`; tail=`base+1..N`.
- **Chunked resumable tail:** monotonic cursor `(fromSeq,toSeq)`, `maxBatchBytes`/`maxBatchItems`
  bounded, each carrying a **bounded RANGE MULTIPROOF against the anchored `N` root + exact per-record
  payload digests** (not a generic "inclusion proof"), staged + applied idempotently in order into the
  candidate generation, **generation-scoped checkpoints/history**, resuming on crash. Never terminally
  rejected for size.
- **Old-epoch classify — only after the signed boundary/anchor authority verified:**
  `seq ≤ base` → **duplicate-ok ONLY on EXACT applied-history record digest + head + HOTP match** (not
  merely `seq ≤ base`); `base < seq ≤ N` → apply only as **exact contiguous MMR-proven** record;
  post-boundary unproven → **isolate as fork evidence** (no halt). Any mismatch → isolate.
- **Exact durable READY saga (K)** — no implied atomicity:
  1. control **IMPORTING** write-ahead (binds manifest+bundle) → B import intent;
  2. B stages+applies tail to `N` → **B `PENDING_N` receipt** (signed, binds generationId+N+roots);
  3. control verifies → signs **READY / boundary anchor** (forward-CAS on the PR2a cutover head);
  4. B verifies the signed READY → **flips the generation pointer** → durable **B finalize ack**.
  Each state is individually durable; crash resumes from the last durable state. `READY→ACTIVE` = PR2c.

---

## G. Idempotent crash-resume

Import + tail replay idempotent (re-attest + exact-digest duplicate-ok). Crash before the pointer flip
→ candidate generation only; resume against the write-ahead IMPORTING + the saga state. Crash mid-tail
→ resume from the generation-scoped applied checkpoint. Post-`READY` = PR2c (rehydrate-not-reclaim).

---

## H. Exact failure matrix (M)

| # | Fault | Detected at | Response |
|---|-------|-------------|----------|
| 1 | stale-epoch append after revoke commit | source gate FOR SHARE (§A.2) | reject in-tx |
| 2 | pass start-check then stall; commit races expiry | **lock-based revoke linearization** (§A.2) | revoke waits → next append rejects (time bound honest) |
| 3 | in-flight append concurrent with revoke | conflicting row lock | revoke blocks; next append rejects |
| 4 | Redis precheck passes but PG fenced | source gate | reject in-tx (decisive) |
| 5 | replayed/reordered/rolled-back `grant_seq`; command reuse w/ diff tuple | grant install (§A.1) | reject / conflict-quarantine |
| 6 | source-PG restore rolls back grant_seq/head; **same-height fork** | **external witness digest+cadence** (§A.3) | quarantine |
| 7 | forged/expired/compromised grant or revoke | grant verify + registry | reject |
| 8 | **MMR leaf payload substitution (op/HOTP/head)** | substitution vectors (§B.1) | reject (root changes) |
| 9 | MMR path/consistency/bounds/domain/lineage/empty-root | vectors (§B.1) | reject |
| 10 | **partial / non-atomic multi-lineage or state-map update** | forward-CAS (§B.3) | reject (all-or-nothing) |
| 11 | **state omission (event proven, set incomplete)** | canonical sorted-set root recompute (§B.2) | reject |
| 12 | **historical root@S / root@C not retained** | persistent versioned state (§B.2) | reject (must be anchor-provable) |
| 13 | **B stateRoot@C ≠ A anchored root@C (C≥S)** | saga root-equality (§D.4) | reject |
| 14 | `C > N` / wrong base / `C<S` tail from C+1 | `importBase=max(C,S)` (§D.4) | reject / normalize |
| 15 | anchor chain gap / prev break / **anchor-head rollback** | anchor + registryVersion (§C.2) | reject |
| 16 | **registry rollback (in-DB monotonic only)** | external min-version witness (§C.1) | reject |
| 17 | retro compromise / blind re-sign / backdating | rederive-from-ledger + quorum (§C.1) | reject; rebuild path |
| 18 | **stale valid bundle replay** | bundle+version bound to active command (§D.5) | reject |
| 19 | manifest replay/wrong-source/epoch/tampered/oversize | attest (§D/§E) | reject before flip |
| 20 | B `system_identifier` == A or control | attest (§E) | reject |
| 21 | planted/conflicting/duplicate-digest/gap/overlap chunk | chunk DDL (§E) | isolate/quarantine |
| 22 | **candidate generation flipped authoritative before N** | generation pointer / READY saga (§E/§F) | impossible — flip only at READY |
| 23 | tail range multiproof / per-record payload mismatch | range multiproof (§F) | reject |
| 24 | old-epoch `seq≤base` digest/head/HOTP mismatch | tail classify (§F) | isolate (not dup-ok) |
| 25 | old-epoch `base<seq≤N` non-contiguous/unproven; post-boundary unproven | classify (§F) | isolate as fork (no halt) |
| 26 | boundary/READY before B reaches N | cutover CAS (§F) | reject |
| 27 | **crash at any saga state** (freeze/anchor/export/receipt/IMPORTING/tail/PENDING_N/READY/flip) | write-ahead + resume (§F/§G) | resume from last durable state; no partial authority |
| 28 | source **equivocation** (two heads @ a seq) | MMR consistency + witness (§A.3/§B) | reject/quarantine |

---

## I. Topology + drill/CI (honest)

- **State authorities:** source **A-PG (=5432, PR14)**, receiver **B-PG (= the PR14 B @ 5433 —
  REUSED)**, control **PG @ 5434 (PR2a)**. **Distinct `system_identifier` attested** across A/B/control.
  **Redis is a cross-checked coordinator/witness, NOT a durable authority** (single = mechanism-only;
  real 3-node Sentinel/quorum is PR2c).
- **Drills (fail-not-skip, real PG16 + real Redis):** b0 source-gate matrix (lock-based revoke,
  restore/fork witness, Redis-passes-but-PG-fenced); b1 accumulator contract + **substitution**
  vectors (MMR payload + state-map completeness recompute) + real-PG atomic all-lineage append; b2
  anchor genesis→N + registry retire/compromise + external-version rollback; b3 manifest +
  `importBase=max(C,S)` + root@C equality + dual-sig + signed B receipt + bundle-bound-to-command; b4
  staged import into a candidate generation + no-flip-before-N + independence; b5 chunked tail range
  multiproof + exact-digest old-epoch classify + the exact READY saga with crash at each state.

## J. PR2c (what closes #10)

`READY→ACTIVE` two-phase promotion (single epoch bump + unforgeable readiness capability,
rehydrate-not-reclaim recovery, source-write capability minted here); child-process **SIGKILL crash
matrix** across A/control/B (prove NO writer after any crash); real **3-node Redis Sentinel/quorum**
(WAITAOF/CKQUORUM/AOF/min-replicas/old-master-refusal/rollback); **measured RPO/RTO**. **#10 closes
only when PR2c is green.**
