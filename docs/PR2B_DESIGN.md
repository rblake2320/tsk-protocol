# PR2b — Simple, correct durable cutover: full freeze + full snapshot at N (toward closing TSK #10)

> **Status:** DESIGN ONLY. No code until this concise design is reviewed once. **#10 stays OPEN
> through PR2b.** PR2b makes receiver **B** a *promotable candidate* by fully freezing source **A**,
> exporting the **complete** history `1..N` + complete state-at-`N`, and having B independently replay
> and verify it, then one atomic pointer flip. **PR2c** activates B (Sentinel/crash/RPO-RTO) and
> closes #10.
>
> **v1 scope decision (supersedes the earlier MMR/state-map/S-C/tail draft).** Optimize for FEWER
> MOVING PARTS and a real rollout path. **O(N) export/replay and a promotion-window downtime are
> explicit v1 tradeoffs** — incremental MMR / historical snapshot-at-`C` / tail resync / a new key
> registry are a **later performance** concern, **not** #10 correctness. This eliminates the S/C,
> completeness-proof, and receiver-map criticals.

Builds on merged **PR2a** (control fencing: signed cutover head, lease, witness) and **#10 PR12/13/14**
(source outbox with `opDigest` + signed hash-linked head chain, `NodePostgresTransactor`, receiver
checkpoint, two-node transport **A=5432 / B=5433**, control **PG=5434**). All signed artifacts use a
pinned canonical encoding (JCS / I-JSON) before hashing/signing.

---

## 1. Full freeze (source A) + `SourceFrozenReceipt` — bound before FENCED

- Control issues a **signed revoke command** (`command_id`, `epoch`). On A, every source append tx
  holds the **fence row `FOR SHARE` through commit** (PR2b-0 gate); the **revoke `UPDATE`** takes the
  conflicting lock — it **waits for all in-flight appends to finish**, commits, and thereafter every
  new append sees `revoked` and **fails in-tx**. A never reads the control clock/DB in its tx.
- After the revoke commits, A emits a signed **`SourceFrozenReceipt`** =
  `{command_id, epoch, N, signedHeadDigest@N, sourceStateDigest@N, sourceNodeId, sourceSig}`, where
  `N` = the max committed source head at freeze, `signedHeadDigest@N` from the existing head chain, and
  `sourceStateDigest@N` = a digest over the complete canonical sorted state-at-`N`.
- The fence/status is **one authoritative A-PG row**; the append lock+check and the revoke + read of
  `N`/head/state are **linearized by SERIALIZABLE tx ordering** on that row.
- **Control binds the `SourceFrozenReceipt` BEFORE the Redis/witness `FENCED` advance** — a new
  versioned **`SOURCE_FENCED`** cutover phase (`PREPARING → SOURCE_FENCED → FENCED`), a signed
  forward-CAS on the PR2a cutover head. The migration bumps `CONTROL_SCHEMA_VERSION` + re-pins the
  manifest digest (offline, code-reviewed — PR2a R5-H1). Frozen `N` is provable ONLY after the A-PG
  revoke commits (or STONITH/reaper), and the external witness **synchronously + monotonically binds
  the EXACT frozen `N` + `signedHeadDigest@N` + `sourceStateDigest@N` BEFORE `SOURCE_FENCED`** (a
  stale periodic witness misses a suffix rollback); a source-PG restore/regression → quarantine.

## 2. Complete export (A frozen) — one manifest root, dual independent signatures

- With A frozen, export the **complete canonical source history `1..N`** — for every record the
  **FULL canonical sanitized mutation PAYLOAD + all signed-head fields (sequence, prev/head digest,
  signature, keyId, alg)** (not merely immutable fields + `opDigest` — `opDigest` alone cannot replay
  or materialize state) — **and** the complete sorted state-at-`N`, in **bounded chunks**
  (`maxChunkBytes`/`maxChunkItems`).
- **A single versioned canonical REPLAY function** is the one authority: guard/B **recompute
  `opDigest` from the payload, verify every head signature + prev/head link `1..N`, and DERIVE state
  by replay** — **never trusting the exported state-at-`N`**. `signedHeadDigest@N` and
  `sourceStateDigest@N` are **comparison OUTPUTS** of that replay, **never replay inputs**; the frozen
  receipt (§1) uses the same function.
- **Historical verification keys** required by `1..N` must resolve under the **EXISTING verifier
  policy** (#10 key handling); a missing / revoked / unknown key **fails closed**. **No new registry.**
- **`manifestRoot` is versioned + length-prefixed over an EXACT ordered chunk INVENTORY** — each entry
  `{kind, ordinal, seqFrom, seqTo, itemCount, byteDigest}` covering exactly `1..N` with **no gaps /
  extras**, so reorder / truncation / substitution / a missing or duplicate chunk fail. Manifest =
  `{manifestSchemaVersion, streamId, epoch, commandId, sourceNodeId, N, frozenReceiptDigest,
  signedHeadDigest@N, sourceStateDigest@N, chunkCount, inventory, manifestRoot, canonicalDigest}`
  (binds the `commandId`, `sourceNodeId`, and `frozenReceiptDigest`). **Source signs**; the **guard
  verifies the exact active cutover command + the frozen receipt FIRST, then INDEPENDENTLY replays +
  verifies + signs** — dual signatures under **independent custody** (source sig then guard sig; not
  one atomic tx). **NO MMR, no historical `S`/`C`, no tail, no new registry/state-map.**

## 3. Receiver B — stage, replay, verify, one atomic flip, `BFinalizedReceipt`

- B stages the manifest + chunks into an **isolated candidate generation** (`generationId`), **not
  visible as authority**. Exact **chunk conflict / gap / overlap / duplicate-digest checks** (isolate,
  never merge).
- B **independently replays history `1..N`** (recomputing the signed head chain from the `opDigest`s)
  and **materializes state-at-`N`**, then **recomputes `signedHeadDigest@N` + `sourceStateDigest@N` +
  `manifestRoot`** and matches the manifest; verifies **both** source and guard signatures; verifies
  `epoch`/`streamId`/`sourceNodeId` and **B `system_identifier` distinct from A and control**
  (attested). B never reads the control DB in its tx (verifies the signed manifest bundle).
- Only if all pass, B **seals** the generation and **CONSTRUCTS + SIGNS the `BFinalizedReceipt`
  FIRST**; then **ONE SERIALIZABLE CAS tx VERIFIES that signed receipt and atomically installs
  checkpoint/head/state + flips the singleton generation pointer + stores the complete signed receipt
  — all together**. There is therefore **no post-flip / pre-receipt state**: recovery always returns
  the already-stored receipt. The generation is authoritative **receiver/candidate** state (NOT
  writable source — PR2c).
  **`BFinalizedReceipt`** binds `{commandId, epoch, N, generationId, frozenReceiptDigest,
  manifestDigest, manifestRoot, sourceSigId+digest, guardSigId+digest, signedHeadDigest@N,
  sourceStateDigest@N, B system_identifier, bSig}` — the `commandId` and all digests are **derived
  from the manifest**, not free-standing.

## 4. Control cutover ordering (no ready-before-flip ambiguity)

`PREPARING → SOURCE_FENCED` (bind `SourceFrozenReceipt`) `→ FENCED` (PR2a Redis+witness) `→ IMPORTING`
(**only after** the freeze receipt is bound) `→ READY` (**only AFTER** control verifies the
`BFinalizedReceipt` and **compares its `commandId` / `frozenReceiptDigest` / `manifestDigest+root` /
signature identities against the ACTIVE cutover command** — B has already flipped). Each transition is
a signed forward-CAS on the PR2a cutover head. `READY → ACTIVE` is **PR2c**. Every step is
individually durable + crash-resumable; no implied cross-DB atomicity.

## 5. Idempotent crash-resume

Freeze (revoke) is idempotent on `command_id`. Export + stage + replay are idempotent (re-stage /
re-verify; exact chunk-digest duplicate-ok). Crash before the flip → candidate generation only
(discardable). **The flip and the signed `BFinalizedReceipt` are ONE atomic SERIALIZABLE CAS**, so
there is **no post-flip / pre-receipt state** — recovery returns the already-stored receipt. Crash
before control READY → resume re-presents the stored receipt. No partial staged state is ever authority.

---

## Failure matrix

| # | Fault | Detected at | Response |
|---|-------|-------------|----------|
| 1 | stale-epoch append after revoke commit | source gate FOR SHARE (§1) | reject in-tx |
| 2 | in-flight append vs revoke | conflicting row lock | revoke waits; next append rejects |
| 3 | Redis precheck passes but PG fenced | source gate | reject in-tx (decisive) |
| 4 | source-PG restore / same-height fork rollback | external witness (§1) | quarantine |
| 5 | `FENCED` attempted before `SourceFrozenReceipt` bound | `SOURCE_FENCED` CAS (§1/§4) | reject |
| 6 | manifest replay / wrong source / epoch / tampered | verify (§3) | reject before flip |
| 7 | history/state digest or `manifestRoot` mismatch on replay | B replay (§3) | reject |
| 8 | source sig or guard sig invalid / missing independent guard replay | dual-sig verify (§2/§3) | reject |
| 9 | chunk conflict / gap / overlap / duplicate-digest | chunk checks (§3) | isolate, never merge |
| 10 | B `system_identifier` == A or control | attest (§3) | reject |
| 11 | candidate generation read as authority before flip | pointer flip (§3) | impossible — flip is atomic all-or-nothing |
| 12 | `IMPORTING` before freeze receipt / `READY` before `BFinalizedReceipt` | cutover order (§4) | reject (no ready-before-flip) |
| 13 | crash at any step (freeze/export/import/replay/flip/READY) | write-ahead + resume (§5) | resume from last durable state; no partial authority |

---

## Topology + drills (honest)

- **A-PG=5432**, **B-PG = the PR14 PG @5433 (reused)**, **control PG=5434**; distinct attested
  `system_identifier` across A/B/control. **Redis is a cross-checked coordinator, NOT a durable
  authority** (single instance = mechanism-only; real 3-node Sentinel/quorum is PR2c).
- **Drills (fail-not-skip, real A/B/control PG16 + real Redis):** the freeze matrix (lock-based revoke,
  restore witness, Redis-passes-but-PG-fenced); full export + dual independent signatures; B
  stage/replay/verify + chunk conflict/gap + atomic flip + independence; the cutover order
  (SOURCE_FENCED → FENCED → IMPORTING → READY); **crash injected at every step**.

## What PR2b does NOT do (PR2c closes #10)

`READY → ACTIVE` promotion (activate B as writable source, unforgeable readiness capability,
rehydrate-not-reclaim recovery); child-process **SIGKILL crash matrix** across A/control/B; real
**3-node Redis Sentinel/quorum** + failover/rollback; **measured RPO/RTO**. **#10 closes only when
PR2c is green.** (v1 performance follow-up, out of #10 scope: incremental MMR + snapshot-at-`C` + tail
resync to remove the O(N)/downtime cost.)
