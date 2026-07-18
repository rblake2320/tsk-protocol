# PR2b — Source fence gate, MMR accumulator, anchor chain, snapshot manifest, import + tail (toward closing TSK #10)

> **Status:** DESIGN ONLY. No code ships from this doc. **#10 stays OPEN through PR2b.** PR2b makes
> a receiver B a *promotable* source authority via a verifiable snapshot-at-`C` + tail `C+1..N`
> import under the PR2a signed cutover head. It does **NOT** close #10 — the two-phase
> `READY→ACTIVE` promotion, rehydrate-not-reclaim crash recovery, child-process SIGKILL matrix, a
> real 3-node Redis Sentinel/quorum, and measured RPO/RTO are **PR2c**.

Builds on the merged **PR2a** control-DB fencing foundation (`ha-control-fencing.ts`: signed
provisioning / epoch witness / monotonic command-bound lease / signed cutover head at `FENCED`,
per-op live catalog attestation + `FOR SHARE` authority stamp, `pg_catalog`-first search_path) and
the merged **#10 PR12/PR13/PR14** source outbox + `NodePostgresTransactor` + receiver checkpoint +
authenticated transport.

This revision incorporates the eight PR2b design-review corrections (C1–C8) inline; each is tagged.

---

## 0. Slice order (reordered per C3 — source gate FRONT-LOADED)

| Slice | Ships | Does NOT claim |
|-------|-------|----------------|
| **PR2b-0** | **Non-bypassable SOURCE in-tx fence/lease gate** (§A) | no snapshot/import; enables a *provable* frozen `N` |
| **PR2b-1** | **MMR accumulator: versioned CONTRACT + cross-impl vectors, THEN A-PG append integration** (§B) | no anchor/manifest |
| **PR2b-2** | **Control-DB anchor chain + signed key registry** (§C) | no manifest/import |
| **PR2b-3** | **`SourceAuthoritySnapshot` manifest** (state at `C`, binds `C`+anchored `N`, proves `C≤N`) + synchronous promotion-time anchor of `N` (§D) | no B import |
| **PR2b-4** | **Atomic import + attest on receiver-B** via isolated staging + one visibility flip (§E) | no tail/boundary |
| **PR2b-5** | **C/N/tail chunked resumable batches + old-epoch classification + `FENCED→IMPORTING→READY`** (§F) | does NOT reach `ACTIVE` (PR2c) |

**C3 ordering blocker (resolved).** PR2a shipped the *control-DB* lease but **not** a non-bypassable
*source-PG* in-tx fence. Without it a fenced-on-the-control-clock source could still accept a late
append, so "frozen final `N`" was unprovable. PR2b-0 front-loads the source gate; only after it
lands may any later slice speak of a frozen `N` or a promotion. (Alternative rejected by review: an
operator-quiesced mechanism with **no** frozen-`N`/promotion claim.)

---

## A. PR2b-0 — Non-bypassable source in-tx fence/lease gate (C3)

**Goal:** a stale-epoch or unleased writer loses **in its own SERIALIZABLE commit** on the source
PG, even after passing any Redis/pre-op check (Redis CAS alone has a check-to-commit TOCTOU; the
in-tx PG gate is the write authority).

- Extend the source fence row `tsk_outbox_fence` with **lease columns**: `lease_id`,
  `lease_epoch`, `lease_until_ms bigint`, `lease_grant_seq bigint`, `lease_grant_digest`,
  `lease_grant_key_id`. A control-issued, guard-signed **`LeaseGrant`** (from the PR2a control
  lease) is transported to the source and installed with a **strictly-increasing `lease_grant_seq`**
  (replay/rollback rejected) after **verifying the guard signature over the exact grant tuple**
  (same framing the control authority signed — source applier and control cannot diverge).
- **Every** source authority append runs `assertSourceWritable(exec, streamId, expectedEpoch)` in
  the SAME tx: read the fence row `FOR UPDATE`; require `lease_epoch == expectedEpoch`, `status
  active`, and `lease_until_ms > controlclock_now_ms` read in-tx; and the append's total tx deadline
  `< lease_until_ms − skew`. A stale-epoch or expired-lease append **fails in-tx** — non-bypassable.
- **Frozen-`N` definition (now provable):** once the control lease is revoked AND its monotonic
  max-expiry has elapsed on the control clock (PR2a `advanceEpoch` precondition) AND the source
  in-tx gate rejects any new append at the old epoch, the **source ledger cannot grow past `N`**.
  `N` := the final committed source head sequence at that instant.
- **Reaper/STONITH note:** PG16 has no universal tx-lifetime cap; a *session reaper*
  (`pg_terminate_backend` of stale-epoch backends) or STONITH is the belt to the in-tx suspenders,
  documented as a deployment control. PR2b-0 ships the in-tx gate + the reaper hook interface.

**PR2b-0 faults (matrix §H):** stale-epoch append after fence → in-tx reject; replayed/rolled-back
`lease_grant_seq` → reject; forged grant signature/keyId → reject; expired lease → reject; a
Redis-precheck-passing but PG-fenced writer → in-tx reject (the decisive test).

---

## B. PR2b-1 — MMR accumulator (contract-first, C1)

**C1: ship a versioned accumulator CONTRACT + cross-implementation test vectors FIRST, then the PG
append integration.** The MMR is our own **named profile** — the IETF **MMRIVER** draft is a
work-in-progress *reference for ideas only*, **not** a standards-conformance claim.

### B.1 Pinned profile (`mmrProfileVersion = 1`)
- **Domain-separated, versioned hashing.** Distinct one-byte (framed) domain tags for **leaf**,
  **internal node**, **peak-bag**, and **root**; each hash input is length-prefixed framed and
  carries `mmrProfileVersion`. `H = sha256`.
- **Separate MMRs per lineage (C1).** Three independent accumulators with distinct domains AND
  distinct node tables: **source-ledger** lineage, **HOTP** lineage, **head** lineage. A defined
  cross-lineage ordering is pinned (head appended after the row+HOTP leaves of the same sequence).
- **Indexing.** MMR node indices, leaf→position mapping, peak positions, and `mmrSize` are pinned
  with **unsigned 53-bit-safe integer bounds** validated at every boundary (`0 ≤ x ≤ 2^53`).
- **Root** = domain-tagged **bagging of peaks** high→low (order pinned).

### B.2 Proofs
- **Inclusion proof** for leaf `i` against `root(mmrSize)`: the audit path (siblings + peak bag).
- **Consistency proof** from `(size_a, root_a)` to `(size_b, root_b)`, `size_a ≤ size_b`: proves the
  first accumulator is a **prefix** of the second (append-only; no history rewrite).
- **Rejection vectors (pinned, cross-impl):** truncated/extended path, wrong sibling, wrong peak
  order, size/root mismatch, non-prefix consistency, out-of-range index, domain confusion (leaf hash
  accepted as node), profile-version mismatch. Each MUST reject.

### B.3 A-PG append integration
- Node/peak tables per lineage: `tsk_mmr_<lineage>_node (stream_id, pos bigint, hash, PK(stream_id,pos))`
  and a per-stream `tsk_mmr_<lineage>_head (stream_id, mmr_size bigint, mmr_root, updated_at)`.
- **Atomic append (C1):** in the SAME SERIALIZABLE tx as the source row append, insert the new
  leaf + all newly-formed internal nodes + advance peaks/root, `mmr_size` forward-CAS
  (affected-row = 1). The MMR root advances **exactly with** the ledger — never lazily.

---

## C. PR2b-2 — Control-DB anchor chain + key registry (C2)

- **Anchor chain** on the control DB begins at a **provisioned genesis anchor**; each later signed
  anchor `{streamId, lineage, mmrSize, mmrRoot, prevAnchorDigest, sourceSig, guardSig}` carries a
  **consistency proof from its immediately prior anchored `(size,root)`**. The chain of per-anchor
  consistency proofs makes **`genesis → latest` exact** (not merely latest→N). Append-only,
  prev-digest-linked, head==latest-history verified (PR2a chain pattern).
- **Key registry (C2)** on the control DB: a signed registry of source-signing and guard-signing
  public keys, **independently protected** (distinct from each other and from transport keys).
  **Rotation/revocation semantics are evaluated AT SIGNING TIME** — a manifest/anchor is verified
  against the keyIds valid *when it was signed* (overlap windows honored); a keyId **revoked** in
  the registry is rejected even if the signature is cryptographically valid.
- **Synchronous promotion-time anchor of `N` (C4):** after PR2b-0 freezes `N`, the promoter
  synchronously anchors the frozen `N` and proves consistency **latest-prior-anchor → N** + inclusion
  of `N`; the prior chain (genesis → latest) is already proven. Nothing is trusted un-anchored.

---

## D. PR2b-3 — `SourceAuthoritySnapshot` manifest (C4, C5-cap)

**C4 — snapshot is state at checkpoint `C`, not at `N`.** A snapshot "at `N`" would leave no tail.
The manifest is the **state at `C`** (the receiver's applied checkpoint at promotion start) and
**binds BOTH `C` and the anchored `N`**, proving **`C ≤ N`**; the tail `C+1..N` (§F) carries the
receiver from `C` to `N`.

Exported in **one consistent SERIALIZABLE tx** on the (PR2b-0-fenced) source PG:
- `manifestSchemaVersion`, `contractVersion`, `mmrProfileVersion`.
- `streamId`, `epoch` (fence epoch), `sourceNodeId`.
- **`snapshotCheckpoint C`** + the signed `SignedStreamHead` at `sequence = C` + the state-at-`C`
  tumbler set (**size-bounded**, C5): `maxManifestBytes`, `maxTumblers`, enforced before attest.
- **`sourceHeadN`** = the frozen final source head + its anchored MMR `(mmrSize=N, mmrRoot)` + a
  **bounded consistency proof `C → N`** and **inclusion of both `C` and `N`** against the anchored
  `N` root — so B independently verifies `C ≤ N` and `genesis → N`.
- `fenceToken`/`epoch`; `canonicalDigest` = sha256 over the canonicalized manifest.
- **Dual signatures:** source signature AND guard signature over `canonicalDigest`; keyIds resolved
  against the registry (C2).
- **Layout attestation:** `manifestSchemaVersion` + a pinned layout digest (mismatch → reject),
  mirroring the #10 `TSK_OUTBOX_SCHEMA_MANIFEST` pattern.
- **Tail is NOT size-capped** — only the state-at-`C` snapshot is (§F chunks the tail).

---

## E. PR2b-4 — Atomic import + attest on receiver-B (C5, C6)

**C5 — do NOT promise one huge transaction.** Large state imports as **isolated STAGING** with
per-chunk proof + idempotency, then **ONE atomic attest + visibility flip**. **No partial staged
state ever becomes authority.**

On receiver-B (a **third independent PG @ 5435, distinct `system_identifier` from A and control** —
C6):
1. **Stage** the snapshot-at-`C` (and later tail batches) into `*_staging` tables keyed by
   `(streamId, epoch, command_id)`, each chunk carrying its **bounded MMR inclusion proof** and
   applied **idempotently** (duplicate-ok on re-delivery). Staging is NOT visible as source authority.
2. **Attest** (one SERIALIZABLE tx): contract/schema/`manifestSchemaVersion`/layout match;
   recompute + match `canonicalDigest`; verify source **and** guard signatures + keyIds (rotation
   overlap, revoked rejected); verify **MMR inclusion of `C` and `N` + consistency `genesis→N`
   against the EXACT anchored `N` root** in the control DB; verify HOTP monotonic lineage against its
   domain-tagged MMR; verify `epoch`/`streamId`/`sourceNodeId` binding + distinct `system_identifier`;
   enforce the snapshot size bound.
3. **Visibility flip:** only if all pass, **atomically** mark the staged state authoritative
   (`import-complete` at `C`) and expose it. Any failure → the staged chunks are discarded/quarantined;
   **B has no writable source authority.**

---

## F. PR2b-5 — C/N/tail chunked batches + old-epoch classify + cutover transitions (C7)

**H8 — distinct authorities:** SOURCE ledger (`tsk_outbox_rows` + source checkpoint on A, contiguous
`1..N`, MMR-proven) vs RECEIVER applied (`tsk_outbox_receiver_checkpoint` on B). `C` = B's applied
checkpoint; `N` = frozen final source head; **tail = `C+1..N`**.

- **Chunked resumable tail (H9):** bounded BATCHES with a monotonic **batch cursor `(fromSeq,toSeq)`**
  advancing `C+1 → N`, each bounded by `maxBatchBytes` + `maxBatchItems`, each carrying its **bounded
  MMR inclusion proof against the anchored `N` root**, staged + applied **idempotently in order**,
  resuming from B's applied checkpoint on crash. The tail is **never terminally rejected for size**.
- **Old-epoch classification (C7 — ONLY after the signed boundary/anchor authority is verified):**
  - `seq ≤ C` (in applied history) → **duplicate-ok**;
  - `C < seq ≤ N` → **MUST apply/reconcile as tail** (real committed source data);
  - the **signed epoch-transition boundary commits ONLY AFTER B reaches `N`**;
  - **after** the boundary, an old-epoch record **not proven in applied history** → **isolated as
    old-epoch fork/evidence** (quarantined), **without halting the new-epoch stream** — never
    silently dropped. Classification runs **only once** the boundary/anchor authority is verified
    (C7); before that, records are staged, not classified.
- **Cutover transitions** on the PR2a signed control-DB cutover head:
  `FENCED → IMPORTING` (import started, manifest bound once attested) `→ READY` (B reached `N`,
  boundary anchored). `READY → ACTIVE` is **PR2c**. Each transition is a signed forward-CAS.

---

## G. Idempotent crash-resume

Import + tail replay are idempotent (re-attest + duplicate-ok apply). Crash mid-import (before the
visibility flip) → no writable source; resume re-attests durable staged state. Crash mid-tail →
resume from B's applied checkpoint. A crash after `READY` is a PR2c concern (rehydrate-not-reclaim).

---

## H. Exact failure matrix

| # | Fault | Detected at | Response |
|---|-------|-------------|----------|
| 1 | stale-epoch source append after fence | source in-tx gate (§A) | reject in-tx (non-bypassable) |
| 2 | Redis-precheck passes but PG fenced | source in-tx gate | reject in-tx (decisive test) |
| 3 | replayed/rolled-back `lease_grant_seq` | grant install (§A) | reject (strictly-increasing) |
| 4 | forged/expired/revoked-keyId lease grant | grant verify (§A) | reject |
| 5 | MMR truncated/extended/wrong-sibling/peak-order | inclusion proof (§B.2) | reject vector |
| 6 | non-prefix / size-root-mismatch consistency | consistency proof (§B.2) | reject vector |
| 7 | domain confusion / profile-version mismatch | MMR hashing (§B.1) | reject vector |
| 8 | anchor chain gap / prev-digest break | anchor verify (§C) | reject (genesis→N not exact) |
| 9 | manifest replay / wrong-source / wrong-epoch | attest (§E) | reject |
| 10 | tampered / oversize snapshot | attest size bound (§D/§E) | reject before flip |
| 11 | manifest layout/schema-version mismatch | attest (§D) | reject |
| 12 | dual-sig invalid / keyId revoked-at-signing | attest (§C/§E) | reject |
| 13 | `system_identifier` of B == A/control | attest (§E) | reject (not independent) |
| 14 | `C > N` (snapshot ahead of source head) | manifest bind (§D) | reject (C≤N invariant) |
| 15 | partial staged state read as authority | visibility flip (§E) | impossible — flip is atomic all-or-nothing |
| 16 | crash mid-import / mid-tail | resume (§G) | idempotent re-attest / resume from checkpoint |
| 17 | late old-epoch record `C<seq≤N` | tail classify (§F) | apply-as-tail (never dropped) |
| 18 | late old-epoch record post-boundary, unproven | boundary classify (§F) | isolate as fork evidence (never dropped, no halt) |
| 19 | boundary commit attempted before B reaches `N` | cutover CAS (§F) | reject |

---

## I. Topology + drill/CI

- **Four independent state authorities:** source **A-PG**, **control-PG**, receiver **B-PG @ 5435**
  (distinct `system_identifier`, attested), and **Redis** (single instance = mechanism-only; real
  3-node Sentinel/quorum is PR2c).
- **Drills (fail-not-skip, real PG16 + real Redis):** per-slice — b0 source-gate matrix (incl. the
  Redis-precheck-passes-but-PG-fenced test); b1 MMR contract vectors + real-PG atomic-append; b2
  anchor chain genesis→N + rotation/revocation; b3 manifest export + C≤N + dual-sig; b4 staged
  import + atomic flip + independence; b5 chunked tail resume + old-epoch classify + cutover CAS.
- CI adds a third control-independent PG service (5435) for B.

## J. What PR2b explicitly does NOT do (PR2c)

`READY→ACTIVE` two-phase promotion (single epoch bump + unforgeable readiness capability,
rehydrate-not-reclaim crash recovery, epoch-separated streams); child-process **SIGKILL crash
matrix** across A/control/B (prove NO writer after any crash); real **3-node Redis Sentinel/quorum**
with persistence/replication + failover/rollback; **measured RPO/RTO**. **#10 closes only when PR2c
is green.**
