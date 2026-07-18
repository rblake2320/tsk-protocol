# PR2 — HA fencing, snapshot resync, and promotion cutover (closing TSK #10)

Design only. **No implementation until Codex approves this document.** Supersedes the
mesh design packets. Incorporates Codex's review blockers (1)–(6) and precision fixes.

## 0. Scope & boundaries

- **No HA / production / uptime claim** until the full PR2c drill is green.
- **#10 stays OPEN** through PR2a and PR2b, and until the PR2c full acceptance is green
  **including a real 3-node Redis Sentinel/quorum** with configured persistence/replication
  and demonstrated failover **and rollback** evidence. Single Redis is **fail-closed
  mechanism evidence only** — it cannot close #10.
- A receiver is **never** a source authority without the minted source-readiness capability
  (atomic import + attest under a signed epoch-transition boundary).
- No Enterprise #28 collision; coordinate before touching it.

## 1. Failure domains (three distinct)

| Role | Component | Responsibility |
|---|---|---|
| Promotion **claim coordinator** | Redis (`RedisFencingStore`) | fast cross-node serialization of *who may promote*; NOT the write authority |
| **Control DB (third domain)** — durable intent + epoch witness | a **dedicated third PG** (`tsk_ha_epoch_witness`, `tsk_ha_cutover`), **not node A or B** | write-ahead promotion intent (§3.3 H1) + the monotonic epoch floor + provisioned genesis |
| Source **write authority** | per-node **PG** `tsk_outbox_fence` row **+ a DB-clock-bounded expiring write lease** | the fence token **and unexpired lease** checked **inside every SERIALIZABLE authority mutation** |

**Q1 (answered):** the witness/control DB is a **fixed third failure domain**, never node A
or B — otherwise loss of the old source would block promotion. Redis, the control DB, and
each node's PG are three distinct domains.

**H2/H3 — proving A is fenced under partition/outage (control-granted lease).** "Advance A's
PG fence first" is **not sufficient**: a promoter partitioned from A cannot advance A's fence,
and A must not be able to self-renew its own authority. So A's write authority is a
**control-authority-GRANTED, DB-clock-bounded expiring write lease**:
- **Renewal requires a control-authority grant** — A cannot extend its own lease; a partitioned
  A therefore cannot keep writing past the current grant.
- The lease's **max expiry is recorded in the control DB** (externally observable without
  reaching A's PG), so the promoter knows exactly when A must be dead.
- Every A authority tx **re-checks the lease in a non-bypassable PRE-COMMIT hook**, and the
  **total tx deadline is strictly shorter than the remaining lease margin** (leveraging the #10
  transactor's transaction deadline + `statement_timeout`), so a socket pause/GC after the
  check cannot let a commit land after expiry.
- **To promote**, the control authority **stops granting renewals and revokes**, then **waits
  `max_expiry + clock_skew + max_tx/commit_window`** (all control-observable, **no A-PG access
  needed**) — **or** performs **STONITH**. **Promotion refuses (fail-closed) if it cannot prove
  A fenced.** Fault test: A reaches its own PG but not Redis/control with an in-flight tx → its
  grant lapses → its pre-commit lease check fails → self-fenced; promotion proceeds only after
  the control-observable wait.
Production profile may select STONITH instead of wait-for-expiry; the drill uses lease-expiry
(deterministic, no infra).

## 2. Slice order (reordered per Codex)

- **PR2a — fencing foundation only.** Epoch witness + provisioned genesis; Redis
  absent/rollback → quarantine; source PG fence token advanced + checked inside every
  SERIALIZABLE authority mutation; the saga order (§4.3). No split-brain claim until green.
- **PR2b — canonical bounded snapshot manifest** + atomic import+attest + tail resync +
  idempotent crash-resume.
- **PR2c — two-phase promotion state machine** + child-process crash matrix + full
  end-to-end drill (+ 3-node Sentinel to close #10).

---

## 3. PR2a — Fencing foundation

### 3.1 Schemas (PR2a)

```
-- external monotonic epoch witness (authority PG, distinct failure domain from Redis)
CREATE TABLE tsk_ha_epoch_witness (
  stream_id       text PRIMARY KEY,
  epoch           bigint      NOT NULL CHECK (epoch >= 0),   -- highest-ever promoted epoch
  genesis_marker  text        NOT NULL,                       -- explicit provisioned-genesis nonce
  provisioned_at  timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
-- existing: tsk_outbox_fence(stream_id, fence_token) — the in-tx source write fence.
-- fence_token is DERIVED from the epoch (canonical decimal of the epoch), so advancing the
-- epoch advances the authoritative write token in the SAME PG tx.
```

Redis side keeps the existing `FenceRecord {nodeId, fenceEpoch, expiresAt, commandId, active}`.

### 3.2 Provisioned genesis — its own signed saga (H2)

Provisioning is itself cross-resource (witness + Redis) and crash-ambiguous, so it uses the
same write-ahead pattern and **an explicit completion flag — never infer "provisioned" from a
witness row alone**:
1. **Signed `PROVISIONING` intent** in the control DB first (`stream_id`, `genesis_marker`,
   guard signature), idempotent.
2. Write the witness genesis row (`epoch = 0`) **with `state = 'incomplete'`**.
3. Write the Redis fence record for epoch 0.
4. Flip the witness to **`state = 'provisioned'`** (the ONLY marker of a usable stream).
A crash mid-provision leaves an **explicit incomplete-provision state** → promotion/writes
refuse until provisioning is idempotently completed or governed-reset. `never-provisioned`
(no intent) is distinct from `incomplete` (intent present, not `provisioned`) is distinct from
`provisioned-then-Redis-lost` (provisioned + Redis absent/lower → §3.4 quarantine).

### 3.3 Promotion saga (Redis + 3 PG are NOT atomic — write-ahead intent + resource-fencing order)

Redis and the PGs cannot commit atomically, so the saga uses a **durable, guard-signed
write-ahead INTENT** (H1) as the single authoritative record of an in-flight promotion, then
orders the effects so a partial failure leaves **no writer**. `E' = witness.epoch + 1`. Every
step is idempotent, keyed by `(streamId, E', commandId)`.

0. **(H1) Durable signed intent BEFORE any effect — exactly ONE active intent per stream.**
   Atomically insert a `PREPARING` reservation into the **control DB** keyed by `stream_id`
   (a `UNIQUE (stream_id) WHERE phase NOT IN (terminal states)` partial constraint) with
   `epoch = E'`, `commandId`, and a **guard signature**. Conflict resolution — **never
   leapfrog an in-flight intent**:
   - **same `commandId`** → **idempotent resume** of the existing intent;
   - **different `commandId`** while an intent is active → **deny / quarantine**; the new
     promotion is refused until the current intent reaches a **terminal governed state**
     (`ACTIVE`, or an explicit governed `ABORTED`). A racing promoter does **not** pick `E'+1`.
   This is the first durable action; a crash after any later effect is always recoverable from
   this authenticated intent. Without a committed intent, no fence/claim happens.
1. **Allocate/verify `E'`** against the witness (`W`), require provisioned + Redis-not-lost (§3.4).
2. **Fence OLD A + PROVE it.** Advance `tsk_outbox_fence` (token = `E'`, `lease_until` frozen)
   in A's PG, then **prove A fenced per H2** — wait `lease_until + margin` on A's PG clock (or
   STONITH). Every in-flight/new A mutation re-reads the fence + lease `FOR UPDATE` in its own
   SERIALIZABLE tx and loses. **Refuse (fail-closed) if A cannot be proven fenced.**
3. **Claim `E'` in Redis** (CAS: accept only if `R < E'`) — only after A is proven fenced.
4. **Advance the witness** to `E'` (monotonic, `FOR UPDATE`, forward-only).
5. **Advance B's PG fence + begin import** (PR2b/PR2c).

**Crash after every step** (fault A6/C1) resumes by **rehydrating** from the committed intent
(§5.4): re-read intent/witness/Redis/PG-fence, validate consistency with `(E', commandId)`,
and continue idempotently. **Partial-failure ⇒ NO writer** (old A fenced or fencing pending,
B not ready). No new claim, no epoch bump on resume.

### 3.4 Redis-loss fail-closed (blocker 3)

On any claim/promotion path, cross-check Redis `R` against the witness `W`:
- witness absent → **not provisioned** (must provision, not promote);
- Redis absent, OR `R < W` → the Redis authority was **lost or rolled back** →
  **QUARANTINE / fail-closed**: deny promotion and deny writes; require a **governed reseed**
  (an explicit, audited operation that re-establishes Redis from the witness floor). **Never
  re-initialize the epoch from an empty/stale Redis, and never bump the epoch gratuitously.**
- **Lost CAS response** (Redis ack lost): the claim is ambiguous → reconcile by re-reading
  Redis+witness; the claim is idempotent by `(nodeId, E', commandId)`; never assume success.

**H4/H10 — Redis durability under Sentinel async failover (internet-verified against official
Redis docs).** Redis OSS Sentinel **explicitly does NOT guarantee** that acknowledged writes
survive a failover; async replication + an old-master partition can lose writes, and **3-node
Sentinel is failure-detection, NOT consensus**. `WAIT` is **best-effort replication ack, not
strong consistency and not fsync**. `WAITAOF` (Redis **≥ 7.2**) proves local/replica **AOF
fsync counts**. Therefore:
- the **external control-DB witness remains the epoch authority + quarantine backstop** —
  Redis is the coordinator/optimization, never the sole truth;
- config to evidence for #10: **`appendonly yes` + `appendfsync everysec|always`**,
  **`min-replicas-to-write ≥ 1`** with bounded `min-replicas-max-lag`, and a **`WAITAOF` after
  every fence write with validated return counts** (not `WAIT` alone);
- drill (Redis ≥ 7.2) validates: **`WAITAOF` local+replica fsync counts**, **Sentinel
  `CKQUORUM`**, min-replicas, AOF **rewrite/restart**, **min-replica split partition**,
  **old-master isolation → write refusal**, and a **rollback cross-check** (on `R < W` the
  witness quarantines → governed reseed);
- the design defines the **write-outage window / RTO** during failover (writes fail-closed
  until a quorum-durable fence is re-confirmed against the witness).
Single Redis (no Sentinel) is **mechanism-only** and cannot close #10.
Sources: redis.io/docs/latest/commands/wait, /commands/waitaof, /operate/oss_and_stack/management/sentinel.

### 3.5 In-tx source fence (TOCTOU close, blocker 2)

Every source mutation (`appendInTx`) already does `SELECT fence_token FROM tsk_outbox_fence
WHERE stream_id=$1 FOR UPDATE` and asserts `record.fenceToken == authoritative token` in the
same SERIALIZABLE tx (existing `StaleFenceError`). PR2a: promotion advances that token
(step 2) so a lower-epoch writer that passed a stale Redis pre-check **still fails in-tx**.
A Redis pre-check alone can never close this.

### 3.6 Invariants (PR2a)

- **I1 Monotonic epoch:** `tsk_ha_epoch_witness.epoch` never decreases; every promotion
  strictly increases it by exactly 1.
- **I2 Fail-closed on Redis loss:** if the witness shows provisioned `W` but Redis is absent
  or `< W`, no promotion/source write proceeds.
- **I3 In-tx fence:** no source mutation commits with `fenceToken != authoritative PG fence`
  at commit time.
- **I4 No re-initialize:** an empty Redis after provisioning never yields a fresh epoch-0 claim.
- **I5 Single winner:** the saga (step 2 before step 3) + I3 admit at most one committing
  source writer per epoch; a lower claim can never commit a source write after a higher
  promotion advances the fence.

### 3.7 PR2a fault tests (real Redis + PG)

concurrent lower/higher claims (lower loses in-tx); lost CAS response (idempotent reconcile);
node A isolated from Redis (lease cannot refresh → A fails-closed, no writes); Redis
down / data-loss / stale-replica (witness cross-check → quarantine, never re-init); PG
ambiguous-commit / 40001 serialization races on witness+fence (AmbiguousCommit reconciliation
from #10, no lost/duplicated epoch); **crash after every saga step** (§3.3) → rehydrate, no
double-promote, no A resurrection.

---

## 4. PR2b — Snapshot manifest, import + attest, tail resync

### 4.1 `SourceAuthoritySnapshot` manifest (canonical, bounded — blocker 4)

Exported in **one consistent SERIALIZABLE tx** on the (already-fenced) source PG at the
frozen final head **N**:

- `schemaVersion`, `contractVersion`
- `streamId`, `epoch` (the fence epoch of the frozen source), `sourceNodeId`
- **final source head N**: the signed `SignedStreamHead` at `sequence = N`
- `sourceCheckpoint` (final applied source `sequence = N`)
- **head-chain integrity — REQUIRED externally-anchored MMR (Decision 3, Q2).**
  Dual-signature attestation alone is **insufficient** for our independently-verifiable
  evidence target. The source maintains an **incremental Merkle Mountain Range (MMR)** over the
  head chain, **updated atomically with every append** (the MMR root advances in the same
  SERIALIZABLE append tx) and its roots **anchored in the control DB**. The manifest carries the
  MMR root at `N` + a **bounded inclusion/consistency proof** so B **independently verifies**
  `genesis→N` continuity — not merely trusts two signatures. Dual signatures still authenticate
  the manifest; the MMR provides the verifiable proof. Full lineage is also retained for audit.
- **HOTP authoritative state**: per-tumbler high-water counters + a consumed-lineage covered by
  the same MMR/anchored-checkpoint mechanism (verifiable, not attestation-only); full lineage
  retained for audit.
- `fenceToken` / `epoch`
- `canonicalDigest` = sha256 over the canonicalized manifest
- **signatures**: source signature **and** guard signature over `canonicalDigest`

**H7 — manifest key custody, rotation, revocation, schema attestation, limits.**
- **Custody**: source-signing key on the source authority; guard-signing key on the guard
  (both distinct from the transport keys). Public keys in a signed **key registry** on the
  control DB.
- **Rotation**: `keyId`-scoped with overlap (a manifest is verified against the registry's
  currently-valid keyIds); **revocation** — a revoked keyId in the registry is rejected even
  if the signature is otherwise valid.
- **Schema attestation**: the manifest schema itself is versioned (`manifestSchemaVersion`)
  and its layout digest is pinned + attested (mismatch → reject), mirroring the #10
  `TSK_OUTBOX_SCHEMA_MANIFEST` pattern.
- **Limits (cardinality + size)**: max manifest bytes, max tumblers, max tail length
  (`N - C`), max per-tumbler lineage — all bounded and enforced before attest; an oversize or
  over-cardinality manifest is rejected (terminal).

### 4.2 Import + attest (atomic, all-or-nothing)

On B, in one SERIALIZABLE tx: verify contract/schema match; recompute + match
`canonicalDigest`; verify source **and** guard signatures + keyIds (rotation overlap);
verify head-chain continuity `genesis → N` via the accumulator + the signed head; verify
HOTP monotonic lineage; verify `epoch`/`streamId`/`sourceNodeId` binding; enforce the size
bound. **Only if all pass**, atomically persist B's imported source state and mark
`import-complete`. Any failure rolls back entirely → no partial source authority.

### 4.3 C, N, tail — distinct authorities (H8) + chunked tail (H9) + old-epoch handling

**H8 — do NOT conflate source-ledger vs receiver-applied state.** Define each authority/table:
- the **SOURCE ledger** = `tsk_outbox_rows` + `tsk_outbox_source_checkpoint` on the source PG:
  the contiguous `1..N` sequence the source has **committed/produced**, with the hash-linked
  head chain + MMR. **N is proven from this contiguous source ledger** (no gaps, MMR-verified),
  NOT from any receiver state.
- the **RECEIVER applied** state = `tsk_outbox_receiver_checkpoint` on B: what B has **applied**.
- **C** = B's receiver-**applied** checkpoint; **N** = the frozen final **source** head (A fenced
  before the snapshot → the source ledger cannot grow past `N`).
- **tail** = `C+1 .. N` (the source rows B has not yet applied).

**H9 — the tail is CHUNKED, never terminally rejected for size.** The bounded-size limit
applies to the **snapshot manifest** (state at `N`). A large backlog `C+1..N` is **transported
in bounded BATCHES**, each with its own bounded MMR inclusion proof, applied idempotently in
order until B reaches `N`. A valid backlog exceeding one manifest is **resynced in chunks**, not
rejected.
- A late **old-epoch** record is classified, **never silently dropped**:
  - `seq ≤ C` (already in applied history) → **duplicate-ok**;
  - `C < seq ≤ N` → **MUST apply/reconcile as tail** (it is real committed source data);
  - the **signed epoch-transition boundary may commit ONLY AFTER the receiver reaches N**;
  - **after** the boundary, any old-epoch record **not proven in applied history** is
    **isolated as old-epoch fork / evidence** (quarantined as evidence) **without halting the
    new-epoch stream** — never silently dropped.

### 4.4 Idempotent crash-resume

Import and tail-replay are idempotent (re-attest + duplicate-ok apply). A crash mid-import
(before ready) → no writable source, resume re-attests durable state; crash mid-tail →
resume from B's applied checkpoint.

### 4.5 PR2b faults

replay / truncate / wrong-source / wrong-epoch / tampered / oversize snapshot → attest
rejects; keyId rotation across epoch (overlap accepted, unknown rejected); crash
mid-import / mid-tail → idempotent resume; the `C<seq≤N` tail must be applied before the
boundary; post-boundary unproven old record → isolated as evidence, new epoch not halted.

---

## 5. PR2c — Two-phase promotion state machine, crash matrix, full drill

### 5.1 Cutover state (durable, **per-transition signed**, forward-CAS) — H5

Each phase transition writes a **new signed row** whose signature covers the **current**
phase and the **previous state digest** (an immutable initial signature cannot authenticate a
later mutated phase). Transitions are applied by **forward CAS on `prev_state_digest`** so a
stale/racing writer cannot fork the state machine.

```
CREATE TABLE tsk_ha_cutover (
  stream_id        text        NOT NULL,
  epoch            bigint      NOT NULL,            -- target E'
  command_id       text        NOT NULL,
  seqno            bigint      NOT NULL,            -- monotonic transition number
  phase            text        NOT NULL,            -- PREPARING|FENCED|IMPORTING|READY|ACTIVE|ABORTED
  -- exactly ONE active intent per stream (H1): a partial UNIQUE index over stream_id
  -- WHERE phase NOT IN ('ACTIVE','ABORTED') rejects a second in-flight intent.
  prev_state_digest text,                            -- digest of the prior row (forward CAS)
  state_digest     text        NOT NULL,            -- canonical digest of THIS row
  manifest_digest  text,                            -- bound once import attested
  guard_key_id     text        NOT NULL,
  guard_signature  text        NOT NULL,            -- signs (stream_id,epoch,command_id,seqno,phase,prev_state_digest,manifest_digest)
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, epoch, seqno)
);
```
A transition commits iff its `prev_state_digest` equals the current head row's `state_digest`
(forward CAS) and the guard signature verifies against a currently-valid, non-revoked keyId.

### 5.2 States & transitions (forward-only, idempotent, each a durable signed tx)

- **PREPARING** (§3.3 step 0): the durable signed intent — the first authenticated state.
- **PREPARING → FENCED**: saga §3.3 steps 1–4 (allocate `E'` → **fence + prove A fenced** →
  Redis claim → advance witness); write the signed `FENCED` transition. Old A fenced; **B not writable**.
- **FENCED → IMPORTING → READY**: import + attest §4 (advance B fence, import tail `C+1..N`,
  commit the signed epoch-transition boundary **only after B reaches N**); on success **mint
  the unforgeable source-readiness capability** (module-private mint, WeakMap-bound to
  `manifest_digest` + `E'`, same pattern as `SchemaReadyToken`); write the signed `READY`
  transition binding `manifest_digest`.
- **READY → ACTIVE — cross-DB durable-operation saga (H6).** The `N+1` append lives in **B-PG**
  and the `ACTIVE` transition in the **control DB** — **distinct DBs, so one SERIALIZABLE tx is
  impossible**. Use a durable saga, idempotent at each step:
  1. **B-PG commits `N+1` as `pending`/NON-publishable** under `E'` (durable but not yet
     deliverable/authoritative);
  2. the **signed `ACTIVE` transition** is written to the control DB (binding `manifest_digest`
     + the pending `N+1` id);
  3. **activate/publish `N+1` idempotently** (mark publishable).
  A crash between steps leaves `N+1` durable-but-pending (never published, never two sources);
  resume completes activation idempotently. This replaces the earlier (incorrect) single-tx
  claim — a distributed 2PC is possible but not preferred.

### 5.3 Epoch-transition boundary & epoch-separated streams (blocker 6)

The receiver checkpoint is keyed by `(streamId, epoch)`. The signed boundary marks
`prevA_head(N) → epoch-transition(E') → B:N+1`. Pre-boundary (old-epoch) traffic is handled
per §4.3 (duplicate-ok / tail / isolated-evidence) and **can never reject-epoch →
terminal-quarantine + halt the new-epoch stream**.

### 5.4 Crash recovery — rehydrate, never re-claim (precision fix 2)

Redis claim is non-idempotent and the readiness token is process-local, so recovery **must
not issue a new claim or bump the epoch**. On restart:
1. read the durable signed `tsk_ha_cutover` state (verify its signature);
2. **rehydrate the exact current epoch** — validate the Redis record, PG fence, witness, and
   (if past IMPORTING) the manifest against `(E', command_id)`; do **not** claim;
3. resume the remaining forward transitions idempotently;
4. **remint the readiness capability only by re-attesting the durable state** (never fabricate);
5. **governed re-promotion cannot bypass or gratuitously bump the epoch.**
Crash in FENCED (before READY) → no writable source (safe); crash in READY (before first
write) → capability re-derived from durable attested state; **A is never resurrected**
(its epoch `< E'`, fenced by I1/I3).

### 5.5 Child-process crash matrix (real SIGKILL)

The source/publisher runs as a **child process**; SIGKILL after **every saga step** (§3.3)
and **every cutover phase** (FENCED, IMPORTING, READY); **B crash after import/before ready**
and **after promote/before first write**; restart → resume idempotently; assert no
split-brain, no A resurrection, converged.

### 5.6 Full end-to-end drill + RPO/RTO

2 independent PG16 + real Redis (single = mechanism; **3-node Sentinel/quorum** = the closing
evidence) + the PG witness. Run A→B promotion under faults §6 + the crash matrix.
- **data-loss RPO — reported PER FAULT (H3), not a blanket 0.**
  - **process / network / recoverable-storage** faults → **RPO = 0**: the committed tail is
    still durable on A, so attested import + tail `C+1..N` converges losslessly.
  - **catastrophic old-A disk/volume loss** with the async outbox → **RPO = the
    committed-but-undelivered tail** (it existed only on A). This is honestly non-zero.
  - **#10 closes with the HONEST measured per-fault RPO** (0 for recoverable faults; = the
    committed-undelivered tail for source-volume loss). The doc does **not** imply
    storage-loss RPO=0. A **synchronous independent durable receipt before the source ACK**
    (mutation reaches an independent durable quorum/third journal first) is tracked as a
    **separate higher-assurance mode/gate** that achieves RPO=0 under storage loss at a latency
    cost — **not required to close #10**.
- **RTO — reported per fault** = wall-clock from the fault/promote trigger to the new authority
  being **writable** (originating `N+1` under `E'`) **and** converged to `N`; includes the H2
  lease-expiry wait and the H4 Redis failover write-outage window.

### 5.7 To close #10

- PR2c green **including** real Redis (≥7.2) Sentinel with `WAITAOF`/AOF/min-replicas evidence,
  `CKQUORUM`, old-master-isolation write-refusal, and rollback cross-check (§3.4) — with the
  **external control-DB witness remaining authoritative** (Sentinel is not consensus);
- the **externally-anchored MMR** `genesis→N` proof (Decision 3), independently verified on import;
- **honest per-fault RPO** + per-fault RTO (§5.6);
- the synchronous-durability RPO=0-under-storage-loss mode is a **separate gate**, not required.

### 5.8 PR2a evidence harness (H11)

The PR2a drill uses **three distinct PostgreSQL systems** — A, B, and the **control DB** —
plus Redis, and **attests all three have distinct `system_identifier`** (no shared instance).
It **crashes at each saga step** (signed intent → fence → Redis claim → witness advance) and at
provisioning steps, and **proves NO writer** exists after any crash (old A fenced/pending, B not
ready). No split-brain claim; PR2a merges bounded/mechanism-only on this evidence.

---

## 6. Consolidated fault matrix

| # | Fault | Slice | Expected |
|---|---|---|---|
| A1 | concurrent lower/higher claim | 2a | higher wins; lower's write fails in-tx |
| A2 | lost Redis CAS response | 2a | idempotent reconcile, no double-promote |
| A3 | node A isolated from Redis | 2a | A cannot refresh lease → fail-closed, no writes |
| A4 | Redis down / data-loss / stale-replica | 2a | witness cross-check → quarantine, never re-init |
| A5 | PG ambiguous-commit / 40001 on witness+fence | 2a | AmbiguousCommit reconcile, no lost/dup epoch |
| A6 | crash after every saga step | 2a/2c | rehydrate, no double-promote, no A resurrection |
| B1 | replay/truncate/wrong-source/wrong-epoch/tampered/oversize snapshot | 2b | attest rejects |
| B2 | keyId rotation across epoch | 2b | overlap accepted, unknown rejected |
| B3 | crash mid-import (before ready) / mid-tail | 2b | no writable source; idempotent resume |
| B4 | old record `C<seq≤N` | 2b | applied as tail before boundary |
| B5 | post-boundary unproven old record | 2b/2c | isolated as old-epoch fork/evidence; new epoch not halted |
| C1 | crash after each cutover phase (FENCED/IMPORTING/READY) | 2c | resume idempotently; never resurrect A |
| C2 | B crash after import/before ready; after promote/before first write | 2c | re-attest capability; safe resume |
| C3 | equal vs different concurrent promote commands | 2c | idempotent by command_id; one epoch winner |
| C4 | lease expiry / clock skew | 2c | fail-closed; no stale writer |
| C5 | disk-full / backpressure | 2c | fail-closed, no partial state |
| C6 | interrupted cutover | 2c | idempotent resume; A never resurrected |
| C7 | terminal stale delivery during cutover | 2c | must NOT halt the new epoch (§5.3) |
| H1 | crash after fence/claim but before durable intent | 2a/2c | impossible — signed intent (§3.3 step 0) is written FIRST |
| H2 | A partitioned from guard/Redis but can write its own PG (in-flight tx) | 2a | A's lease expires → self-fences; promotion refuses until A proven fenced |
| H3 | catastrophic old-A disk/volume loss (async outbox) | 2c | RPO = committed-undelivered tail (honest); 0 only in synchronous-durability mode |
| H4 | Redis Sentinel async failover loses an acked fence | 2c | witness cross-check quarantines; bounded write-outage RTO; needs AOF/min-replicas/WAIT |
| H5 | tampered/mutated cutover phase row | 2c | per-transition signature + forward CAS rejects |
| H6 | crash between READY and first N+1 origination | 2c | durable saga: N+1 pending→ACTIVE→publish; never published-while-READY, never two sources |
| H1b | different-commandId promotion vs an in-flight intent | 2a/2c | deny/quarantine until current intent terminal; no leapfrog |
| H2b | crash mid-provisioning (witness+Redis) | 2a | explicit incomplete-provision state; refuse until completed; never infer provisioned |
| H8 | source-ledger vs receiver-applied conflation | 2b | N proven from contiguous source ledger + MMR; distinct tables/authorities |
| H9 | valid backlog C+1..N exceeds one manifest | 2b | chunked/batched tail with per-batch MMR proof; never rejected for size |
| H10 | Sentinel async failover loses acked fence / old-master partition | 2c | WAITAOF+AOF+min-replicas+CKQUORUM; old-master write-refusal; witness authoritative + quarantine/reseed |
| H11 | crash at each saga/provision step (3 distinct PG + Redis) | 2a | distinct system_identifier attested; prove NO writer after any crash |

## 7. Resolved answers + remaining choices

All decisions from Codex's reviews are now folded in — **no open choices remain**:
- **Q1 / Fencing domain:** witness = fixed **third** failure-domain control DB (§1).
- **A fencing (H2/H3):** **control-granted expiring lease** + wait-for-expiry (drill) **or**
  STONITH (production profile); promotion refuses without proof (§1/§3.3).
- **RPO (Decision 2):** **honest per-fault RPO** closes #10; storage-loss RPO=0 is **not
  implied**; synchronous-durability is a **separate higher-assurance gate** (§5.6).
- **Manifest proof (Decision 3):** **externally-anchored incremental MMR is REQUIRED** for #10;
  dual-signature-only is insufficient (§4.1).
- **Redis (H10, internet-verified):** Sentinel is not consensus; **witness stays authoritative**;
  `WAITAOF`/AOF/min-replicas/`CKQUORUM`/old-master-isolation/rollback evidence, Redis ≥ 7.2 (§3.4).
- **Q3:** PR2a merges **bounded/mechanism-only** after its fencing evidence (§5.8).
- **H1** exactly-one-active-intent, no leapfrog (§3.3.0); **H2** provisioning saga (§3.2);
  **H5** per-transition forward-CAS signatures (§5.1); **H6** cross-DB durable saga (§5.2);
  **H7** manifest keys/limits (§4.1); **H8** source-ledger vs applied (§4.3); **H9** chunked
  tail (§4.3); **H11** 3-distinct-PG evidence (§5.8).
