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
| **Control DB (third domain)** — durable intent + epoch witness | a **dedicated third PG** (`tsk_ha_epoch_witness`, `tsk_ha_cutover_head`/`_history`, `tsk_ha_lease_head`/`_history`, `tsk_ha_provisioning`), **not node A or B** | write-ahead promotion intent (§3.3 H1) + the monotonic epoch floor + provisioned genesis |
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

### 3.1 Schemas (PR2a) — executable DDL sketches (control DB unless noted)

```sql
-- (correction 6) schema/version authority — SINGLETON + pinned full-catalog attestation
CREATE TABLE tsk_ha_schema (
  id               int PRIMARY KEY CHECK (id = 1),   -- exactly one authority row
  version          int         NOT NULL,
  catalog_manifest text        NOT NULL,             -- pinned digest over the full control catalog (cf. TSK_OUTBOX_SCHEMA_MANIFEST)
  applied_at       timestamptz NOT NULL DEFAULT now()
);

-- (H2, correction 6) provisioning — state transitions are affected-row=1 forward CAS with a
-- SIGNED state digest per transition (not an unsigned mutable state under an initial signature)
CREATE TABLE tsk_ha_provisioning (
  stream_id         text PRIMARY KEY,
  genesis_marker    text        NOT NULL,
  state             text        NOT NULL CHECK (state IN ('intent','incomplete','provisioned')),
  state_seq         bigint      NOT NULL,             -- monotonic
  prev_state_digest text,                             -- forward CAS
  state_digest      text        NOT NULL,             -- canonical digest of THIS state
  guard_key_id      text        NOT NULL,
  guard_signature   text        NOT NULL,             -- signs (stream_id,genesis_marker,state,state_seq,prev_state_digest,state_digest)
  created_at        timestamptz NOT NULL DEFAULT now(),
  provisioned_at    timestamptz
);
-- append-only provisioning history (symmetry with lease/cutover), keyed (stream_id, state_seq)
CREATE TABLE tsk_ha_provisioning_history (
  stream_id         text        NOT NULL,
  genesis_marker    text        NOT NULL,
  state             text        NOT NULL CHECK (state IN ('intent','incomplete','provisioned')),
  state_seq         bigint      NOT NULL,
  prev_state_digest text,
  state_digest      text        NOT NULL,
  guard_key_id      text        NOT NULL,
  guard_signature   text        NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, state_seq),
  UNIQUE (stream_id, state_digest)
);
-- each provisioning transition, in one tx: INSERT the signed history row, then
--   UPDATE tsk_ha_provisioning SET ... WHERE stream_id=$1 AND state_digest=$prev (affect 1).

-- external monotonic epoch witness (authoritative floor; distinct failure domain from Redis)
CREATE TABLE tsk_ha_epoch_witness (
  stream_id       text PRIMARY KEY REFERENCES tsk_ha_provisioning(stream_id),
  epoch           bigint      NOT NULL CHECK (epoch >= 0),   -- highest-ever promoted epoch
  state           text        NOT NULL CHECK (state IN ('incomplete','provisioned')),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

-- (H3, correction 2) control-authority GRANTED write lease. A cannot self-renew. Grants are
-- MONOTONIC + forward-CAS (grant_seq + prev_grant_digest) so an OLD signed grant cannot be
-- replayed on A: A's grant applier accepts a grant only if its grant_seq > A's current lease
-- grant_seq (checked in-tx), and rejects a lower/equal one even if the signature is valid.
-- (fix 2) a lease grant AND its revocation are the SAME kind of object: a signed, monotonic
-- grant-STATE transition. `status` is inside the signed fields, so revocation is authenticated
-- (never a mutate-in-place of an unsigned `revoked` bool). Head row = current; history = audit.
CREATE TABLE tsk_ha_lease_head (
  stream_id          text PRIMARY KEY,
  lease_id           text        NOT NULL,     -- opaque, rotated per grant
  holder_node_id     text        NOT NULL,     -- the source authority (A)
  epoch              bigint      NOT NULL,
  grant_seq          bigint      NOT NULL,     -- monotonic per stream (anti-replay)
  status             text        NOT NULL CHECK (status IN ('active','revoked')),
  granted_max_expiry timestamptz NOT NULL,     -- CONTROL-DB clock; A dead after this (+skew+tx window)
  prev_grant_digest  text,                     -- forward CAS
  grant_digest       text        NOT NULL,     -- canonical digest of THIS grant state (binds ALL fields incl status)
  guard_key_id       text        NOT NULL,     -- rotation via a signed key registry; a revoked keyId is rejected
  guard_signature    text        NOT NULL      -- signs (stream_id,lease_id,holder,epoch,grant_seq,status,granted_max_expiry,prev_grant_digest,grant_digest)
);
-- explicit history (NOT LIKE ... INCLUDING ALL — that would copy the head PK and permit only
-- one row per stream). Append-only, keyed by (stream_id, grant_seq).
CREATE TABLE tsk_ha_lease_history (
  stream_id          text        NOT NULL,
  lease_id           text        NOT NULL,
  holder_node_id     text        NOT NULL,
  epoch              bigint      NOT NULL,
  grant_seq          bigint      NOT NULL,
  status             text        NOT NULL CHECK (status IN ('active','revoked')),
  granted_max_expiry timestamptz NOT NULL,
  prev_grant_digest  text,
  grant_digest       text        NOT NULL,
  guard_key_id       text        NOT NULL,
  guard_signature    text        NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, grant_seq),
  UNIQUE (stream_id, grant_digest)
);
-- every grant/revoke, in one control-DB tx: INSERT the signed history row, then
--   UPDATE tsk_ha_lease_head SET ... WHERE stream_id=$1 AND grant_digest=$prev
--   (affected-row=1 forward CAS, strictly-increasing grant_seq).
```
The A-PG grant applier is a **separate role** from the runtime (write) role; it installs a grant
only with strictly-increasing `lease_grant_seq` — a replayed older still-valid signed grant
affects 0 rows and is rejected in-tx.

On **each source PG** (A / a promoted B), the existing `tsk_outbox_fence(stream_id, fence_token)`
gains lease columns; the write token AND an unexpired, non-revoked lease are checked in-tx:
```sql
ALTER TABLE tsk_outbox_fence
  ADD COLUMN lease_id         text,
  ADD COLUMN lease_epoch      bigint,
  ADD COLUMN lease_until      timestamptz,   -- mirror of the control grant, checked in the pre-COMMIT hook
  ADD COLUMN lease_grant_seq  bigint,        -- (fix 1) monotonic; the applier rejects a lower/equal grant
  ADD COLUMN lease_grant_digest text,        -- binds the installed grant (anti-replay)
  ADD COLUMN lease_grant_key_id text;        -- the verified guard keyId that signed the grant
-- grant applier: UPDATE ... WHERE stream_id=$1 AND (lease_grant_seq IS NULL OR lease_grant_seq < $newSeq)
--   (affected-row=1, strictly-increasing) — a replayed older still-valid signed grant affects 0 rows.
```
`fence_token` is the canonical decimal of `epoch`, so a promotion advances the authoritative
write token in the SAME PG tx as the fence/lease update. Redis keeps the existing
`FenceRecord {nodeId, fenceEpoch, expiresAt, commandId, active}` as the claim coordinator only.

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

### 3.3 Promotion saga (Redis + PGs are NOT atomic — write-ahead intent + resource-fencing order)

(PR2a touches the source PG + control PG + Redis; the receiver-B PG enters in PR2b — §5.8.)

Redis and the PGs cannot commit atomically, so the saga uses a **durable, guard-signed
write-ahead INTENT** (H1) as the single authoritative record of an in-flight promotion, then
orders the effects so a partial failure leaves **no writer**. `E' = witness.epoch + 1`. Every
step is idempotent, keyed by `(streamId, E', commandId)`.

0. **(H1) Durable signed intent BEFORE any effect — exactly ONE active intent per stream.**
   Admission is the **`tsk_ha_cutover_head` CAS (§5.1)**, not a partial-unique index: a new
   `PREPARING` intent is admitted only when the head row's `phase` is terminal
   (`ACTIVE`/`ABORTED`) or the head is absent — the `UPDATE ... WHERE stream_id=$1 AND phase IN
   ('ACTIVE','ABORTED')` (or an insert-if-absent) must affect exactly 1 row, and it writes the
   signed `PREPARING` head + a signed history row with `epoch = E'`, `commandId`, and the guard
   signature. Conflict resolution — **never leapfrog an in-flight intent**:
   - **same `commandId`** → **idempotent resume** of the existing intent;
   - **different `commandId`** while an intent is active → **deny / quarantine**; the new
     promotion is refused until the current intent reaches a **terminal governed state**
     (`ACTIVE`, or an explicit governed `ABORTED`). A racing promoter does **not** pick `E'+1`.
   This is the first durable action; a crash after any later effect is always recoverable from
   this authenticated intent. Without a committed intent, no fence/claim happens.
1. **Allocate/verify `E'`** against the witness (`W`), require provisioned + Redis-not-lost (§3.4).
2. **Fence OLD A + PROVE it — on the CONTROL clock, not A's PG (blocker 3/4).**
   - **Revoke the control lease grant** — a NEW signed grant-state transition to
     `status='revoked'` (`tsk_ha_lease_head` forward-CAS, next `grant_seq`), always reachable and
     not dependent on A. From now A gets no renewal (a partitioned A's mirrored grant expires).
   - **Prove A dead without A-PG access**: wait `granted_max_expiry + clock_skew + max_tx/commit_window`
     on the **control-DB clock**. (`granted_max_expiry` is the control-recorded max; A mirrors
     `lease_until ≤ granted_max_expiry` and its non-bypassable pre-commit hook fails once passed.)
   - **HONESTY (blocker 4):** a client deadline + pre-commit hook alone **cannot** stop a COMMIT
     completing after expiry under a stalled partition, and **PG16 has no universal
     server-side total-transaction-lifetime cap**. So A's node MUST enforce one of, and the
     drill proves it: (a) a **session reaper** — a watchdog on A's PG that
     `pg_terminate_backend()`s any backend older than the lease (backed by `statement_timeout` +
     `idle_in_transaction_session_timeout` tuned below the lease margin); or (b) **STONITH**.
     Lease-expiry-without-enforced-termination is documented as insufficient under a stalled
     partition.
   - If A's PG is reachable, also advance its `fence_token`/`lease_until` immediately (an
     optimization; the control wait is the authority).
   - **Refuse (fail-closed) if A cannot be proven fenced.**
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
- **`R > W` (Redis ahead of the witness)** — legitimate only mid-saga (Redis `E'` claimed at
  step 3 before the witness advanced at step 4). **Only the exact signed active intent
  `(streamId, E', commandId)` in `tsk_ha_cutover_head` may reconcile it** (complete step 4,
  advancing `W` to `R`). **Every other caller quarantines** (a `R > W` without the matching
  active intent is treated as an anomaly). `R < W` or Redis-absent stays the rollback path
  (quarantine, governed reseed) — never re-initialize.

**Governed ABORT & epoch reuse (blocker: abort semantics).** A governed `ABORT` of an intent
**cannot undo** a fence / Redis claim / witness advance that already happened, nor permit reuse
until reconciled:
- **pre-effect abort** (intent still `PREPARING`, no fence/claim/witness effect) → the target
  `E'` **is reused** by the next promotion (nothing was consumed);
- **post-effect abort** (any effect applied) → **before** the head transitions to terminal
  `ABORTED`, the abort saga (under the SAME signed intent) **reconciles/consumes `E'` fully
  across witness + Redis + fences** — e.g. if Redis claimed `E'` but the witness had not
  advanced, advance the witness to `E'` (§3.4 `R>W` reconciliation) so the epoch is consistently
  consumed everywhere. **Only after that reconciliation** does the head reach `ABORTED`, and the
  next intent uses `witness.epoch + 1 = E'+1`. This is what lets **"never reuse after an effect"
  and "never skip"** both hold — `E'` is neither reused (it is consumed) nor skipped (the witness
  is now exactly at `E'`, so `+1` is contiguous).

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
- `sourceCheckpoint` = the **final committed SOURCE sequence `N`** (from the source ledger — not
  any receiver-applied state; see H8/§4.3)
- **head-chain integrity — REQUIRED MMR with an explicit CROSS-DB boundary (Decision 3, correction 3).**
  Two distinct mechanisms, not one atomic step across DBs:
  - **A-PG (local, atomic):** an incremental **MMR** root advances **in the same SERIALIZABLE
    append tx** as each append (leaf = `H(leafVersion ‖ domainTag ‖ headDigest)`, domain-separated
    and versioned; **HOTP lineage and head lineage use separate domain-tagged MMRs** with a
    defined ordering).
  - **Control DB (external anchor CHAIN):** the anchor chain **begins at a provisioned genesis
    anchor**; each later signed anchor (`{streamId, mmrSize, mmrRoot, prevAnchorDigest, guard+source
    sig}`) **proves consistency from its immediately prior anchored size/root**. The chain of
    per-anchor consistency proofs makes **`genesis → N` exact** — not merely latest-anchor→N.
  - **At promotion:** after fencing freezes `N`, the promoter **synchronously anchors the frozen
    `N`** and proves consistency **from the latest prior anchor → N** plus inclusion of `N`; the
    prior chain (genesis → latest anchor) is already proven. The **unanchored suffix** is assured
    by this synchronous promotion-time anchor — nothing is trusted un-anchored.
  - The manifest carries the anchored `N` root + the bounded consistency/inclusion proof so B
    **independently verifies** `genesis→N`; dual signatures authenticate the manifest, the MMR
    is the verifiable proof; full lineage retained for audit.
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
- **Limits (SNAPSHOT only)**: max manifest bytes + max tumblers for the state-at-`N` snapshot,
  enforced before attest. **The tail `C+1..N` is NOT size-limited** — it is resumable chunked
  batches (§4.3), so a large valid backlog is never terminally rejected.

### 4.2 Import + attest (atomic, all-or-nothing)

On B, in one SERIALIZABLE tx: verify contract/schema match; recompute + match
`canonicalDigest`; verify source **and** guard signatures + keyIds (rotation overlap, revoked
keyId rejected); verify head-chain continuity `genesis → N` by an **MMR inclusion + consistency
proof against the EXACT anchored `N` root** in the control DB (not a generic accumulator);
verify HOTP monotonic lineage against its domain-tagged MMR; verify `epoch`/`streamId`/
`sourceNodeId` binding; enforce the snapshot size bound. **Only if all pass**, atomically persist
B's imported source state and mark `import-complete`. Any failure rolls back entirely → no
partial source authority.

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

**H9 — the tail is a resumable CHUNKED stream, never terminally rejected for size.** A large
backlog `C+1..N` is transported in **bounded BATCHES** with an explicit **batch cursor** —
`(fromSeq, toSeq)` monotonically advancing from `C+1` toward `N` — each batch bounded by
**`maxBatchBytes` and `maxBatchItems`**, carrying its own **bounded MMR inclusion proof against
the anchored `N` root**, applied idempotently in order (resume from B's applied checkpoint on
crash) until B reaches `N`. Batches never overlap the terminal size limit — only the snapshot
manifest is size-capped.
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

**Blocker-2 fix — authoritative HEAD row + immutable HISTORY.** A partial-unique over history
rows is self-violating (PREPARING stays while FENCED is appended → two non-terminal rows).
Instead: **one `tsk_ha_cutover_head` row per stream** (the single authoritative current state,
updated by `state_digest` CAS with `affected rows = 1`) + an append-only signed
`tsk_ha_cutover_history`. This also closes the authoritative-head / fork gap.

```sql
-- authoritative CURRENT state: exactly one row per stream (H1: one active intent)
CREATE TABLE tsk_ha_cutover_head (
  stream_id       text PRIMARY KEY,
  epoch           bigint      NOT NULL,      -- target E' of the in-flight/last intent
  command_id      text        NOT NULL,
  seqno           bigint      NOT NULL,      -- monotonic transition number
  phase           text        NOT NULL CHECK (phase IN ('PREPARING','FENCED','IMPORTING','READY','ACTIVE','ABORTED')),
  state_digest    text        NOT NULL,      -- canonical digest of the current head
  manifest_digest text,                      -- bound once import attested
  pending_n1_digest text,                    -- (H8/H6) full digest of the pending N+1 (head/fence/id) once READY->ACTIVE saga starts
  updated_at      timestamptz NOT NULL DEFAULT now()
);
-- append-only, per-transition SIGNED history (forward CAS on prev_state_digest)
CREATE TABLE tsk_ha_cutover_history (
  stream_id         text        NOT NULL,
  epoch             bigint      NOT NULL,
  command_id        text        NOT NULL,
  seqno             bigint      NOT NULL,
  phase             text        NOT NULL,
  prev_state_digest text,                     -- must equal the head's state_digest at apply time (CAS)
  state_digest      text        NOT NULL,
  manifest_digest   text,
  pending_n1_digest text,
  guard_key_id      text        NOT NULL,
  guard_signature   text        NOT NULL,     -- signs (stream_id,epoch,command_id,seqno,phase,prev_state_digest,state_digest,manifest_digest,pending_n1_digest)
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, epoch, seqno)
);
```
A transition, in one control-DB tx: append the signed history row, then
`UPDATE tsk_ha_cutover_head SET ... WHERE stream_id=$1 AND state_digest = $prev` (must affect
exactly 1 row — forward CAS). The guard signature must verify against a currently-valid,
non-revoked keyId. A **new promotion is admitted only when the head phase is terminal**
(`ACTIVE`/`ABORTED`) — H1 exactly-one-active-intent, enforced by the single head row.

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
  2. the **signed `ACTIVE` transition** is written to the control DB, and its signature
     **binds the pending `N+1`'s FULL digest** (`pending_n1_digest` = head + fence + row id) —
     not just an id (blocker 8);
  3. **activate/publish `N+1` idempotently** (mark publishable), only after verifying the B-PG
     pending row matches `pending_n1_digest`.
  **Recovery (blocker 8):** on restart in the READY→ACTIVE saga, **verify the B-PG pending/
  published state against the signed `pending_n1_digest`** before reminting the capability or
  allowing writes. If B-PG has **lost the pending `N+1` after ACTIVE was signed → FAIL CLOSED**;
  never recreate `N+1` from unauthenticated data. A crash between steps leaves `N+1`
  durable-but-pending (never published, never two sources); resume completes activation
  idempotently. (A distributed 2PC is possible but not preferred.)

### 5.3 Epoch-transition boundary & epoch-separated streams (blocker 6)

The receiver checkpoint is keyed by `(streamId, epoch)`. The signed boundary marks
`prevA_head(N) → epoch-transition(E') → B:N+1`. Pre-boundary (old-epoch) traffic is handled
per §4.3 (duplicate-ok / tail / isolated-evidence) and **can never reject-epoch →
terminal-quarantine + halt the new-epoch stream**.

### 5.4 Crash recovery — rehydrate, never re-claim (precision fix 2)

Redis claim is non-idempotent and the readiness token is process-local, so recovery **must
not issue a new claim or bump the epoch**. On restart:
1. read the authoritative `tsk_ha_cutover_head` row **and verify the matching signed
   `tsk_ha_cutover_history` row** (`state_digest` + guard signature) — not any obsolete table;
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

### 5.8 PR2a evidence harness (H11 — honest topology)

PR2a exercises the **fencing foundation only**, which involves the **source PG (A)** and the
**control DB** + **Redis** — **two distinct PostgreSQL systems + Redis** (the distinct
**receiver B** PG enters in PR2b; PR2a does **not** inflate the topology to 3 PG). The drill
**attests A-PG and control-PG have distinct `system_identifier`** (no shared instance),
**crashes at each saga/provisioning step** (provisioning intent → witness genesis → Redis
genesis → complete; and promote: signed intent → lease revoke/expiry → fence → Redis claim →
witness advance), and **proves NO writer** exists after any crash (old A fenced or fencing
pending). No split-brain claim; PR2a merges **bounded/mechanism-only** on this evidence.

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
| H11 | crash at each saga/provision step (A-PG + control-PG + Redis) | 2a | distinct system_identifier attested; prove NO writer after any crash (B-PG enters 2b) |

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

---

## Erratum-R4 (2026-07-18) — Redis genesis epoch, superseding the epoch-0 genesis claim

The original design (§3.2) described a **Redis epoch-0 genesis claim** written between the
`incomplete` and `provisioned` provisioning steps. Independent adversarial review of the PR2a
implementation established that this is **incompatible with the production `RedisFencingStore`**,
whose record validator requires `fenceEpoch >= 1` (an epoch-0 claim returns
`TSK_FENCE_RECORD_CORRUPT` and writes no key). The store deliberately models fence epochs as
**≥ 1**, with the pre-promotion/genesis state represented by the **absence** of a record
(`current() === null`).

**Corrected rule (authoritative):**

1. **Provisioning is control-DB only.** The signed provisioning saga (intent → incomplete +
   signed witness genesis → provisioned) makes **no** Redis claim. The authoritative genesis is a
   **signed witness floor of epoch 0** with **no** Redis record.
2. **The first Redis record is the first promotion (epoch 1).** `advanceEpoch(target=1)` writes the
   first `RedisFencingStore` record.
3. **Redis-vs-witness authority policy** (fail-closed, `assertRedisAuthority`):
   - `current() === null` **AND** signed `witness == 0` → **canonical genesis**, admissible.
   - `current() === null` **AND** signed `witness > 0` → **loss/rollback → quarantine**.
   - `current().fenceEpoch < witness` → **rollback → quarantine**.
   - `current().fenceEpoch > witness` → admissible **only** for the exact active intent
     (`fenceEpoch == targetEpoch && commandId == the PREPARING command`); otherwise quarantine.
4. **On an idempotent post-FENCED retry** (`assertFencedAuthority`), Redis must still reflect the
   fenced epoch (or later); a null/rolled-back record is a loss → quarantine (never report a
   promotion durable without reading the authority).

The external signed **witness** remains the authoritative epoch floor; Redis is the cross-node
claim coordinator, always cross-checked against the witness, never trusted alone. This erratum does
not change the §5 promotion/import/attest machinery or the #10 acceptance boundary (real 3-node
Redis Sentinel/quorum + persistence/replication + failover/rollback + measured RPO/RTO).

### Fence-TTL note (mechanism scope)

`advanceEpoch` requires the Redis claim TTL to still cover a **configured worst-case
final-tx + commit + clock-skew budget** (`FenceProof.minClaimRemainingMs`), validated against the
control-DB clock **inside the final FENCED transaction**. This is **mechanism evidence** that the
claim is not about to expire at commit — it is **not** a universal commit-time guarantee nor a
source-side pre-commit fence. The non-bypassable in-transaction **source** fence/lease (a stale
writer loses in its own commit even after passing a Redis pre-check) is a subsequent PR2a milestone.
