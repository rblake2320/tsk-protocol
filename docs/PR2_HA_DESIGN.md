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

**H2 — proving A is fenced under partition/outage.** "Advance A's PG fence first" is **not
sufficient** for HA: a promoter partitioned from A cannot advance A's fence, yet an isolated
A that can still reach its own PG would keep writing. Therefore A's write authority is a
**DB-clock-bounded expiring write lease** (`tsk_outbox_fence.lease_until`, A's PG clock),
re-checked `FOR UPDATE` inside **every** A mutation tx immediately before commit — so a tx
cannot commit once the lease has expired. Promotion proves A fenced by **one of**:
(a) **wait-for-expiry** — advance the fence/epoch, then wait `lease_until + margin` on A's PG
clock so any in-flight A tx fails its in-tx lease check; or (b) **STONITH / infrastructure
fencing** of A's node. **Promotion MUST refuse to proceed (fail-closed) if it cannot prove A
is fenced** (neither expiry elapsed nor STONITH confirmed). Fault test: A reaches its PG but
not Redis/guard with an in-flight tx → A's lease expires → A self-fences → promotion proceeds
only after proven expiry.

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

### 3.2 Provisioned genesis

Provisioning writes the witness genesis row (`epoch = 0`, `genesis_marker` = a random
provisioning nonce) **and** the Redis fence record for epoch 0. A stream is *provisioned*
iff the witness row exists. This distinguishes **never-provisioned** (no witness) from
**provisioned-then-Redis-lost** (witness present, Redis absent/lower) → the latter is
fail-closed, never re-initialized.

### 3.3 Promotion saga (Redis + 3 PG are NOT atomic — write-ahead intent + resource-fencing order)

Redis and the PGs cannot commit atomically, so the saga uses a **durable, guard-signed
write-ahead INTENT** (H1) as the single authoritative record of an in-flight promotion, then
orders the effects so a partial failure leaves **no writer**. `E' = witness.epoch + 1`. Every
step is idempotent, keyed by `(streamId, E', commandId)`.

0. **(H1) Durable signed intent BEFORE any effect.** Atomically insert a `PREPARING`
   reservation into the **control DB** keyed `(streamId, E')` with `commandId` + a **guard
   signature** — an `INSERT ... ON CONFLICT (streamId, E') DO NOTHING` so two promoters racing
   the same epoch resolve to exactly one reservation (the other must pick `E'+1`). This is the
   first durable action; a crash after any later effect is always recoverable from this
   authenticated intent. Without a committed intent, no fence/claim happens.
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

**H4 — Redis durability under Sentinel async failover.** Sentinel can promote a replica that
lost the last acknowledged fence write, silently rolling the epoch back. To close #10 the
Redis authority must be configured + evidenced: **`appendonly yes` + `appendfsync everysec`
(or always)**, **`min-replicas-to-write` ≥ 1 with a bounded `min-replicas-max-lag`**, and a
**`WAIT`/`WAITAOF` after every fence write** to confirm replication/fsync before the write is
treated as committed. Even so, a rollback remains possible; the **external witness cross-check
(§3.4) quarantines** on `R < W` and forces a **governed reseed**. The design defines the
resulting **write-outage window / RTO** during a Sentinel failover (writes fail-closed until a
quorum-durable fence is re-confirmed). Single Redis (no Sentinel) is **mechanism-only** and
cannot close #10.

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
- **head-chain integrity (Q2 — no over-claim)**: a compact rolling hash + the signed head at
  `N` is **NOT** an independently verifiable `genesis→N` proof. Two honest options; PR2b picks
  ONE and labels it precisely:
  - **(default) dual-signature STATE ATTESTATION**: the manifest carries the source **and**
    guard signatures over `canonicalDigest`; B trusts the attested `N`/head/HOTP because two
    independent keys signed it — **not** a cryptographic replay proof. **Full head + HOTP
    lineage is retained on the source/control DB for audit** so an independent verifier can
    replay `genesis→N` out-of-band.
  - **(optional stronger)** an **incrementally maintained, externally anchored MMR/Merkle
    checkpoint** updated atomically with each append, giving a **bounded inclusion/consistency
    proof** `genesis→N` that B verifies independently. Deferred unless required to close #10.
- **HOTP authoritative state**: per-tumbler high-water counters + a consumed-lineage
  **attestation** digest (same honesty caveat; full lineage retained for audit).
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

### 4.3 C, N, tail — corrected old-epoch handling (blocker 1, precision fix 1)

- **C** = B's receiver-**applied** checkpoint (what B already applied as a receiver).
- **N** = the frozen final source head (A fenced before the snapshot → nothing after the fence).
- **tail** = `C+1 .. N`.
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
  phase            text        NOT NULL,            -- PREPARING|FENCED|IMPORTING|READY|ACTIVE
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
- **READY → ACTIVE — atomic with the first origination (H6)**: B's first source mutation
  (append `seq N+1`, chained from N through the epoch boundary, requiring the capability) **and**
  the signed `ACTIVE` transition commit in **ONE SERIALIZABLE tx**. So a crash can never leave a
  committed `N+1` while the phase still reads `READY` (which would look un-promoted). Equivalent
  safe form: a durable pending-origination record reconciled idempotently — never two sources.

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
  - To claim **RPO = 0 even under source-storage loss**, the write path must add a
    **synchronous durable receipt**: a source mutation ACKs the client only after it has
    synchronously reached an **independent durable quorum / third journal** (e.g. the receiver
    or the control DB) — a latency trade-off, offered as an optional **synchronous-durability
    mode**, not the default.
- **RTO — reported per fault** = wall-clock from the fault/promote trigger to the new authority
  being **writable** (originating `N+1` under `E'`) **and** converged to `N`; includes the H2
  lease-expiry wait and the H4 Redis failover write-outage window.

### 5.7 To close #10

PR2c green **including** real 3-node Redis Sentinel/quorum with configured
persistence/replication and demonstrated **failover + rollback** evidence, measured RPO/RTO.

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
| H6 | crash between READY and first N+1 origination | 2c | atomic ACTIVE+append: never committed N+1 while phase=READY |

## 7. Resolved answers + remaining choices

- **Q1 (resolved):** witness/control DB is a **fixed third failure domain**, never node A or B (§1).
- **Q2 (resolved):** the manifest is **dual-signature state attestation with full lineage
  retained for audit** by default; a real MMR/Merkle `genesis→N` proof is an optional stronger
  upgrade (§4.1). No over-claim of "independently verifiable proof."
- **Q3 (resolved):** **PR2a may merge as bounded, mechanism-only** (no split-brain claim) after
  its fencing evidence is green.
- **H1–H7 (folded into the design):** write-ahead signed intent (§3.3), lease-based A fencing
  proof under partition (§1/§3.3), per-fault RPO incl. synchronous-durability mode (§5.6),
  Redis Sentinel AOF/min-replicas/WAIT + witness quarantine (§3.4), per-transition signed
  forward-CAS cutover (§5.1), atomic READY→ACTIVE+N+1 (§5.2), manifest key
  custody/rotation/revocation/schema-attestation/limits (§4.1).

### Remaining choices for Codex
1. **Fencing model for A (H2):** wait-for-lease-expiry (pure software, adds RTO = lease TTL) vs
   require STONITH/infrastructure fencing (faster, needs infra). Propose: **support both**;
   the drill uses lease-expiry (deterministic, no infra), STONITH documented as the production
   option. Confirm.
2. **RPO target for #10:** accept per-fault RPO (0 for recoverable, tail for source-storage
   loss) as the honest closure, or **require the synchronous-durability mode** (RPO=0 under
   storage loss, with the latency cost) to close #10?
3. **Manifest proof (Q2):** dual-signature attestation + audit lineage sufficient for #10, or
   require the MMR/Merkle independent proof?
