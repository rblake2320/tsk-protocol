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

## 1. Failure domains (must be distinct)

| Role | Component | Responsibility |
|---|---|---|
| Promotion **claim coordinator** | Redis (`RedisFencingStore`) | fast cross-node serialization of *who may promote*; NOT the write authority |
| Source **write authority** | per-node **PG** `tsk_outbox_fence` row | the fence token checked **inside every SERIALIZABLE authority mutation** |
| **External monotonic epoch witness** | **PG authority row** in a domain **distinct from Redis** (`tsk_ha_epoch_witness`) | the durable monotonic floor of the highest-ever-promoted epoch + provisioned genesis |

Redis and the witness must not share a failure domain, so Redis loss is detectable
against the witness. (Proposal: the witness lives on the **authority PG** — e.g. node-A /
a dedicated authority DB — separate from the Redis host. Confirm.)

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

### 3.3 Promotion saga (Redis + 2 PG are NOT atomic — resource-fencing order)

`E' = witness.epoch + 1`. Steps, each a durable idempotent action keyed by `(streamId, E', commandId)`:

1. **Allocate `E'` from the witness** (read `witness.epoch = W`; require the stream is
   provisioned; require Redis is not lost per §3.4; set target `E' = W + 1`). No mutation yet.
2. **Advance the OLD-A PG fence row FIRST** — atomically set `tsk_outbox_fence.fence_token`
   for the (old source) authority to the `E'` token in one SERIALIZABLE tx. From this instant,
   **every in-flight or new A mutation re-reads the fence `FOR UPDATE` inside its own
   SERIALIZABLE tx and loses** (token mismatch → `StaleFenceError`). This closes A's
   check-to-commit TOCTOU *before* any coordinator claim.
3. **Claim `E'` in Redis** (CAS: accept only if `R < E'`).
4. **Advance the witness** to `E'` (monotonic, `FOR UPDATE`, forward-only).
5. **Advance B's PG fence + begin import** (PR2b/PR2c).

**Partial-failure ⇒ NO writer, idempotent resume.** A crash after any step leaves the
stream with old A fenced (step 2) and B not yet ready — safe. Resume **rehydrates the
exact current state** (no new claim, §5.4): re-read witness/Redis/PG-fence, validate they
are consistent with `(E', commandId)`, and continue the remaining steps idempotently.

### 3.4 Redis-loss fail-closed (blocker 3)

On any claim/promotion path, cross-check Redis `R` against the witness `W`:
- witness absent → **not provisioned** (must provision, not promote);
- Redis absent, OR `R < W` → the Redis authority was **lost or rolled back** →
  **QUARANTINE / fail-closed**: deny promotion and deny writes; require a **governed reseed**
  (an explicit, audited operation that re-establishes Redis from the witness floor). **Never
  re-initialize the epoch from an empty/stale Redis, and never bump the epoch gratuitously.**
- **Lost CAS response** (Redis ack lost): the claim is ambiguous → reconcile by re-reading
  Redis+witness; the claim is idempotent by `(nodeId, E', commandId)`; never assume success.

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
- **head-chain history proof**: bounded — the head chain is already hash-linked
  `genesis → N`; the proof is the **signed head at N + a compact accumulator** (rolling hash
  of the chain) so attest verifies continuity without an O(N) payload
- **HOTP authoritative state**: per-tumbler high-water counters + consumed-lineage digest
  (bounded per-tumbler, not per-event)
- `fenceToken` / `epoch`
- `canonicalDigest` = sha256 over the canonicalized manifest
- **signatures**: source signature **and** guard signature over `canonicalDigest`; `keyId`s; `alg`
- explicit **bounded size** limit (reject oversize / O(N) manifests)

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

### 5.1 Cutover state (durable, signed)

```
CREATE TABLE tsk_ha_cutover (
  stream_id   text PRIMARY KEY,
  epoch       bigint      NOT NULL,   -- target E'
  command_id  text        NOT NULL,   -- guard command id (idempotency)
  phase       text        NOT NULL,   -- IDLE|FENCED|IMPORTING|READY|ACTIVE
  manifest_digest text,               -- bound once import attested
  signature   text        NOT NULL,   -- signed cutover state (guard) — tamper-evident
  updated_at  timestamptz NOT NULL DEFAULT now()
);
```

### 5.2 States & transitions (forward-only, idempotent, each a durable tx)

- **IDLE → FENCED**: run the saga §3.3 steps 1–4 (witness allocate → **advance OLD-A fence
  first** → Redis claim → advance witness); persist `phase=FENCED` + `command_id` + signature.
  Old A is now fenced; **B is not writable**.
- **FENCED → IMPORTING → READY**: import + attest §4 (advance B fence, import tail `C+1..N`,
  commit the signed epoch-transition boundary only after B reaches N); on success **mint the
  unforgeable source-readiness capability** (module-private mint, WeakMap-bound to
  `manifest_digest` + `E'`, same pattern as `SchemaReadyToken`); persist `phase=READY`.
- **READY → ACTIVE**: B originates `seq N+1` with a signed head chained from N through the
  epoch-transition boundary; **requires the capability**; persist `phase=ACTIVE`.

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
- **data-loss RPO** = records durably committed on the old authority but not applied/imported
  on the new authority at the cutover instant; **target 0** (durable outbox + attested import +
  tail `C+1..N`); proven post-convergence (every committed seq applied exactly once on the
  promoted authority).
- **RTO** = wall-clock from the fault/promote trigger to the new authority being **writable**
  (originating `N+1` under `E'`) **and** the stream converged to `N`.

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

## 7. Open questions

1. Confirm the epoch witness lives on the authority PG (distinct failure domain from Redis) —
   proposal in §1.
2. Confirm the bounded head-chain history proof form (signed head at N + compact rolling
   accumulator) is acceptable.
3. Confirm PR2a merges on its fencing evidence alone (no split-brain claim) before PR2b/PR2c.
