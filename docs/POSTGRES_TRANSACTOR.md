# Production PostgreSQL Transaction Adapter (#10)

`NodePostgresTransactor` is the production `pg`-pool adapter for the TSK durable
HOTP-outbox `PgTransactor` contract. It runs each unit of work in exactly one
`SERIALIZABLE` transaction, installs and verifies a server-side statement timeout,
verifies the `BEGIN` and `COMMIT` command tags, bounds the whole transaction with a
client-side deadline that does not require a caller signal, and destroys failed or
timed-out connections instead of returning them to the pool.

It depends only on the structural `NodePostgresPool` / `NodePostgresClient` /
`NodePostgresResult` interfaces, so `pg` never enters the `@tsk/server` runtime
dependency closure — a real `pg.Pool` / `PoolClient` satisfies them and is injected
by the application.

## Outcome contract

The caller must be able to tell three failure shapes apart:

- An error **before `COMMIT` is dispatched** is a definite transaction failure — the
  work rolled back.
- An explicit PostgreSQL `ROLLBACK` command tag **after `COMMIT`** is a definite
  abort. A missing, malformed, or otherwise unexpected tag is ambiguous.
- **`AmbiguousCommitError`** (`committed === "unknown"`) means `COMMIT` was dispatched
  but its response was lost (abort or socket death after dispatch). Do **not** blindly
  retry. Reconcile against authoritative state by idempotency key first — for the TSK
  outbox, the `(streamId, sourceEpoch, sequence, opDigest)` row on `tsk_outbox_rows`,
  the receiver checkpoint sequence + head chain, and `tsk_hotp_consumed.last_counter`.
- **`PostCommitReleaseError`** (`committed === true`) means PostgreSQL confirmed the
  commit, but returning the client to the pool failed. The data is durable; only pool
  hygiene degraded.
- **`ConnectionDisposalError`** (`committed === false`) means the transaction failed
  and the connection could not be disposed.

## Durability preconditions

A "confirmed COMMIT is durable" claim only holds under a durable configuration, which
the transactor enforces per transaction:

- `synchronousCommit` is forced tx-locally and read back before COMMIT. Accepted values
  are `on` (default), `local`, `remote_write`, `remote_apply`. **`off` is rejected** — it
  does not wait for the local WAL flush, so a confirmed COMMIT would not be durable.
- `fsync = on` and `full_page_writes = on` are verified on the exact transaction
  connection — both BEFORE any work and again immediately before COMMIT (both are
  SIGHUP-reloadable, so a mid-transaction reload is a TOCTOU that would otherwise leave
  the commit non-durable or unsafe on torn-page crash recovery). A mismatch fails closed.
- `remote_write` / `remote_apply` do **not** by themselves establish standby durability:
  they only matter when `synchronous_standby_names` configures synchronous standbys.
  Absent that, they behave like `on` for local durability.

This is single-node local durability. Cross-node/HA durability (#10) remains OPEN until
the two-node PostgreSQL failover / split-brain drill records measured RPO and RTO.

Serialization / deadlock (`40001` / `40P01`) retries are **disabled by default**
because a transaction callback can contain non-database side effects that cannot be
safely replayed. Enable bounded retries (`maxSerializationRetries`) only for callbacks
that are replay-safe — the TSK outbox append/publish callbacks are, because redelivery
is `duplicate-ok` and the HOTP counter is consumed exactly once.

## Checked-out connection ownership

While a client is checked out, `pg` removes its own `'error'` listener and makes the
borrower responsible: an unlistened mid-transaction connection death would crash the
process. The transactor attaches (and later releases) an `'error'` listener for the
checked-out lifetime; the authoritative failure still surfaces through the in-flight
query rejection.

## Deployment boundary

Configure the `pg.Pool` with TLS, bounded connection and socket timeouts, and
least-privilege runtime credentials. The runtime role must **not** hold DDL rights;
schema provisioning and attestation run under a separate startup/migration identity.
Use `onDisposalError` to feed connection-disposal faults to operational telemetry.

**This adapter and the single-node PostgreSQL integration do not prove high
availability.** Issue #10 remains OPEN until the real two-node PostgreSQL failover /
split-brain drill records measured RPO and RTO. Redis is out of scope for this slice.

## Evidence

- `npm run test:pg-transactor -w packages/server` — hermetic driver-fake unit suite
  (commit/rollback/discard, unconfirmed-commit fail-closed, ambiguity classification,
  acquire bound, abort, retry policy, listener ownership, config validation).
- `npm run test:postgres:ha` — the full durable-outbox adversarial suite, now run
  **through** `NodePostgresTransactor` against a live PostgreSQL.
- `npm run test:pg-partition` — a **deterministic** real-network partition drill. A TCP
  fault proxy injects faults by matching PostgreSQL wire-protocol state (never timing):
  a work-phase cut rolls back with no partial commit; a COMMIT-window cut — dropped
  only **after** the server's `CommandComplete('COMMIT')` is observed on the wire —
  yields `AmbiguousCommitError` and is reconciled by idempotency key to prove
  exactly-once; an acquire-phase stall is bounded by the acquire deadline.
