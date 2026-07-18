/**
 * PostgreSQL durable HOTP-outbox implementation for TSK (#10).
 *
 * Concrete implementation of the merged `ha-outbox-contract.ts` TSK extension:
 * an ordered, crash-durable outbox whose records carry a tumbler HOTP mutation
 * (tumblerId, strictly-increasing counter) AND a SIGNED, HASH-LINKED stream head
 * (prevHeadDigest → opDigest chain, signed per keyId/alg). The receiver applies
 * a record ONLY through `verifyAndApplyTumblerInTx`, which in ONE serializable
 * transaction: re-sanitizes + recomputes the op digest, binds + VERIFIES the
 * signed stream head, checks the head hash-chain continuity, validates the
 * record-bound fence token against the persisted authoritative token, enforces
 * in-order delivery, CONSUMES the HOTP counter EXACTLY ONCE (rejects any replay/
 * double-consume), applies, and advances the checkpoint + head + applied-history.
 *
 * Structural patterns (schema attestation + unforgeable readiness capability +
 * capability-scoped, deadline/abort-bounded transactions + per-stream ordered
 * single-active publisher lease + fencing/quarantine) are re-derived from the
 * hardened BPC #16 mechanism; the TSK INVARIANTS (signed head chain, HOTP
 * exactly-once) are implemented against this contract, not copied.
 *
 * BOUNDARY: this is the single-node mechanism + adversarial evidence. It makes NO
 * crash-durable-HA claim; #10 stays OPEN until a real two-node PostgreSQL(+Redis)
 * failover/split-brain drill passes with recorded RPO/RTO.
 */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  ContractValidationError,
  OutboxBackpressureError,
  StaleFenceError,
  assertHeaderConformant,
  assertStreamHeadBinds,
  canonicalOpDigest,
  fenceTokenToDecimal,
  streamHeadDigest,
  type DurableTx,
  type EpochTransitionAuthorizer,
  type FenceToken,
  type HotpMutationSanitizer,
  type OutboxRecord,
  type OutboxRecordHeader,
  type PublisherBackpressure,
  type ReceiverDecision,
  type SanitizedMutation,
  type SignedStreamHead,
  type StreamHeadAlg,
  type StreamHeadVerifier,
  type TskHotpMutation,
  type TskReceiverCheckpoint,
} from './ha-outbox-contract.js';

/** Contract HOTP counter bound (mirrors the TSK segment counter ceiling). */
export const TSK_HOTP_MAX_COUNTER = 2_147_483_647;

/**
 * The ONLY `StreamHeadVerifier` error that is RETRYABLE: a transient verification
 * DEPENDENCY (key store / HSM / network) is unavailable. Every other throw from a
 * verifier — an invalid signature, an unknown key/alg, OR an unexpected/unknown
 * exception — is treated as a PERMANENT reject-fork (fail-closed). Verification
 * failures therefore can never be turned into an attacker-controlled retry loop:
 * only an explicitly-typed unavailability defers; ambiguity fails closed.
 */
export class StreamHeadVerificationUnavailableError extends Error {
  constructor(message = 'stream-head verifier dependency unavailable') {
    super(message);
    this.name = 'StreamHeadVerificationUnavailableError';
  }
}

// ── Backend brand + transaction primitives (re-derived from the hardened core) ──

export interface TskPgBackend { readonly __tskHaOutbox: unique symbol }
export type PgTx = DurableTx<TskPgBackend>;

/** A transaction-scoped executor; `rowCount` is REQUIRED so write effects can be
 *  asserted (a silent 0-row write is a fault, not a no-op). */
export interface PgExecutor {
  query(sql: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number }>;
}

/**
 * Runs `fn` inside ONE SERIALIZABLE transaction. A conforming transactor MUST:
 * bound queries at the connection layer (statement/socket timeout); VERIFY the
 * COMMIT command tag (an aborted tx silently turns COMMIT into ROLLBACK); HONOR
 * `opts.signal` (on abort, cancel the in-flight query and destroy the connection
 * promptly, without unbounded-awaiting ROLLBACK); and DISCARD any connection
 * whose tx errored/timed-out/failed-commit. This slice ships the contract +
 * signal + a conforming test transactor, not a production driver.
 */
export interface PgTransactor {
  transaction<T>(fn: (exec: PgExecutor) => Promise<T>, opts?: { signal?: AbortSignal }): Promise<T>;
}

// Bound-tx state: executor + identity of the transactor+schema that produced it,
// held module-privately. Only transactor-owning methods mint a bound tx (via
// withBoundTx), so the recorded db is always the one that produced `exec`.
interface BoundTxState { db: PgTransactor; schema: string; scoped: PgExecutor }
const TX_STATE = new WeakMap<object, BoundTxState>();

function boundStateOf(tx: PgTx): BoundTxState {
  const st = TX_STATE.get(tx as unknown as object);
  if (!st) throw new ContractValidationError('DurableTx not bound to a PostgreSQL transaction (forged, foreign, or used after its scope)');
  return st;
}

/** Return a CAPABILITY-SCOPED executor of a bound tx ONLY if produced by THIS
 *  object's exact transactor + schema. The proxy re-checks liveness on EVERY
 *  query; a foreign/stale tx is rejected before any query. */
function execOfBound(tx: PgTx, db: PgTransactor, schema: string): PgExecutor {
  const st = boundStateOf(tx);
  if (st.db !== db) throw new ContractValidationError('DurableTx is bound to a different transactor than this object');
  if (st.schema !== schema) throw new ContractValidationError('DurableTx is bound to a different schema than this object');
  return st.scoped;
}

function digestEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function safeSeq(v: unknown, label: string): number {
  let b: bigint;
  try { b = BigInt(String(v)); }
  catch { throw new ContractValidationError(`${label} is not an integer: ${String(v)}`); }
  if (b < 0n || b > BigInt(Number.MAX_SAFE_INTEGER)) throw new ContractValidationError(`${label} out of safe-integer range: ${b.toString()}`);
  return Number(b);
}

function affectedOne(res: { rowCount: number }, label: string): void {
  if (res.rowCount !== 1) throw new ContractValidationError(`${label}: expected exactly 1 affected row, got ${res.rowCount}`);
}

// ── (TOCTOU) immutable canonical snapshots of UNTRUSTED, caller-owned objects ──
// A verified digest/signature is meaningless if the object it covers can be
// mutated across a later `await`. Every method that verifies-then-uses an object
// takes a deep-cloned, field-restricted, DEEP-FROZEN snapshot SYNCHRONOUSLY at
// entry (before its first await) and uses ONLY the snapshot afterward.

function deepFreeze<T>(o: T): T {
  if (o && typeof o === 'object') { for (const v of Object.values(o as Record<string, unknown>)) deepFreeze(v); Object.freeze(o); }
  return o;
}
/**
 * (MED) STRICT structural gate for an untrusted object: it MUST present a plain
 * (Object.prototype or null) prototype, EXACTLY the expected own-enumerable DATA
 * keys (no missing/extra), no symbol keys, and no accessor (get/set) descriptors.
 * This blocks laundering an inherited value, an accessor that changes across
 * reads, or extra symbol/non-enumerable shape past the snapshot.
 *
 * NOTE ON PROXIES: this does NOT reject a transparent Proxy — a Proxy that
 * faithfully forwards getPrototypeOf/ownKeys/getOwnPropertyDescriptor over an
 * exact plain target passes every check here, by design. Rejection is not the
 * safety property; STABILITY is. Each field's descriptor `value` is read ONCE via
 * getOwnPropertyDescriptor and copied out synchronously (and the caller deep-
 * freezes the result) BEFORE any await, so a Proxy — or a later mutation of the
 * target — cannot change what was validated, applied, consumed, or persisted. The
 * accessor ban is what makes that single synchronous read authoritative: a data
 * descriptor cannot re-run trap logic on read. Returns the copied own-data values.
 */
function assertPlainData(o: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (o === null || typeof o !== 'object') throw new ContractValidationError(`${label} must be a plain object`);
  const proto = Object.getPrototypeOf(o);
  if (proto !== Object.prototype && proto !== null) throw new ContractValidationError(`${label} must have a plain (Object) or null prototype`);
  const own = Reflect.ownKeys(o);
  if (own.some((k) => typeof k === 'symbol')) throw new ContractValidationError(`${label} must not have symbol keys`);
  if (own.length !== keys.length) throw new ContractValidationError(`${label} has an invalid key set`);
  const values: Record<string, unknown> = {};
  for (const k of keys) {
    const d = Object.getOwnPropertyDescriptor(o, k);
    if (!d || !d.enumerable || typeof d.get === 'function' || typeof d.set === 'function' || !('value' in d)) {
      throw new ContractValidationError(`${label}.${k} must be an own enumerable data property`);
    }
    values[k] = d.value;
  }
  return values;
}
function reqString(v: unknown, label: string): string { if (typeof v !== 'string') throw new ContractValidationError(`${label} must be a string`); return v; }
function reqInt(v: unknown, label: string): number { if (typeof v !== 'number' || !Number.isInteger(v)) throw new ContractValidationError(`${label} must be an integer`); return v; }

const RECORD_KEYS = ['contractVersion', 'streamId', 'sourceEpoch', 'sequence', 'fenceToken', 'opDigest', 'mutation'] as const;
const MUTATION_KEYS = ['tumblerId', 'counter'] as const;
const HEAD_KEYS = ['streamId', 'sequence', 'prevHeadDigest', 'opDigest', 'keyId', 'alg', 'headDigest', 'signature'] as const;
const RECEIPT_KEYS = ['streamId', 'sourceEpoch', 'sequence', 'opDigest', 'decision', 'receiverId', 'keyId', 'issuedAt', 'signature'] as const;

/** Frozen, strictly-validated snapshot of an OutboxRecord (plain data only). */
function snapshotRecord(r: OutboxRecord<TskHotpMutation>): OutboxRecord<TskHotpMutation> {
  const v = assertPlainData(r, RECORD_KEYS, 'record');
  const m = assertPlainData(v.mutation, MUTATION_KEYS, 'record.mutation');
  return deepFreeze({
    contractVersion: reqString(v.contractVersion, 'record.contractVersion'),
    streamId: reqString(v.streamId, 'record.streamId'),
    sourceEpoch: reqString(v.sourceEpoch, 'record.sourceEpoch'),
    sequence: reqInt(v.sequence, 'record.sequence'),
    fenceToken: reqString(v.fenceToken, 'record.fenceToken'),
    opDigest: reqString(v.opDigest, 'record.opDigest'),
    mutation: { tumblerId: reqString(m.tumblerId, 'record.mutation.tumblerId'), counter: reqInt(m.counter, 'record.mutation.counter') } as SanitizedMutation<TskHotpMutation>,
  }) as OutboxRecord<TskHotpMutation>;
}
function snapshotHead(h: SignedStreamHead): SignedStreamHead {
  const v = assertPlainData(h, HEAD_KEYS, 'head');
  return deepFreeze({
    streamId: reqString(v.streamId, 'head.streamId'), sequence: reqInt(v.sequence, 'head.sequence'),
    prevHeadDigest: reqString(v.prevHeadDigest, 'head.prevHeadDigest'), opDigest: reqString(v.opDigest, 'head.opDigest'),
    keyId: reqString(v.keyId, 'head.keyId'), alg: reqString(v.alg, 'head.alg') as StreamHeadAlg,
    headDigest: reqString(v.headDigest, 'head.headDigest'), signature: reqString(v.signature, 'head.signature'),
  }) as SignedStreamHead;
}
function snapshotAckReceipt(r: TskAckReceipt): TskAckReceipt {
  const v = assertPlainData(r, RECEIPT_KEYS, 'ack receipt');
  return deepFreeze({
    streamId: reqString(v.streamId, 'receipt.streamId'), sourceEpoch: reqString(v.sourceEpoch, 'receipt.sourceEpoch'),
    sequence: reqInt(v.sequence, 'receipt.sequence'), opDigest: reqString(v.opDigest, 'receipt.opDigest'),
    decision: reqString(v.decision, 'receipt.decision') as ReceiverDecision, receiverId: reqString(v.receiverId, 'receipt.receiverId'),
    keyId: reqString(v.keyId, 'receipt.keyId'), issuedAt: reqString(v.issuedAt, 'receipt.issuedAt'), signature: reqString(v.signature, 'receipt.signature'),
  }) as TskAckReceipt;
}

async function assertSerializable(exec: PgExecutor): Promise<void> {
  const rows = (await exec.query('SHOW transaction_isolation')).rows;
  const level = String(rows[0]?.transaction_isolation ?? '').toLowerCase();
  if (level !== 'serializable') throw new ContractValidationError(`critical tx requires SERIALIZABLE isolation; got '${level}'`);
}

/** (MED) NARROWED to lowercase unquoted-identifier chars only, so it matches
 *  both current_schema() (PostgreSQL folds unquoted identifiers to lowercase) AND
 *  the manifest index-def schema-strip (`\w+`) — no `$`/uppercase mismatch. */
function assertSchemaIdentifier(schema: string): void {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) throw new ContractValidationError(`invalid schema identifier (lowercase unquoted only): ${schema}`);
}

/** PIN the schema for THIS tx: SET LOCAL search_path (parameterized) then assert
 *  current_schema() is exactly the configured schema, so pooled-connection default
 *  search_path cannot land operations in another schema. */
async function pinSchema(exec: PgExecutor, schema: string): Promise<void> {
  assertSchemaIdentifier(schema);
  await exec.query('SELECT set_config($1, $2, true)', ['search_path', schema]);
  const cur = (await exec.query('SELECT current_schema() AS s')).rows[0]?.s;
  if (cur !== schema) throw new ContractValidationError(`schema context mismatch: current_schema=${String(cur)} pinned=${schema}`);
}

async function enterCriticalTx(exec: PgExecutor, schema: string): Promise<void> {
  await assertSerializable(exec);
  await pinSchema(exec, schema);
}

const DEFAULT_SCOPE_DEADLINE_MS = 30_000;
const MAX_TIMER_MS = 2_147_483_647;
function validateDeadlineMs(ms: number, label: string): number {
  if (!Number.isInteger(ms) || ms < 1 || ms > MAX_TIMER_MS) throw new ContractValidationError(`${label} must be an integer in [1, ${MAX_TIMER_MS}] ms`);
  return ms;
}

/** Run `run(signal)` under a bounded deadline; on timeout, abort the signal (so a
 *  conforming transactor cancels + destroys the connection) AND reject promptly.
 *  End-to-end availability under a hung connection depends on the transactor
 *  honoring the signal — a documented OPEN boundary (#10), not a closed guarantee. */
function runScoped<T>(ms: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const err = new ContractValidationError(`transaction scope deadline exceeded (${ms}ms) — aborting; the transactor must cancel the in-flight query and discard this connection`);
      controller.abort(err);
      reject(err);
    }, ms);
  });
  const p = run(controller.signal);
  p.catch(() => {});
  return Promise.race([p, deadline]).finally(() => clearTimeout(timer));
}

/** Structured, capability-scoped bound-tx: never exposes the raw executor; the
 *  proxy rejects a query once the scope is closing/revoked; every launched query
 *  is retained (a fast rejection cannot vanish); an unawaited in-flight query at
 *  close forces a rollback. Timing is bounded by the outer runScoped deadline. */
async function withBoundTx<T>(exec: PgExecutor, db: PgTransactor, schema: string, body: (tx: PgTx, scoped: PgExecutor) => Promise<T>): Promise<T> {
  const tx = Object.freeze({}) as unknown as PgTx;
  let closing = false;
  let rejectionSeen = false;
  let firstRejection: unknown;
  let pending = 0;
  const settlements: Promise<void>[] = [];
  const scoped: PgExecutor = {
    query(sql, params) {
      if (closing || !TX_STATE.has(tx as unknown as object)) throw new ContractValidationError('DurableTx query issued outside its active transaction scope');
      pending++;
      const p = exec.query(sql, params);
      settlements.push(p.then(() => { pending--; }, (err) => { pending--; if (!rejectionSeen) { rejectionSeen = true; firstRejection = err; } }));
      return p;
    },
  };
  TX_STATE.set(tx as unknown as object, { db, schema, scoped });
  try {
    const result = await body(tx, scoped);
    closing = true;
    const hadUnawaitedInFlight = pending > 0;
    await Promise.allSettled(settlements);
    if (rejectionSeen) throw new ContractValidationError(`a query launched in this DurableTx scope rejected — rolling back: ${String((firstRejection as { message?: string })?.message ?? firstRejection)}`);
    if (hadUnawaitedInFlight) throw new ContractValidationError('DurableTx scope ended with unawaited in-flight queries — rolling back');
    return result;
  } finally {
    closing = true;
    TX_STATE.delete(tx as unknown as object);
  }
}

// ── Schema version + DDL ────────────────────────────────────────────────────

export const TSK_OUTBOX_SCHEMA_VERSION = 1 as const;
const FENCE_MAX_EXCLUSIVE = '1e39';

/**
 * DDL. Distinct source/receiver checkpoints; per-stream publisher lease; row
 * carries BOTH the HOTP mutation and the signed stream-head fields; a per-stream
 * head chain (last applied headDigest); a per-tumbler HOTP-consumed high-water
 * mark for exactly-once. Every column has a CHECK so a malformed row cannot
 * persist. The DDL NEVER stamps the version; only provision/adopt stamp, after a
 * full manifest attestation.
 */
export const TSK_OUTBOX_PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS tsk_outbox_meta (
  id             integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  schema_version integer NOT NULL CHECK (schema_version >= 1)
);
CREATE TABLE IF NOT EXISTS tsk_outbox_fence (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  fence_token   numeric NOT NULL DEFAULT 0 CHECK (fence_token >= 0 AND scale(fence_token) = 0 AND fence_token < ${FENCE_MAX_EXCLUSIVE})
);
CREATE TABLE IF NOT EXISTS tsk_outbox_source_checkpoint (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  epoch_index   bigint NOT NULL DEFAULT 0 CHECK (epoch_index >= 0),
  sequence      bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0 AND sequence <= 9007199254740991),
  head_digest   text NOT NULL DEFAULT '' CHECK (head_digest = '' OR head_digest ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS tsk_outbox_receiver_checkpoint (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  epoch_index   bigint NOT NULL DEFAULT 0 CHECK (epoch_index >= 0),
  sequence      bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0 AND sequence <= 9007199254740991),
  head_digest   text NOT NULL DEFAULT '' CHECK (head_digest = '' OR head_digest ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS tsk_outbox_rows (
  stream_id     text NOT NULL CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  sequence      bigint NOT NULL CHECK (sequence >= 1 AND sequence <= 9007199254740991),
  fence_token   numeric NOT NULL CHECK (fence_token >= 0 AND scale(fence_token) = 0 AND fence_token < ${FENCE_MAX_EXCLUSIVE}),
  op_digest     text NOT NULL CHECK (op_digest ~ '^[0-9a-f]{64}$'),
  tumbler_id    text NOT NULL CHECK (length(tumbler_id) BETWEEN 1 AND 512),
  hotp_counter  bigint NOT NULL CHECK (hotp_counter >= 1 AND hotp_counter <= 2147483647),
  mutation      jsonb NOT NULL,
  head_prev     text NOT NULL CHECK (head_prev ~ '^[0-9a-f]{64}$'),
  head_digest   text NOT NULL CHECK (head_digest ~ '^[0-9a-f]{64}$'),
  head_key_id   text NOT NULL CHECK (length(head_key_id) BETWEEN 1 AND 128),
  head_alg      text NOT NULL CHECK (head_alg IN ('ed25519','ecdsa-p256-sha256')),
  head_sig      text NOT NULL CHECK (length(head_sig) BETWEEN 1 AND 4096),
  published_at  timestamptz,
  acked_at      timestamptz,
  quarantined_at timestamptz,
  PRIMARY KEY (stream_id, source_epoch, sequence)
);
CREATE INDEX IF NOT EXISTS tsk_outbox_rows_deliverable
  ON tsk_outbox_rows (stream_id, sequence) WHERE acked_at IS NULL AND quarantined_at IS NULL;
CREATE TABLE IF NOT EXISTS tsk_outbox_publisher_lease (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  lease_token   text,
  lease_until   timestamptz
);
CREATE TABLE IF NOT EXISTS tsk_outbox_quarantine (
  stream_id     text NOT NULL CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  sequence      bigint NOT NULL CHECK (sequence >= 1 AND sequence <= 9007199254740991),
  op_digest     text NOT NULL CHECK (op_digest ~ '^[0-9a-f]{64}$'),
  decision      text NOT NULL,
  quarantined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, source_epoch, sequence)
);
CREATE TABLE IF NOT EXISTS tsk_outbox_applied (
  stream_id     text NOT NULL CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  sequence      bigint NOT NULL CHECK (sequence >= 1 AND sequence <= 9007199254740991),
  op_digest     text NOT NULL CHECK (op_digest ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (stream_id, source_epoch, sequence)
);
-- Per-tumbler HOTP high-water mark: the receiver consumes a counter EXACTLY ONCE
-- by advancing this monotonically. A counter at or below last_counter is a replay.
CREATE TABLE IF NOT EXISTS tsk_hotp_consumed (
  stream_id     text NOT NULL CHECK (length(stream_id) BETWEEN 1 AND 512),
  tumbler_id    text NOT NULL CHECK (length(tumbler_id) BETWEEN 1 AND 512),
  last_counter  bigint NOT NULL CHECK (last_counter >= 1 AND last_counter <= 2147483647),
  PRIMARY KEY (stream_id, tumbler_id)
);
-- DURABLE stream-halt marker: a terminal (fork/stale/unsanitized/epoch) rejection
-- is a divergence that cannot be auto-recovered. The quarantined sequence stays
-- excluded and the receiver checkpoint cannot advance past it, so every later
-- sequence is a permanent reject-gap. Writing this row in the same tx as the
-- quarantine makes the halt DURABLE + EXPLICIT so the publisher refuses to spin.
-- RECOVERY IS A GOVERNED REPAIR (out of this slice): unquarantine/repair the
-- diverged record and epoch-resync the receiver. Deleting this row ALONE does NOT
-- recover the stream — the reject-gap persists — so no delete-to-recover is offered.
CREATE TABLE IF NOT EXISTS tsk_outbox_stream_halted (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  sequence      bigint NOT NULL CHECK (sequence >= 1 AND sequence <= 9007199254740991),
  op_digest     text NOT NULL CHECK (op_digest ~ '^[0-9a-f]{64}$'),
  decision      text NOT NULL,
  halted_at     timestamptz NOT NULL DEFAULT now()
);
`;

/** Tables in the attestation scope. */
const TSK_OUTBOX_TABLES = [
  'tsk_outbox_meta', 'tsk_outbox_fence', 'tsk_outbox_source_checkpoint',
  'tsk_outbox_receiver_checkpoint', 'tsk_outbox_rows', 'tsk_outbox_publisher_lease',
  'tsk_outbox_quarantine', 'tsk_outbox_applied', 'tsk_hotp_consumed',
  'tsk_outbox_stream_halted',
] as const;

/** Pinned catalog manifest — recompute via schemaManifest() on a PG-major bump.
 *  (Placeholder; the real-PG manifest-pin test asserts and reports the value.) */
export const TSK_OUTBOX_SCHEMA_MANIFEST = 'c1972f05a816b44127b365e138753aeef3afe2ed4f8d53cd1d0070ee46311f0d';

export async function schemaManifest(exec: PgExecutor): Promise<string> {
  const tables = TSK_OUTBOX_TABLES as unknown as string[];
  const cols = (await exec.query(
    `SELECT table_name, ordinal_position, column_name, udt_name, is_nullable, coalesce(column_default, '') AS cd
     FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ANY($1)`, [tables])).rows;
  const cons = (await exec.query(
    `SELECT rel.relname AS t, c.contype, pg_get_constraintdef(c.oid) AS def
     FROM pg_constraint c JOIN pg_class rel ON rel.oid = c.conrelid JOIN pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = current_schema() AND rel.relname = ANY($1) AND c.contype IN ('p','c','u','f')`, [tables])).rows;
  const idx = (await exec.query(
    `SELECT tablename AS t, indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename = ANY($1)`, [tables])).rows;
  const rel = (await exec.query(
    `SELECT rel.relname AS t, rel.relkind, rel.relpersistence, rel.relrowsecurity, rel.relforcerowsecurity
     FROM pg_class rel JOIN pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = current_schema() AND rel.relname = ANY($1)`, [tables])).rows;
  const trig = (await exec.query(
    `SELECT rel.relname AS t, tg.tgname, tg.tgenabled, pg_get_triggerdef(tg.oid) AS def
     FROM pg_trigger tg JOIN pg_class rel ON rel.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = current_schema() AND rel.relname = ANY($1) AND NOT tg.tgisinternal`, [tables])).rows;
  const pol = (await exec.query(
    `SELECT rel.relname AS t, p.polname, p.polcmd,
            coalesce((SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE oid = ANY(p.polroles)), '') AS roles,
            coalesce(pg_get_expr(p.polqual, p.polrelid), '') AS qual,
            coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') AS withcheck
     FROM pg_policy p JOIN pg_class rel ON rel.oid = p.polrelid JOIN pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = current_schema() AND rel.relname = ANY($1)`, [tables])).rows;
  const stripSchema = (s: string) => s.replace(/ ON \w+\./, ' ON ');
  const parts: string[] = [];
  for (const r of cols) parts.push(`COL|${r.table_name}|${r.ordinal_position}|${r.column_name}|${r.udt_name}|${r.is_nullable}|${r.cd}`);
  for (const r of cons) parts.push(`CON|${r.t}|${r.contype}|${r.def}`);
  for (const r of idx) parts.push(`IDX|${r.t}|${r.indexname}|${stripSchema(String(r.indexdef))}`);
  for (const r of rel) parts.push(`REL|${r.t}|${r.relkind}|${r.relpersistence}|${r.relrowsecurity}|${r.relforcerowsecurity}`);
  for (const r of trig) parts.push(`TRG|${r.t}|${r.tgname}|${r.tgenabled}|${stripSchema(String(r.def))}`);
  for (const r of pol) parts.push(`POL|${r.t}|${r.polname}|${r.polcmd}|${r.roles}|${r.qual}|${r.withcheck}`);
  parts.sort();
  return createHash('sha256').update(parts.join('\n'), 'utf8').digest('hex');
}

export async function attestSchema(exec: PgExecutor): Promise<void> {
  const found = await schemaManifest(exec);
  if (!digestEquals(found, TSK_OUTBOX_SCHEMA_MANIFEST)) {
    throw new ContractValidationError('tsk_outbox schema attestation failed: live catalog does not match the expected manifest');
  }
}

// ── Unforgeable readiness capability ────────────────────────────────────────

const READY_BRAND = Symbol('tsk_outbox_schema_ready');
export interface SchemaReadyToken { readonly [READY_BRAND]: true }
interface ReadyState { db: PgTransactor; schema: string; manifest: string; version: number }
const READY_STATE = new WeakMap<object, ReadyState>();

function mintReadyToken(state: ReadyState): SchemaReadyToken {
  const token = Object.freeze({ [READY_BRAND]: true as const });
  READY_STATE.set(token, state);
  return token as SchemaReadyToken;
}
function requireReady(token: SchemaReadyToken, db?: PgTransactor): string {
  const st = READY_STATE.get(token as unknown as object);
  if (!st) throw new ContractValidationError('invalid schema-readiness capability (forged or foreign token)');
  if (db !== undefined && st.db !== db) throw new ContractValidationError('schema-readiness token is bound to a different PgTransactor');
  if (st.manifest !== TSK_OUTBOX_SCHEMA_MANIFEST || st.version !== TSK_OUTBOX_SCHEMA_VERSION) throw new ContractValidationError('schema-readiness token attests a different manifest/version');
  return st.schema;
}
// (R2/HIGH) There is NO test-only mint helper: it would ship in dist and permit
// unattested construction via a deep import. Tests obtain a token the same way
// production does — via `assertSchemaReady`/`provisionSchemaVersion` — using a fake
// transactor that replays a real catalog fixture so attestation genuinely runs.
// `mintReadyToken` stays module-private (never exported).

async function assertVersionInTx(exec: PgExecutor): Promise<void> {
  const rows = (await exec.query('SELECT schema_version FROM tsk_outbox_meta WHERE id = 1')).rows;
  if (!rows.length) throw new ContractValidationError('tsk_outbox schema is not provisioned (no meta row)');
  const found = safeSeq(rows[0].schema_version, 'schema_version');
  if (found !== TSK_OUTBOX_SCHEMA_VERSION) throw new ContractValidationError(`tsk_outbox schema version mismatch: db=${found} expected=${TSK_OUTBOX_SCHEMA_VERSION}`);
}

/**
 * RUNTIME READINESS GATE: full manifest attestation + version, in the pinned
 * schema, minting a transactor+schema-bound unforgeable token.
 *
 * (MED) Readiness is POINT-IN-TIME. The token attests the schema at mint time; it
 * cannot prevent a later DDL change. Preserving it at runtime is a database
 * privilege-separation responsibility: the runtime DB role used by the transactor
 * MUST NOT hold DDL/migration rights (no CREATE/ALTER/DROP/INDEX) on this schema,
 * so the attested structure cannot be mutated under the operating identity.
 * Provisioning/migration run under a SEPARATE privileged role, offline from serving.
 */
export async function assertSchemaReady(db: PgTransactor, schema: string): Promise<SchemaReadyToken> {
  await db.transaction(async (exec) => { await enterCriticalTx(exec, schema); await attestSchema(exec); await assertVersionInTx(exec); });
  return mintReadyToken({ db, schema, manifest: TSK_OUTBOX_SCHEMA_MANIFEST, version: TSK_OUTBOX_SCHEMA_VERSION });
}

/** FRESH provisioning: attest, then stamp with a plain asserted insert; an exact-
 *  current meta row is idempotent, any other existing row is rejected. */
export async function provisionSchemaVersion(db: PgTransactor, schema: string): Promise<SchemaReadyToken> {
  await db.transaction(async (exec) => {
    await enterCriticalTx(exec, schema);
    await attestSchema(exec);
    const rows = (await exec.query('SELECT schema_version FROM tsk_outbox_meta FOR UPDATE')).rows;
    if (rows.length > 1) throw new ContractValidationError('multiple schema-version authority rows');
    if (rows.length === 1) {
      const cur = safeSeq(rows[0].schema_version, 'schema_version');
      if (cur === TSK_OUTBOX_SCHEMA_VERSION) return;
      throw new ContractValidationError(`fresh provisioning refused: meta already at version ${cur}`);
    }
    affectedOne(await exec.query(`INSERT INTO tsk_outbox_meta (id, schema_version) VALUES (1, ${TSK_OUTBOX_SCHEMA_VERSION})`), 'fresh schema provision');
  });
  return mintReadyToken({ db, schema, manifest: TSK_OUTBOX_SCHEMA_MANIFEST, version: TSK_OUTBOX_SCHEMA_VERSION });
}

/** ADOPT the current version for an install whose catalog already matches the
 *  manifest exactly (forward-only; a future version is refused). */
export async function adoptCurrentSchemaVersion(db: PgTransactor, schema: string): Promise<SchemaReadyToken> {
  await db.transaction(async (exec) => {
    await enterCriticalTx(exec, schema);
    await attestSchema(exec);
    const rows = (await exec.query('SELECT schema_version FROM tsk_outbox_meta FOR UPDATE')).rows;
    if (rows.length > 1) throw new ContractValidationError('multiple schema-version authority rows');
    if (rows.length === 1) {
      const cur = safeSeq(rows[0].schema_version, 'schema_version');
      if (cur === TSK_OUTBOX_SCHEMA_VERSION) return;
      if (cur > TSK_OUTBOX_SCHEMA_VERSION) throw new ContractValidationError(`refusing to downgrade schema version ${cur} -> ${TSK_OUTBOX_SCHEMA_VERSION}`);
    }
    affectedOne(await exec.query(`INSERT INTO tsk_outbox_meta (id, schema_version) VALUES (1, ${TSK_OUTBOX_SCHEMA_VERSION}) ON CONFLICT (id) DO UPDATE SET schema_version = EXCLUDED.schema_version`), 'schema version adopt');
  });
  return mintReadyToken({ db, schema, manifest: TSK_OUTBOX_SCHEMA_MANIFEST, version: TSK_OUTBOX_SCHEMA_VERSION });
}

// ── Types: signer, transport, decision-bound receipt, applier ────────────────

export const GENESIS_HEAD = '0'.repeat(64);

/** Source-side signer: identity (keyId/alg) + a detached signature over a head
 *  digest. The head is signed atomically as part of the append. */
export interface StreamHeadSigner {
  readonly keyId: string;
  readonly alg: StreamHeadAlg;
  sign(headDigest: string): Promise<string>;
}

/** Record-bound, decision-carrying acknowledgement (H1 pattern): the source acts
 *  on the SIGNED `decision`, not on receipt-of-a-receipt. */
export interface TskAckReceipt {
  streamId: string; sourceEpoch: string; sequence: number; opDigest: string;
  decision: ReceiverDecision;
  receiverId: string; keyId: string; issuedAt: string; signature: string;
}
/** Verifies a receipt is a genuine, authorized ack of THIS record + decision;
 *  MUST throw on invalid/unauthorized/unavailable — a forged or swapped-decision
 *  receipt is rejected here (fail-closed). */
export interface TskAckReceiptVerifier {
  verify(receipt: TskAckReceipt, record: OutboxRecord<unknown>): Promise<void>;
}
/** Delivers a record + its signed head and returns the receiver's signed decision
 *  receipt. A throw leaves the row undelivered (retry); never acked on completion. */
export interface TskOutboxTransport {
  deliverAndAwaitAck(record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead): Promise<TskAckReceipt>;
}
export interface HotpApplier {
  applyInTx(exec: PgExecutor, record: OutboxRecord<TskHotpMutation>): Promise<void>;
}

const ACK_DECISIONS: ReadonlySet<ReceiverDecision> = new Set<ReceiverDecision>(['applied', 'duplicate-ok']);
const TRANSIENT_DECISIONS: ReadonlySet<ReceiverDecision> = new Set<ReceiverDecision>(['reject-gap', 'reject-fence']);
const TERMINAL_DECISIONS: ReadonlySet<ReceiverDecision> = new Set<ReceiverDecision>(['reject-fork', 'reject-stale', 'reject-unsanitized', 'reject-epoch']);
const KNOWN_DECISIONS: ReadonlySet<ReceiverDecision> = new Set<ReceiverDecision>([...ACK_DECISIONS, ...TRANSIENT_DECISIONS, ...TERMINAL_DECISIONS]);

export interface PgTskOutboxOptions {
  streamId: string;
  sanitizer: HotpMutationSanitizer;
  signer: StreamHeadSigner;
  maxPendingRows: number;
  backpressure: PublisherBackpressure;
  scopeDeadlineMs?: number;
}

// ── Source-side durable outbox (append builds + signs the head chain) ────────

export class PgTskDurableOutbox {
  readonly sanitizer: HotpMutationSanitizer;
  private readonly schema: string;
  private readonly scopeDeadlineMs: number;
  constructor(private readonly db: PgTransactor, ready: SchemaReadyToken, private readonly opts: PgTskOutboxOptions) {
    if (!Number.isSafeInteger(opts.maxPendingRows) || opts.maxPendingRows <= 0) throw new ContractValidationError('maxPendingRows must be a positive safe integer');
    this.scopeDeadlineMs = validateDeadlineMs(opts.scopeDeadlineMs ?? DEFAULT_SCOPE_DEADLINE_MS, 'scopeDeadlineMs');
    this.schema = requireReady(ready, db);
    this.sanitizer = opts.sanitizer;
  }

  async withOutboxTx<T>(fn: (tx: PgTx, exec: PgExecutor) => Promise<T>): Promise<T> {
    return runScoped(this.scopeDeadlineMs, (signal) => this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      return withBoundTx(exec, this.db, this.schema, (tx, scoped) => fn(tx, scoped));
    }, { signal }));
  }

  /** Append the caller's tumbler mutation: fence check, bounded admission,
   *  sequence allocation, sanitize + digest, build+SIGN the hash-linked head,
   *  insert, advance the source checkpoint head. Returns the header + signed head. */
  async appendInTx(tx: PgTx, input: { streamId: string; rawMutation: TskHotpMutation; fenceToken: FenceToken }): Promise<{ header: OutboxRecordHeader; head: SignedStreamHead }> {
    const exec = execOfBound(tx, this.db, this.schema);
    const streamId = input.streamId;
    if (streamId !== this.opts.streamId) throw new ContractValidationError('streamId mismatch for this outbox');
    const fenceDecimal = fenceTokenToDecimal(input.fenceToken);

    const fenceRows = (await exec.query('SELECT fence_token FROM tsk_outbox_fence WHERE stream_id = $1 FOR UPDATE', [streamId])).rows;
    if (!fenceRows.length) throw new ContractValidationError('no authoritative fence row — stream not provisioned (fail closed)');
    const persistedFence = BigInt(String(fenceRows[0].fence_token));
    if (input.fenceToken !== persistedFence) throw new StaleFenceError(input.fenceToken, persistedFence);

    const pending = safeSeq((await exec.query('SELECT count(*)::bigint AS n FROM tsk_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL AND quarantined_at IS NULL', [streamId])).rows[0].n, 'pending-count');
    if (pending >= this.opts.maxPendingRows) throw new OutboxBackpressureError(this.opts.backpressure);

    const cpRows = (await exec.query('SELECT source_epoch, sequence, head_digest FROM tsk_outbox_source_checkpoint WHERE stream_id = $1 FOR UPDATE', [streamId])).rows;
    if (!cpRows.length) throw new ContractValidationError('stream not provisioned (no source checkpoint row)');
    const sourceEpoch = String(cpRows[0].source_epoch);
    const cur = safeSeq(cpRows[0].sequence, 'source.checkpoint.sequence');
    if (cur >= Number.MAX_SAFE_INTEGER) throw new ContractValidationError('source sequence exhausted safe-integer range');
    const nextSeq = cur + 1;
    const prevHeadDigest = String(cpRows[0].head_digest) || GENESIS_HEAD;

    // (TOCTOU) snapshot the sanitized mutation into a frozen local and FIX the
    // digested/serialized bytes BEFORE the signer.sign await, so what is stored
    // exactly equals what was digested and signed even if the caller's object is
    // mutated during the await.
    const sanitized = this.sanitizer.sanitize(input.rawMutation);
    const counter = (sanitized as unknown as TskHotpMutation).counter;
    if (!Number.isSafeInteger(counter) || counter < 1 || counter > TSK_HOTP_MAX_COUNTER) throw new ContractValidationError('HOTP counter out of range [1, 2^31-1]');
    const tumblerId = (sanitized as unknown as TskHotpMutation).tumblerId;
    if (typeof tumblerId !== 'string' || tumblerId.length < 1 || tumblerId.length > 512) throw new ContractValidationError('tumblerId invalid');
    const mutation = deepFreeze({ tumblerId, counter }) as SanitizedMutation<TskHotpMutation>;

    const opDigest = canonicalOpDigest<TskHotpMutation>({ streamId, sourceEpoch, sequence: nextSeq, fenceToken: fenceDecimal, mutation });
    const mutationJson = JSON.stringify(mutation); // serialize BEFORE any await
    const headDigest = streamHeadDigest({ streamId, sequence: nextSeq, prevHeadDigest, opDigest, keyId: this.opts.signer.keyId, alg: this.opts.signer.alg });
    const signature = await this.opts.signer.sign(headDigest);
    const head: SignedStreamHead = { streamId, sequence: nextSeq, prevHeadDigest, opDigest, keyId: this.opts.signer.keyId, alg: this.opts.signer.alg, headDigest, signature };
    const header: OutboxRecordHeader = { contractVersion: '1', streamId, sourceEpoch, sequence: nextSeq, fenceToken: fenceDecimal, opDigest };
    assertHeaderConformant(header);
    assertStreamHeadBinds(header, head);

    affectedOne(await exec.query(
      `INSERT INTO tsk_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, tumbler_id, hotp_counter, mutation, head_prev, head_digest, head_key_id, head_alg, head_sig)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [streamId, sourceEpoch, nextSeq, fenceDecimal, opDigest, tumblerId, counter, mutationJson, prevHeadDigest, headDigest, this.opts.signer.keyId, this.opts.signer.alg, signature],
    ), 'outbox row insert');
    affectedOne(await exec.query('UPDATE tsk_outbox_source_checkpoint SET sequence = $2, head_digest = $3 WHERE stream_id = $1', [streamId, nextSeq, headDigest]), 'source checkpoint advance');
    return { header, head };
  }
}

export interface PgTskPublisherOptions { leaseMs: number; scopeDeadlineMs?: number }
export interface TskDrainResult { published: number; acked: number; quarantined: number; retriable: boolean; halted: boolean }

/**
 * Per-stream ORDERED single-active publisher (H1/H2). One publisher delivers a
 * stream at a time, strictly ascending; delivery + ACK-await happen OUTSIDE any
 * tx; the row is removed only on a verified applied|duplicate-ok decision; a
 * transient reject releases + retries; a terminal reject quarantines + halts.
 * Delivers the record AND its signed stream head.
 */
export class PgTskPublisher {
  private readonly leaseMs: number;
  private readonly scopeDeadlineMs: number;
  private readonly schema: string;
  constructor(
    private readonly db: PgTransactor,
    private readonly streamId: string,
    private readonly transport: TskOutboxTransport,
    readonly backpressure: PublisherBackpressure,
    private readonly sanitizer: Pick<HotpMutationSanitizer, 'assertSanitized'>,
    private readonly ackVerifier: TskAckReceiptVerifier,
    ready: SchemaReadyToken,
    opts: PgTskPublisherOptions = { leaseMs: 30_000 },
  ) {
    if (!Number.isSafeInteger(opts.leaseMs) || opts.leaseMs <= 0) throw new ContractValidationError('leaseMs must be a positive safe integer');
    this.scopeDeadlineMs = validateDeadlineMs(opts.scopeDeadlineMs ?? DEFAULT_SCOPE_DEADLINE_MS, 'scopeDeadlineMs');
    this.schema = requireReady(ready, db);
    this.leaseMs = opts.leaseMs;
  }

  private tx<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    return runScoped(this.scopeDeadlineMs, (signal) => this.db.transaction(async (exec) => { await enterCriticalTx(exec, this.schema); return fn(exec); }, { signal }));
  }

  private async acquireLease(leaseToken: string): Promise<boolean> {
    return this.tx(async (exec) => {
      const res = await exec.query(
        `INSERT INTO tsk_outbox_publisher_lease (stream_id, lease_token, lease_until)
         VALUES ($1, $2, now() + ($3::text || ' milliseconds')::interval)
         ON CONFLICT (stream_id) DO UPDATE SET lease_token = EXCLUDED.lease_token, lease_until = EXCLUDED.lease_until
           WHERE tsk_outbox_publisher_lease.lease_until IS NULL OR tsk_outbox_publisher_lease.lease_until < now()
         RETURNING lease_token`, [this.streamId, leaseToken, String(this.leaseMs)]);
      return res.rowCount === 1;
    });
  }
  private async releaseLease(leaseToken: string): Promise<void> {
    await this.tx((exec) => exec.query('UPDATE tsk_outbox_publisher_lease SET lease_token = NULL, lease_until = NULL WHERE stream_id = $1 AND lease_token = $2', [this.streamId, leaseToken]));
  }
  private async nextDeliverable(leaseToken: string): Promise<Record<string, unknown> | null> {
    return this.tx(async (exec) => {
      const lease = (await exec.query('SELECT lease_token FROM tsk_outbox_publisher_lease WHERE stream_id = $1 FOR UPDATE', [this.streamId])).rows;
      if (!lease.length || lease[0].lease_token !== leaseToken) throw new ContractValidationError('publisher lease lost — aborting drain');
      const rows = (await exec.query('SELECT source_epoch, sequence, fence_token, op_digest, mutation, head_prev, head_digest, head_key_id, head_alg, head_sig FROM tsk_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL AND quarantined_at IS NULL ORDER BY sequence ASC LIMIT 1', [this.streamId])).rows;
      return rows[0] ?? null;
    });
  }

  private async isHalted(): Promise<boolean> {
    return this.tx(async (exec) => (await exec.query('SELECT 1 FROM tsk_outbox_stream_halted WHERE stream_id = $1', [this.streamId])).rows.length > 0);
  }

  async drainOnce(): Promise<TskDrainResult> {
    // (MED) refuse a durably-halted stream up front — no spin, no permanent
    // reject-gap loop. Recovery is a GOVERNED repair (unquarantine + epoch-resync,
    // out of this slice); clearing the marker alone does NOT recover the stream.
    if (await this.isHalted()) return { published: 0, acked: 0, quarantined: 0, retriable: false, halted: true };
    const leaseToken = randomUUID();
    if (!(await this.acquireLease(leaseToken))) return { published: 0, acked: 0, quarantined: 0, retriable: true, halted: false };
    let published = 0, acked = 0, quarantined = 0, retriable = false, halted = false;
    try {
      for (;;) {
        const r = await this.nextDeliverable(leaseToken);
        if (!r) break;
        const sourceEpoch = String(r.source_epoch);
        const sequence = safeSeq(r.sequence, 'row.sequence');
        const storedDigest = String(r.op_digest);
        const mutation = r.mutation as SanitizedMutation<TskHotpMutation>;
        this.sanitizer.assertSanitized(mutation);
        const recomputed = canonicalOpDigest<TskHotpMutation>({ streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), mutation });
        if (!digestEquals(recomputed, storedDigest)) throw new ContractValidationError(`corrupted outbox row: digest mismatch at ${this.streamId}/${sourceEpoch}/${sequence}`);

        const record: OutboxRecord<TskHotpMutation> = { contractVersion: '1', streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), opDigest: storedDigest, mutation };
        const head: SignedStreamHead = { streamId: this.streamId, sequence, prevHeadDigest: String(r.head_prev), opDigest: storedDigest, keyId: String(r.head_key_id), alg: String(r.head_alg) as StreamHeadAlg, headDigest: String(r.head_digest), signature: String(r.head_sig) };
        // fail closed on a corrupted stored head
        assertStreamHeadBinds({ contractVersion: '1', streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), opDigest: storedDigest }, head);

        const rawReceipt = await this.transport.deliverAndAwaitAck(record, head);
        published++;
        // (TOCTOU) snapshot + strict-validate + FREEZE the FULL receipt BEFORE the
        // verify await, and use ONLY the snapshot afterward — the transport cannot
        // mutate the signed decision (e.g. reject-fork -> applied) after verification.
        const receipt = snapshotAckReceipt(rawReceipt);
        await this.ackVerifier.verify(receipt, record);
        if (receipt.streamId !== this.streamId || receipt.sourceEpoch !== sourceEpoch || receipt.sequence !== sequence || !digestEquals(receipt.opDigest, storedDigest)) {
          throw new ContractValidationError('ACK receipt does not match the delivered record — not acking');
        }
        if (!KNOWN_DECISIONS.has(receipt.decision)) throw new ContractValidationError(`unknown receiver decision: ${String(receipt.decision)}`);

        if (ACK_DECISIONS.has(receipt.decision)) {
          await this.tx(async (exec) => {
            const lease = (await exec.query('SELECT lease_token FROM tsk_outbox_publisher_lease WHERE stream_id = $1 FOR UPDATE', [this.streamId])).rows;
            if (!lease.length || lease[0].lease_token !== leaseToken) throw new ContractValidationError('publisher lease lost — not acking');
            affectedOne(await exec.query('UPDATE tsk_outbox_rows SET published_at = now(), acked_at = now() WHERE stream_id = $1 AND source_epoch = $2 AND sequence = $3 AND acked_at IS NULL AND quarantined_at IS NULL AND op_digest = $4', [this.streamId, sourceEpoch, sequence, storedDigest]), 'publisher ack');
          });
          acked++; continue;
        }
        if (TRANSIENT_DECISIONS.has(receipt.decision)) { retriable = true; break; }
        // terminal → quarantine + halt
        await this.tx(async (exec) => {
          const lease = (await exec.query('SELECT lease_token FROM tsk_outbox_publisher_lease WHERE stream_id = $1 FOR UPDATE', [this.streamId])).rows;
          if (!lease.length || lease[0].lease_token !== leaseToken) throw new ContractValidationError('publisher lease lost — not quarantining');
          const ins = await exec.query('INSERT INTO tsk_outbox_quarantine (stream_id, source_epoch, sequence, op_digest, decision) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (stream_id, source_epoch, sequence) DO NOTHING', [this.streamId, sourceEpoch, sequence, storedDigest, receipt.decision]);
          if (ins.rowCount === 0) {
            const ex = (await exec.query('SELECT op_digest, decision FROM tsk_outbox_quarantine WHERE stream_id = $1 AND source_epoch = $2 AND sequence = $3 FOR UPDATE', [this.streamId, sourceEpoch, sequence])).rows;
            if (!ex.length) throw new ContractValidationError('quarantine conflict without an existing row');
            if (!digestEquals(String(ex[0].op_digest), storedDigest) || String(ex[0].decision) !== receipt.decision) throw new ContractValidationError('quarantine record conflict: existing digest/decision differ from this record');
          } else if (ins.rowCount !== 1) throw new ContractValidationError('quarantine insert affected unexpected row count');
          affectedOne(await exec.query('UPDATE tsk_outbox_rows SET quarantined_at = now() WHERE stream_id = $1 AND source_epoch = $2 AND sequence = $3 AND acked_at IS NULL AND quarantined_at IS NULL', [this.streamId, sourceEpoch, sequence]), 'quarantine mark');
          // (MED) DURABLY halt the stream in the SAME tx as the quarantine so the
          // divergence cannot silently become a permanent reject-gap spin. Idempotent.
          await exec.query('INSERT INTO tsk_outbox_stream_halted (stream_id, source_epoch, sequence, op_digest, decision) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (stream_id) DO NOTHING', [this.streamId, sourceEpoch, sequence, storedDigest, receipt.decision]);
        });
        quarantined++; halted = true; break;
      }
    } finally {
      await this.releaseLease(leaseToken);
    }
    return { published, acked, quarantined, retriable, halted };
  }
}

/**
 * Tumbler receiver (contract TskReceiverCheckpoint). The ONLY apply path,
 * verifyAndApplyTumblerInTx, in ONE serializable tx:
 *   1) re-sanitize + recompute the op digest (tamper → reject-fork);
 *   2) bind the signed head to the record + VERIFY its signature (forged → reject-fork);
 *      a StreamHeadVerifier that throws `StreamHeadVerificationUnavailableError`
 *      (only) is re-thrown for retry — every other throw is a permanent reject-fork;
 *   3) head hash-chain continuity: head.prevHeadDigest == the receiver's last head
 *      (or genesis) → else reject-fork;
 *   4) record-bound fence exact equality vs persisted → reject-fence;
 *   5) in-order delivery vs the independent receiver checkpoint (gap/epoch/dup/fork);
 *   6) HOTP EXACTLY-ONCE: counter strictly > the per-tumbler high-water mark, else
 *      reject-fork (replay/double-consume);
 *   7) apply + consume the counter + advance checkpoint (seq + head) + record
 *      applied-history — all atomic.
 */
export class PgTskReceiverCheckpoint implements TskReceiverCheckpoint<TskPgBackend> {
  readonly sanitizer: Pick<HotpMutationSanitizer, 'assertSanitized'>;
  readonly headVerifier: StreamHeadVerifier;
  readonly epochAuthorizer: EpochTransitionAuthorizer;
  private readonly schema: string;
  private readonly scopeDeadlineMs: number;
  constructor(
    private readonly db: PgTransactor,
    private readonly streamId: string,
    sanitizer: Pick<HotpMutationSanitizer, 'assertSanitized'>,
    headVerifier: StreamHeadVerifier,
    private readonly applier: HotpApplier,
    ready: SchemaReadyToken,
    epochAuthorizer: EpochTransitionAuthorizer = { async authorizeTransition() { throw new ContractValidationError('epoch transition not authorized in this slice'); } },
    scopeDeadlineMs: number = DEFAULT_SCOPE_DEADLINE_MS,
  ) {
    this.schema = requireReady(ready, db);
    this.sanitizer = sanitizer; this.headVerifier = headVerifier; this.epochAuthorizer = epochAuthorizer;
    this.scopeDeadlineMs = validateDeadlineMs(scopeDeadlineMs, 'scopeDeadlineMs');
  }

  /** Safe public entry: receiver opens its OWN bounded tx and applies. */
  async verifyAndApplyTumblerDelivered(record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead): Promise<ReceiverDecision> {
    return runScoped(this.scopeDeadlineMs, (signal) => this.db.transaction((exec) => withBoundTx(exec, this.db, this.schema, (tx) => this.verifyAndApplyTumblerInTx(tx, record, head)), { signal }));
  }

  async verifyAndApplyTumblerInTx(tx: PgTx, recordUntrusted: OutboxRecord<TskHotpMutation>, headUntrusted: SignedStreamHead): Promise<ReceiverDecision> {
    // (TOCTOU) Snapshot the ENTIRE untrusted record + head SYNCHRONOUSLY, before
    // the first await, and use ONLY the frozen snapshots afterward. A caller can
    // no longer mutate the applied/consumed value across the headVerifier await
    // under a valid signed digest.
    const record = snapshotRecord(recordUntrusted);
    const head = snapshotHead(headUntrusted);
    const exec = execOfBound(tx, this.db, this.schema);
    await enterCriticalTx(exec, this.schema);
    if (record.streamId !== this.streamId) throw new ContractValidationError('streamId mismatch for this receiver');
    assertHeaderConformant(record);

    try { this.sanitizer.assertSanitized(record.mutation); } catch { return 'reject-unsanitized'; }
    const recomputed = canonicalOpDigest<TskHotpMutation>({ streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence, fenceToken: record.fenceToken, mutation: record.mutation });
    if (!digestEquals(recomputed, record.opDigest)) return 'reject-fork';

    // (2) signed head bound to the record + signature verified (over the snapshot).
    try { assertStreamHeadBinds(record, head); } catch { return 'reject-fork'; }
    try { await this.headVerifier.verify(head); }
    catch (err) {
      // ONLY a typed unavailability error retries; EVERY other throw (invalid
      // signature, unknown key/alg, or an UNKNOWN exception) is a permanent
      // reject-fork (fail-closed) — no attacker-controlled retry loop.
      if (err instanceof StreamHeadVerificationUnavailableError) throw err;
      return 'reject-fork';
    }

    // (4) fence exact equality vs persisted authoritative token.
    const fenceRows = (await exec.query('SELECT fence_token FROM tsk_outbox_fence WHERE stream_id = $1 FOR UPDATE', [record.streamId])).rows;
    if (!fenceRows.length) return 'reject-fence';
    if (BigInt(record.fenceToken) !== BigInt(String(fenceRows[0].fence_token))) return 'reject-fence';

    // (5) receiver's own checkpoint authority + head chain continuity.
    const cpRows = (await exec.query('SELECT source_epoch, sequence, head_digest FROM tsk_outbox_receiver_checkpoint WHERE stream_id = $1 FOR UPDATE', [record.streamId])).rows;
    if (!cpRows.length) throw new ContractValidationError('receiver stream not provisioned');
    const cpEpoch = String(cpRows[0].source_epoch);
    const cpSeq = safeSeq(cpRows[0].sequence, 'receiver.checkpoint.sequence');
    const cpHead = String(cpRows[0].head_digest) || GENESIS_HEAD;

    if (record.sourceEpoch !== cpEpoch) return 'reject-epoch';
    if (record.sequence <= cpSeq) {
      const prior = (await exec.query('SELECT op_digest FROM tsk_outbox_applied WHERE stream_id=$1 AND source_epoch=$2 AND sequence=$3', [record.streamId, record.sourceEpoch, record.sequence])).rows;
      if (prior.length && digestEquals(String(prior[0].op_digest), record.opDigest)) return 'duplicate-ok';
      if (prior.length) return 'reject-fork';
      return 'reject-stale';
    }
    if (record.sequence > cpSeq + 1) return 'reject-gap';

    // (3) hash-chain continuity: this fresh in-order record's prevHeadDigest MUST
    // equal the receiver's last applied head (or genesis).
    if (head.prevHeadDigest !== cpHead) return 'reject-fork';

    // (6) HOTP exactly-once: strictly increasing per-tumbler high-water mark.
    const counter = record.mutation.counter;
    const tumblerId = record.mutation.tumblerId;
    const consumed = (await exec.query('SELECT last_counter FROM tsk_hotp_consumed WHERE stream_id = $1 AND tumbler_id = $2 FOR UPDATE', [record.streamId, tumblerId])).rows;
    if (consumed.length) {
      const last = safeSeq(consumed[0].last_counter, 'hotp.last_counter');
      if (counter <= last) return 'reject-fork'; // replay / double-consume
    }

    // (7) apply + consume + advance checkpoint(seq+head) + applied-history, atomic.
    // Everything below uses the frozen snapshot exclusively.
    await this.applier.applyInTx(exec, record);
    affectedOne(await exec.query(
      `INSERT INTO tsk_hotp_consumed (stream_id, tumbler_id, last_counter) VALUES ($1,$2,$3)
       ON CONFLICT (stream_id, tumbler_id) DO UPDATE SET last_counter = EXCLUDED.last_counter WHERE EXCLUDED.last_counter > tsk_hotp_consumed.last_counter`,
      [record.streamId, tumblerId, counter]), 'hotp consume');
    affectedOne(await exec.query('INSERT INTO tsk_outbox_applied (stream_id, source_epoch, sequence, op_digest) VALUES ($1,$2,$3,$4)', [record.streamId, record.sourceEpoch, record.sequence, record.opDigest]), 'receiver applied-history insert');
    affectedOne(await exec.query('UPDATE tsk_outbox_receiver_checkpoint SET sequence=$2, head_digest=$3 WHERE stream_id=$1', [record.streamId, record.sequence, head.headDigest]), 'receiver checkpoint advance');
    return 'applied';
  }

  async transitionEpochInTx(): Promise<'transitioned' | 'duplicate-ok' | 'reject-fork' | 'reject-stale-epoch' | 'reject-fence'> {
    throw new ContractValidationError('epoch transition not implemented in this slice (governed transition is separate)');
  }
}
