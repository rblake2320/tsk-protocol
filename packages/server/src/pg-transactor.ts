import { randomUUID } from 'node:crypto';
import { ContractValidationError } from './ha-outbox-contract.js';
import type { PgExecutor, PgTransactor } from './tsk-hotp-outbox-pg.js';

/**
 * Production `node-postgres` adapter for the TSK durable-outbox `PgTransactor`
 * contract (see tsk-hotp-outbox-pg.ts). It satisfies, against a REAL pg pool,
 * every clause the contract requires of a conforming transactor:
 *   - bound every query at the connection layer (a client-side deadline AND a
 *     server-side statement_timeout that is installed and read back to verify);
 *   - run exactly ONE `BEGIN ISOLATION LEVEL SERIALIZABLE` transaction and VERIFY
 *     the BEGIN and COMMIT command tags (an aborted tx silently turns COMMIT into
 *     ROLLBACK — an unverified COMMIT is a correctness hole);
 *   - HONOR an abort signal by cancelling the in-flight query and DESTROYING the
 *     connection promptly, never unbounded-awaiting ROLLBACK;
 *   - DISCARD any connection whose tx errored / timed out / failed to confirm its
 *     commit, so a poisoned connection is never returned to the pool.
 *
 * BOUNDARY (#10 stays OPEN): this is the single-node production driver. It does
 * NOT make a high-availability or uptime claim. Two-node PostgreSQL failover /
 * split-brain with measured RPO/RTO remains the HA gate. Redis is out of scope.
 *
 * The `pg` package is NOT imported here: the adapter depends only on the
 * structural `NodePostgres*` interfaces below, so `pg` never becomes a runtime
 * dependency of `@tsk/server` — a real `pg.Pool`/`PoolClient` satisfies them.
 */

// ── structural driver surface (a real pg.Pool/PoolClient conforms) ───────────

export interface NodePostgresResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
  command?: string;
}

export interface NodePostgresClient {
  query(sql: string, params?: unknown[]): Promise<NodePostgresResult>;
  /** Return to the pool; `destroy` (true or an Error) permanently discards it. */
  release(destroy?: boolean | Error): void;
  /** Optional EventEmitter surface (a real `pg` client has it). While a client is
   *  checked out, `pg` removes its OWN 'error' listener and makes the borrower
   *  responsible — an unlistened mid-transaction connection death would otherwise
   *  crash the process. When present, the transactor attaches an 'error' listener
   *  for the checked-out lifetime; the real failure still surfaces through the
   *  in-flight query rejection, so this listener only prevents the unhandled crash. */
  on?(event: 'error', listener: (err: unknown) => void): void;
  removeListener?(event: 'error', listener: (err: unknown) => void): void;
}

export interface NodePostgresPool {
  connect(): Promise<NodePostgresClient>;
}

export interface NodePostgresTransactorOptions {
  /** Durability level FORCED tx-locally + read back immediately before COMMIT, so the
   *  commit's durability cannot be lowered by anything the callback did. Default 'on'.
   *  'off' is NOT accepted: this driver backs a DURABLE outbox and 'off' does not wait
   *  for the local WAL flush, so a confirmed COMMIT could not be called durable. */
  synchronousCommit?: 'on' | 'local' | 'remote_write' | 'remote_apply';
  /** Server-side per-statement timeout, installed + verified inside the tx. */
  statementTimeoutMs?: number;
  /** Client-side total deadline covering acquire → BEGIN → work → COMMIT. */
  transactionTimeoutMs?: number;
  /** Bound on how long `pool.connect()` may take before we give up + discard. */
  acquireTimeoutMs?: number;
  /** Bound on the best-effort ROLLBACK issued on the failure path. */
  rollbackTimeoutMs?: number;
  /** Bounded SERIALIZABLE/deadlock retries; DEFAULT 0 (callbacks may have
   *  non-DB side effects that cannot be safely replayed). */
  maxSerializationRetries?: number;
  retryBaseDelayMs?: number;
  /** Telemetry sink for connection-disposal faults; it can NEVER change the
   *  transaction outcome. */
  onDisposalError?: (error: unknown, phase: 'active' | 'late-acquire') => void | Promise<void>;
}

// ── outcome taxonomy: the caller must be able to tell these three apart ───────

/** COMMIT was confirmed by PostgreSQL, but returning the client to the pool
 *  failed. The data IS durable; only pool hygiene degraded. */
export class PostCommitReleaseError extends Error {
  readonly committed = true;
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PostCommitReleaseError';
  }
}

/** COMMIT was dispatched but its response was lost (abort / socket death after
 *  dispatch). The outcome is genuinely unknown — DO NOT blindly retry. Reconcile
 *  against authoritative state by idempotency key first (for the TSK outbox:
 *  the (streamId, sourceEpoch, sequence, opDigest) row, the receiver checkpoint
 *  seq+head chain, and tsk_hotp_consumed.last_counter). */
export class AmbiguousCommitError extends Error {
  readonly committed = 'unknown' as const;
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AmbiguousCommitError';
  }
}

/** The transaction failed AND the connection could not be disposed. Definitely
 *  not committed; the connection was poisoned. */
export class ConnectionDisposalError extends Error {
  readonly committed = false;
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ConnectionDisposalError';
  }
}

const MAX_TIMER_MS = 2_147_483_647;
const RETRYABLE = new Set(['40001', '40P01']); // serialization_failure, deadlock_detected
// 'off' is intentionally excluded: it does not wait for the local WAL flush, so a
// confirmed COMMIT on this durable-outbox driver would not actually be durable.
const SYNC_COMMIT_LEVELS = new Set(['on', 'local', 'remote_write', 'remote_apply']);

function boundedInteger(value: number, label: string, min = 1, max = MAX_TIMER_MS): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new ContractValidationError(`${label} must be a safe integer in [${min}, ${max}]`);
  }
  return value;
}

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new ContractValidationError('PostgreSQL transaction aborted');
}

/** Reject as soon as `signal` aborts, even if `work` never settles (hung socket).
 *  The abandoned `work` promise is caught so it cannot raise an unhandled
 *  rejection after we have already moved on. */
function abortRace<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  // Swallow the abandoned work on EVERY path (including the already-aborted early
  // return) so a late rejection from a query/callback we stopped awaiting can never
  // surface as an unhandled rejection.
  work.catch(() => {});
  if (signal.aborted) return Promise.reject(abortError(signal));
  let onAbort!: () => void;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(abortError(signal));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  return Promise.race([work, aborted]).finally(() => signal.removeEventListener('abort', onAbort));
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(abortError(signal));
    const onAbort = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      reject(abortError(signal));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

/** Best-effort ROLLBACK that can never block the failure path unbounded. It is
 *  clamped by BOTH a fixed budget AND the transaction signal, so once the total
 *  deadline (or a caller abort) fires, cleanup stops immediately and the caller
 *  destroys the connection — cleanup can never extend the transaction past its
 *  deadline. If the signal has already fired, it does not even issue the ROLLBACK. */
async function boundedRollback(client: NodePostgresClient, ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return; // deadline/abort already reached — do not extend cleanup; destroy instead
  let timer!: ReturnType<typeof setTimeout>;
  let onAbort!: () => void;
  const stop = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, ms);
    onAbort = () => resolve();
    signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    await Promise.race([client.query('ROLLBACK').then(() => undefined).catch(() => undefined), stop]);
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', onAbort);
  }
}

// (H1) A transaction callback receives a capability-limited executor: it may run
// data statements but MUST NOT issue transaction/session control that would escape
// or subvert the transactor's single-transaction guarantee — a callback that COMMITs
// its own writes then throws would durably persist under an ordinary pre-COMMIT error,
// and a rogue SET could poison the pooled session. Detection must survive PostgreSQL's
// NESTED block comments (`/* /* */ */`), line comments, and string/dollar/identifier
// quoting, so a proper lexer blanks all of those BEFORE keyword/separator checks.
// Defense-in-depth denylist (the runtime authorities below — forced durability + a
// post-commit DISCARD ALL — are what actually guarantee integrity; this just blocks
// the obvious escapes up front). Leading transaction/session/DDL/session-object verbs.
const TX_CONTROL_LEAD = /^(begin|start|commit|end|rollback|abort|savepoint|release|discard|set|reset|prepare|do|call|create|listen|unlisten|load)\b/i;

/** Blank comments and string/dollar/double-quoted literals, honoring PostgreSQL's
 *  NESTED block comments, so hidden control keywords or `;` separators cannot slip
 *  past. Returns SQL with all such spans replaced by neutral placeholders. */
function sqlToCode(sql: string): string {
  let out = '';
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const c = sql[i];
    const c2 = sql[i + 1];
    if (c === '-' && c2 === '-') { i += 2; while (i < n && sql[i] !== '\n') i++; out += ' '; continue; }
    if (c === '/' && c2 === '*') { // nested-aware block comment
      let depth = 1; i += 2;
      while (i < n && depth > 0) {
        if (sql[i] === '/' && sql[i + 1] === '*') { depth++; i += 2; }
        else if (sql[i] === '*' && sql[i + 1] === '/') { depth--; i += 2; }
        else i++;
      }
      out += ' '; continue;
    }
    if (c === "'") { // single-quoted string: '' escape and backslash-escape (E'...')
      i++;
      while (i < n) {
        if (sql[i] === '\\') { i += 2; continue; }
        if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
        if (sql[i] === "'") { i++; break; }
        i++;
      }
      out += "''"; continue;
    }
    if (c === '$') { // dollar-quoted string $tag$...$tag$
      const m = /^\$([A-Za-z_]\w*)?\$/.exec(sql.slice(i));
      if (m) { const tag = m[0]; const end = sql.indexOf(tag, i + tag.length); i = end === -1 ? n : end + tag.length; out += "''"; continue; }
    }
    if (c === '"') { // double-quoted identifier: "" escape
      i++;
      while (i < n) {
        if (sql[i] === '"' && sql[i + 1] === '"') { i += 2; continue; }
        if (sql[i] === '"') { i++; break; }
        i++;
      }
      out += '"x"'; continue;
    }
    out += c; i++;
  }
  return out;
}
function assertCallerQueryAllowed(sql: string): void {
  if (typeof sql !== 'string') throw new ContractValidationError('query sql must be a string');
  const code = sqlToCode(sql).trim();
  const lead = code.replace(/^[('"\s]+/, ''); // tolerate leading '(' / quote-ident / whitespace
  if (TX_CONTROL_LEAD.test(lead)) {
    throw new ContractValidationError('transaction/session-control statements are not allowed inside a transactor callback');
  }
  // set_config(...) is session-control smuggled through a SELECT: session-level
  // set_config (is_local != true) can change role/search_path/etc and POISON the
  // pooled connection. Only the tx-local form set_config(name, value, true) is allowed.
  if (/\bset_config\s*\(/i.test(code) && !/\bset_config\s*\([^)]*,\s*true\s*\)/i.test(code)) {
    throw new ContractValidationError('session-level set_config is not allowed inside a transactor callback (only tx-local set_config(name, value, true))');
  }
  const semi = code.indexOf(';');
  if (semi >= 0 && code.slice(semi + 1).trim().length > 0) {
    throw new ContractValidationError('multiple statements are not allowed inside a transactor callback');
  }
}

// Control queries are schema-qualified to pg_catalog so a callback cannot shadow
// current_setting/set_config via a pg_temp function + a search_path change.
const STMT_TIMEOUT_MS_SQL = "SELECT (EXTRACT(EPOCH FROM pg_catalog.current_setting('statement_timeout')::interval) * 1000)::bigint::text AS statement_timeout_ms";
const CONTINUITY_GUC = 'tsk.tx_continuity';

export class NodePostgresTransactor implements PgTransactor {
  private readonly statementTimeoutMs: number;
  private readonly transactionTimeoutMs: number;
  private readonly acquireTimeoutMs: number;
  private readonly rollbackTimeoutMs: number;
  private readonly maxSerializationRetries: number;
  private readonly retryBaseDelayMs: number;
  private readonly onDisposalError?: NodePostgresTransactorOptions['onDisposalError'];
  private readonly synchronousCommit: NonNullable<NodePostgresTransactorOptions['synchronousCommit']>;

  constructor(private readonly pool: NodePostgresPool, opts: NodePostgresTransactorOptions = {}) {
    if (!pool || typeof pool.connect !== 'function') {
      throw new ContractValidationError('pool.connect is required');
    }
    this.synchronousCommit = opts.synchronousCommit ?? 'on';
    if (!SYNC_COMMIT_LEVELS.has(this.synchronousCommit)) {
      throw new ContractValidationError(`synchronousCommit must be one of ${[...SYNC_COMMIT_LEVELS].join(', ')}`);
    }
    this.statementTimeoutMs = boundedInteger(opts.statementTimeoutMs ?? 30_000, 'statementTimeoutMs');
    this.transactionTimeoutMs = boundedInteger(opts.transactionTimeoutMs ?? 35_000, 'transactionTimeoutMs');
    this.acquireTimeoutMs = boundedInteger(opts.acquireTimeoutMs ?? 5_000, 'acquireTimeoutMs');
    this.rollbackTimeoutMs = boundedInteger(opts.rollbackTimeoutMs ?? 1_000, 'rollbackTimeoutMs');
    this.maxSerializationRetries = boundedInteger(opts.maxSerializationRetries ?? 0, 'maxSerializationRetries', 0, 100);
    this.retryBaseDelayMs = boundedInteger(opts.retryBaseDelayMs ?? 10, 'retryBaseDelayMs', 1, 1_000);
    if (opts.onDisposalError !== undefined && typeof opts.onDisposalError !== 'function') {
      throw new ContractValidationError('onDisposalError must be a function');
    }
    this.onDisposalError = opts.onDisposalError;
  }

  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>, opts?: { signal?: AbortSignal }): Promise<T> {
    // ONE controller unifies the caller's signal and the internal total-deadline
    // timer, so a transaction is bounded even when the caller passes no signal.
    const controller = new AbortController();
    const caller = opts?.signal;
    const onCallerAbort = () => controller.abort(abortError(caller!));
    if (caller?.aborted) controller.abort(abortError(caller));
    else caller?.addEventListener('abort', onCallerAbort, { once: true });
    const timer = setTimeout(
      () => controller.abort(new ContractValidationError(`PostgreSQL transaction deadline exceeded (${this.transactionTimeoutMs}ms)`)),
      this.transactionTimeoutMs,
    );
    try {
      for (let attempt = 0; ; attempt++) {
        if (controller.signal.aborted) throw abortError(controller.signal);
        try {
          return await this.runOnce(fn, controller.signal);
        } catch (error) {
          const code = (error as { code?: unknown })?.code;
          if (
            typeof code !== 'string'
            || !RETRYABLE.has(code)
            || attempt >= this.maxSerializationRetries
            || controller.signal.aborted
          ) throw error;
          await sleep(Math.min(this.retryBaseDelayMs * (2 ** attempt), 1_000), controller.signal);
        }
      }
    } finally {
      clearTimeout(timer);
      caller?.removeEventListener('abort', onCallerAbort);
    }
  }

  private reportDisposalError(error: unknown, phase: 'active' | 'late-acquire'): void {
    try {
      const observed = this.onDisposalError?.(error, phase);
      if (observed && typeof observed.then === 'function') observed.catch(() => {});
    } catch { /* telemetry cannot change the transaction outcome */ }
  }

  /** Acquire a connection under a bound; if the bound (or an abort) wins the race,
   *  destroy the connection that arrives late so it can never leak into the pool. */
  private async acquire(signal: AbortSignal): Promise<NodePostgresClient> {
    const pending = this.pool.connect();
    let timer!: ReturnType<typeof setTimeout>;
    let onAbort!: () => void;
    const gate = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new ContractValidationError('PostgreSQL connection acquisition timed out')), this.acquireTimeoutMs);
      onAbort = () => reject(abortError(signal));
      signal.addEventListener('abort', onAbort, { once: true });
    });
    try {
      return await Promise.race([pending, gate]);
    } catch (error) {
      pending.then((late) => {
        late.on?.('error', () => {}); // a late connection we are about to discard must not crash on error
        try { late.release(true); } catch (releaseError) { this.reportDisposalError(releaseError, 'late-acquire'); }
      }).catch(() => {});
      throw error;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
    }
  }

  private async runOnce<T>(fn: (exec: PgExecutor) => Promise<T>, signal: AbortSignal): Promise<T> {
    const client = await this.acquire(signal);
    let releaseState: 'open' | 'released' | 'destroyed' | 'failed' = 'open';
    let disposalError: unknown;
    let committed = false;
    let commitDispatched = false;
    let commitDefinitivelyAborted = false;
    const terminalRelease = (destroy: boolean) => {
      if (releaseState !== 'open') return;
      releaseState = destroy ? 'destroyed' : 'released';
      try {
        client.release(destroy);
      } catch (error) {
        releaseState = 'failed';
        disposalError = error;
        this.reportDisposalError(error, 'active');
      }
    };
    const destroy = () => terminalRelease(true);
    const releaseNormally = () => {
      terminalRelease(false);
      if (releaseState === 'failed') {
        throw new PostCommitReleaseError('PostgreSQL committed but returning the connection to the pool failed', { cause: disposalError });
      }
    };
    const onAbort = () => destroy();
    signal.addEventListener('abort', onAbort, { once: true });
    // Own the checked-out client's 'error' event so a mid-transaction connection
    // death (real network partition) cannot escape as an unhandled 'error'. The
    // authoritative failure still arrives via the in-flight query rejection below.
    const onClientError = () => { /* swallow — the query rejection carries the real error */ };
    client.on?.('error', onClientError);

    const query = (sql: string, params?: unknown[]) => {
      if (signal.aborted) return Promise.reject(abortError(signal));
      return abortRace(client.query(sql, params), signal);
    };
    try {
      const begin = await query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      if (begin.command !== 'BEGIN') {
        throw new ContractValidationError(`PostgreSQL BEGIN was not confirmed (command=${begin.command ?? 'missing'})`);
      }
      // install the server-side statement timeout, then READ IT BACK to verify it
      // actually took (a silently-ignored SET would leave queries unbounded at the DB).
      const install = await query("SELECT pg_catalog.set_config('statement_timeout', $1, true) AS statement_timeout", [String(this.statementTimeoutMs)]);
      if (install.command !== 'SELECT' || typeof install.rows[0]?.statement_timeout !== 'string') {
        throw new ContractValidationError('PostgreSQL statement_timeout setup was not confirmed');
      }
      const readback = await query(STMT_TIMEOUT_MS_SQL);
      if (readback.command !== 'SELECT' || readback.rows[0]?.statement_timeout_ms !== String(this.statementTimeoutMs)) {
        throw new ContractValidationError('PostgreSQL statement_timeout readback did not match the requested value');
      }
      // (H1 runtime backstop) ARM a transaction-continuity sentinel: an UNFORGEABLE
      // per-transaction nonce stored in a tx-LOCAL custom GUC. It persists only while
      // THIS transaction stays open; any COMMIT/ROLLBACK inside the callback drops it.
      // Unforgeable (random) so a callback cannot pre-set a session value to match, and
      // pg_catalog-qualified so it cannot be shadowed via pg_temp.
      const nonce = randomUUID();
      const armed = await query(`SELECT pg_catalog.set_config('${CONTINUITY_GUC}', $1, true) AS n`, [nonce]);
      if (armed.command !== 'SELECT' || armed.rows[0]?.n !== nonce) {
        throw new ContractValidationError('failed to arm the transaction-continuity sentinel');
      }
      // (durability precondition) verify the server durability settings ON THIS EXACT
      // connection. `fsync` and `full_page_writes` are both server-level (SIGHUP)
      // settings, so this is checked TWICE: once now (fail before doing any work) and
      // again immediately before COMMIT (they can be reloaded mid-transaction — a TOCTOU
      // that would otherwise leave the commit non-durable / unsafe on crash recovery).
      const assertDurableSettings = async () => {
        const r = await query("SELECT pg_catalog.current_setting('fsync') AS fsync, pg_catalog.current_setting('full_page_writes') AS fpw");
        if (r.command !== 'SELECT') throw new ContractValidationError('durable server-settings check was not confirmed');
        if (r.rows[0]?.fsync !== 'on') throw new ContractValidationError(`refusing a durable transaction: fsync is '${String(r.rows[0]?.fsync)}', not 'on'`);
        if (r.rows[0]?.fpw !== 'on') throw new ContractValidationError(`refusing a durable transaction: full_page_writes is '${String(r.rows[0]?.fpw)}', not 'on'`);
      };
      await assertDurableSettings();
      const exec: PgExecutor = {
        query: async (sql, params) => {
          assertCallerQueryAllowed(sql); // (H1) capability limit: no transaction/session-control escape
          const result = await query(sql, params);
          return { rows: result.rows, rowCount: result.rowCount ?? 0 };
        },
      };
      const result = await abortRace(fn(exec), signal);
      // verify the sentinel BEFORE dispatching OUR COMMIT: if the callback slipped a
      // transaction boundary past the executor guard (e.g. a procedure CALL that
      // commits), the tx-local nonce is gone. Fail closed rather than commit against a
      // different (auto)transaction. Runs BEFORE commitDispatched, so a violation is an
      // ordinary pre-COMMIT failure (rollback + destroy), never ambiguous.
      const continuity = await query(`SELECT pg_catalog.current_setting('${CONTINUITY_GUC}', true) AS n`);
      if (continuity.command !== 'SELECT' || continuity.rows[0]?.n !== nonce) {
        throw new ContractValidationError('transaction continuity violated before COMMIT: the transaction-local scope was lost (a COMMIT/ROLLBACK occurred inside the callback)');
      }
      // (durability authority) FORCE synchronous_commit tx-locally + read it back
      // immediately before COMMIT, so nothing the callback did (e.g. a tx-local
      // set_config('synchronous_commit','off',true)) can lower the durability of THIS
      // commit — the observed CommandComplete then genuinely reflects the chosen level.
      const dur = await query("SELECT pg_catalog.set_config('synchronous_commit', $1, true) AS sc", [this.synchronousCommit]);
      if (dur.command !== 'SELECT' || dur.rows[0]?.sc !== this.synchronousCommit) {
        throw new ContractValidationError(`failed to enforce synchronous_commit=${this.synchronousCommit} before COMMIT`);
      }
      // TOCTOU re-check: fsync/full_page_writes could have been reloaded during the
      // callback. The durability that matters is the one in effect AT COMMIT.
      await assertDurableSettings();
      // from here the COMMIT is in flight; a lost response is AMBIGUOUS, not a failure.
      commitDispatched = true;
      const commit = await query('COMMIT');
      if (commit.command !== 'COMMIT') {
        commitDefinitivelyAborted = commit.command === 'ROLLBACK';
        throw new ContractValidationError(`PostgreSQL COMMIT was not confirmed (command=${commit.command ?? 'missing'})`);
      }
      committed = true;
      // (session-cleanliness authority) the connection is now out of the transaction
      // and about to return to the pool. DISCARD ALL scrubs ANY session state the
      // callback may have left — SET/RESET, prepared statements, LISTEN channels, temp
      // objects, held advisory locks — that a SQL guard cannot fully reason about. If
      // the scrub fails, the connection is NOT provably clean: destroy it and surface
      // PostCommitReleaseError (the data is durably committed).
      try {
        const scrub = await query('DISCARD ALL');
        // node-postgres reports only the first token of the command tag ('DISCARD ALL' -> 'DISCARD').
        if (scrub.command !== 'DISCARD') throw new ContractValidationError(`post-commit DISCARD ALL was not confirmed (command=${scrub.command ?? 'missing'})`);
      } catch (scrubError) {
        destroy();
        throw new PostCommitReleaseError('PostgreSQL committed but the post-commit session scrub (DISCARD ALL) failed; connection destroyed to avoid reusing a poisoned session', { cause: scrubError });
      }
      releaseNormally();
      return result;
    } catch (error) {
      // Only ROLLBACK when COMMIT was never dispatched and the connection is still
      // open; otherwise go straight to destroy so we never unbounded-await.
      if (!committed && !commitDispatched && releaseState === 'open') {
        await boundedRollback(client, this.rollbackTimeoutMs, signal);
      }
      if (releaseState === 'open') destroy();
      // COMMIT dispatched, no confirmed tag, no explicit ROLLBACK tag → ambiguous.
      if (commitDispatched && !committed && !commitDefinitivelyAborted) {
        const cause = disposalError === undefined
          ? error
          : new AggregateError([error, disposalError], 'commit response and connection disposal both failed');
        throw new AmbiguousCommitError(
          'PostgreSQL COMMIT was dispatched but its outcome could not be confirmed; reconcile by idempotency key before retry',
          { cause },
        );
      }
      if (!committed && disposalError !== undefined) {
        throw new ConnectionDisposalError(
          'PostgreSQL transaction failed and the connection could not be disposed',
          { cause: new AggregateError([error, disposalError]) },
        );
      }
      throw error;
    } finally {
      signal.removeEventListener('abort', onAbort);
      if (releaseState === 'open') destroy();
      client.removeListener?.('error', onClientError);
    }
  }
}
