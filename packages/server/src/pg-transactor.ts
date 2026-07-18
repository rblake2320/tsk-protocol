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
// or subvert the transactor's single-transaction guarantee (e.g. a callback that
// COMMITs its own writes then throws would durably persist under an ordinary
// pre-COMMIT error). We reject transaction-control leads and multi-statement text.
const TX_CONTROL_LEAD = /^(begin|start|commit|end|rollback|abort|savepoint|release|discard)\b/i;
const TX_CONTROL_SET = /^(set\s+(transaction\b|session\s+characteristics\b|constraints\b)|prepare\s+transaction\b|(commit|rollback)\s+prepared\b)/i;
/** Strip comments and string/dollar-quoted literals so control-keyword and
 *  statement-separator detection cannot be evaded by hiding them in noise. */
function stripSqlNoise(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')                       // block comments
    .replace(/--[^\n]*/g, ' ')                                // line comments
    .replace(/\$([A-Za-z_]\w*)?\$[\s\S]*?\$\1\$/g, "''")      // dollar-quoted strings
    .replace(/'(?:[^']|'')*'/g, "''");                        // single-quoted strings
}
function assertCallerQueryAllowed(sql: string): void {
  if (typeof sql !== 'string') throw new ContractValidationError('query sql must be a string');
  const stripped = stripSqlNoise(sql).trim();
  const lead = stripped.replace(/^[(\s]+/, ''); // tolerate leading '(' / whitespace
  if (TX_CONTROL_LEAD.test(lead) || TX_CONTROL_SET.test(lead)) {
    throw new ContractValidationError('transaction/session-control statements are not allowed inside a transactor callback');
  }
  const semi = stripped.indexOf(';');
  if (semi >= 0 && stripped.slice(semi + 1).trim().length > 0) {
    throw new ContractValidationError('multiple statements are not allowed inside a transactor callback');
  }
}

export class NodePostgresTransactor implements PgTransactor {
  private readonly statementTimeoutMs: number;
  private readonly transactionTimeoutMs: number;
  private readonly acquireTimeoutMs: number;
  private readonly rollbackTimeoutMs: number;
  private readonly maxSerializationRetries: number;
  private readonly retryBaseDelayMs: number;
  private readonly onDisposalError?: NodePostgresTransactorOptions['onDisposalError'];

  constructor(private readonly pool: NodePostgresPool, opts: NodePostgresTransactorOptions = {}) {
    if (!pool || typeof pool.connect !== 'function') {
      throw new ContractValidationError('pool.connect is required');
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
      const install = await query("SELECT set_config('statement_timeout', $1, true) AS statement_timeout", [String(this.statementTimeoutMs)]);
      if (install.command !== 'SELECT' || typeof install.rows[0]?.statement_timeout !== 'string') {
        throw new ContractValidationError('PostgreSQL statement_timeout setup was not confirmed');
      }
      const readback = await query(
        "SELECT (EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval) * 1000)::bigint::text AS statement_timeout_ms",
      );
      if (readback.command !== 'SELECT' || readback.rows[0]?.statement_timeout_ms !== String(this.statementTimeoutMs)) {
        throw new ContractValidationError('PostgreSQL statement_timeout readback did not match the requested value');
      }
      const exec: PgExecutor = {
        query: async (sql, params) => {
          assertCallerQueryAllowed(sql); // (H1) capability limit: no transaction-control escape
          const result = await query(sql, params);
          return { rows: result.rows, rowCount: result.rowCount ?? 0 };
        },
      };
      const result = await abortRace(fn(exec), signal);
      // from here the COMMIT is in flight; a lost response is AMBIGUOUS, not a failure.
      commitDispatched = true;
      const commit = await query('COMMIT');
      if (commit.command !== 'COMMIT') {
        commitDefinitivelyAborted = commit.command === 'ROLLBACK';
        throw new ContractValidationError(`PostgreSQL COMMIT was not confirmed (command=${commit.command ?? 'missing'})`);
      }
      committed = true;
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
