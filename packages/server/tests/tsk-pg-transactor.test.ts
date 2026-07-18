import { describe, expect, it } from 'vitest';

import { ContractValidationError } from '../src/ha-outbox-contract.js';
import {
  NodePostgresTransactor,
  AmbiguousCommitError,
  ConnectionDisposalError,
  PostCommitReleaseError,
  type NodePostgresClient,
  type NodePostgresPool,
  type NodePostgresResult,
} from '../src/pg-transactor.js';

// ── scriptable driver-level fake (a real pg.Pool/PoolClient conforms structurally) ──
interface ClientScript {
  statementTimeoutMs?: number;                 // value echoed by set_config + readback
  begin?: string;                              // BEGIN command tag (default 'BEGIN')
  commit?: string | (() => Promise<never>);    // COMMIT tag, or a thrower (lost response)
  onWork?: (sql: string, params?: unknown[]) => NodePostgresResult | Promise<NodePostgresResult>;
  release?: 'ok' | 'throw';
  rollbackHangs?: boolean;                      // ROLLBACK never resolves (tests cleanup clamping)
  continuityBroken?: boolean;                   // continuity nonce readback differs (tx-local scope lost)
  syncCommitBad?: boolean;                      // synchronous_commit enforcement readback != requested
  discardFails?: boolean;                       // post-commit DISCARD ALL throws
  fsyncOff?: boolean;                           // server fsync reads 'off' (misconfigured server)
  fullPageWritesOff?: boolean;                  // full_page_writes reads 'off'
  durableFlipAfterWork?: boolean;               // durable settings 'on' early, 'off' at the pre-COMMIT re-check
}
class FakeClient implements NodePostgresClient {
  queries: string[] = [];
  releaseCount = 0;
  releasedWith: boolean | Error | undefined = undefined;
  private nonce = '';
  private durableChecks = 0;
  get destroyed(): boolean { return this.releasedWith === true || this.releasedWith instanceof Error; }
  constructor(private readonly script: ClientScript = {}) {}
  async query(sql: string, params?: unknown[]): Promise<NodePostgresResult> {
    this.queries.push(sql);
    const st = String(this.script.statementTimeoutMs ?? 30_000);
    if (sql.startsWith('BEGIN')) return { rows: [], rowCount: null, command: this.script.begin ?? 'BEGIN' };
    if (sql.includes("set_config('statement_timeout'")) return { rows: [{ statement_timeout: st }], rowCount: 1, command: 'SELECT' };
    if (sql.includes("set_config('tsk.tx_continuity'")) { this.nonce = String(params?.[0] ?? ''); return { rows: [{ n: this.nonce }], rowCount: 1, command: 'SELECT' }; }
    if (sql.includes("current_setting('statement_timeout')")) return { rows: [{ statement_timeout_ms: st }], rowCount: 1, command: 'SELECT' };
    if (sql.includes("current_setting('tsk.tx_continuity'")) { return { rows: [{ n: this.script.continuityBroken ? 'BROKEN' : this.nonce }], rowCount: 1, command: 'SELECT' }; }
    if (sql === 'COMMIT') {
      const c = this.script.commit;
      if (typeof c === 'function') return c();
      return { rows: [], rowCount: null, command: c ?? 'COMMIT' };
    }
    if (sql.includes("current_setting('fsync')")) {
      this.durableChecks++;
      const flipped = this.script.durableFlipAfterWork && this.durableChecks >= 2; // reloaded during work
      return { rows: [{ fsync: this.script.fsyncOff || flipped ? 'off' : 'on', fpw: this.script.fullPageWritesOff ? 'off' : 'on' }], rowCount: 1, command: 'SELECT' };
    }
    if (sql.includes("set_config('synchronous_commit'")) { return { rows: [{ sc: this.script.syncCommitBad ? 'off' : String(params?.[0] ?? 'on') }], rowCount: 1, command: 'SELECT' }; }
    if (sql === 'DISCARD ALL') { if (this.script.discardFails) throw new Error('discard failed'); return { rows: [], rowCount: null, command: 'DISCARD' }; }
    if (sql === 'ROLLBACK') { if (this.script.rollbackHangs) return new Promise<never>(() => {}); return { rows: [], rowCount: null, command: 'ROLLBACK' }; }
    if (this.script.onWork) return this.script.onWork(sql, params);
    return { rows: [], rowCount: 1, command: 'SELECT' };
  }
  release(destroy?: boolean | Error): void {
    this.releaseCount++;
    this.releasedWith = destroy;
    if (this.script.release === 'throw') throw new Error('release failed');
  }
  errorListeners: Array<(e: unknown) => void> = [];
  on(event: 'error', listener: (e: unknown) => void): void { if (event === 'error') this.errorListeners.push(listener); }
  removeListener(event: 'error', listener: (e: unknown) => void): void {
    if (event !== 'error') return;
    const i = this.errorListeners.indexOf(listener);
    if (i >= 0) this.errorListeners.splice(i, 1);
  }
  emitError(e: unknown): void { for (const l of [...this.errorListeners]) l(e); }
}
class FakePool implements NodePostgresPool {
  connects = 0;
  constructor(private readonly supplier: (n: number) => Promise<NodePostgresClient>) {}
  connect(): Promise<NodePostgresClient> { return this.supplier(this.connects++); }
}
const poolOf = (...clients: NodePostgresClient[]) => new FakePool((n) => Promise.resolve(clients[Math.min(n, clients.length - 1)]));

describe('NodePostgresTransactor', () => {
  it('commits a serializable, statement-timeout-bounded transaction', async () => {
    const client = new FakeClient({ onWork: () => ({ rows: [{ ok: 1 }], rowCount: 1, command: 'INSERT' }) });
    const tx = new NodePostgresTransactor(poolOf(client));
    const result = await tx.transaction(async (exec) => (await exec.query('INSERT INTO t VALUES (1)')).rows[0]);
    expect(result).toEqual({ ok: 1 });
    expect(client.queries[0]).toBe('BEGIN ISOLATION LEVEL SERIALIZABLE');
    expect(client.queries.some((q) => q.includes("set_config('statement_timeout'"))).toBe(true);
    expect(client.queries.some((q) => q.includes("current_setting('statement_timeout')"))).toBe(true);
    expect(client.queries).toContain('COMMIT');
    expect(client.queries.some((q) => q.includes("set_config('synchronous_commit'"))).toBe(true); // durability forced before COMMIT
    expect(client.queries.at(-1)).toBe('DISCARD ALL'); // session scrubbed after COMMIT, before release
    expect(client.releaseCount).toBe(1);
    expect(client.releasedWith).toBe(false); // returned to the pool, not destroyed
  });

  it('rolls back and destroys the connection on callback failure', async () => {
    const client = new FakeClient();
    const tx = new NodePostgresTransactor(poolOf(client));
    await expect(tx.transaction(async () => { throw new Error('callback boom'); })).rejects.toThrow('callback boom');
    expect(client.queries).toContain('ROLLBACK');
    expect(client.destroyed).toBe(true);
    expect(client.queries).not.toContain('COMMIT');
  });

  it('fails closed (definite abort, not ambiguous) when COMMIT returns a ROLLBACK tag', async () => {
    const client = new FakeClient({ commit: 'ROLLBACK' });
    const tx = new NodePostgresTransactor(poolOf(client));
    const err = await tx.transaction(async () => 'x').catch((e) => e);
    expect(err).toBeInstanceOf(ContractValidationError);
    expect(err).not.toBeInstanceOf(AmbiguousCommitError);
    expect(String(err.message)).toContain('COMMIT was not confirmed');
    expect(client.destroyed).toBe(true);
  });

  it('does NOT retry serialization failures by default (maxSerializationRetries=0)', async () => {
    const client = new FakeClient({ onWork: () => { throw Object.assign(new Error('serialize'), { code: '40001' }); } });
    const pool = poolOf(client);
    const tx = new NodePostgresTransactor(pool);
    await expect(tx.transaction(async (exec) => exec.query('INSERT INTO t VALUES (1)'))).rejects.toMatchObject({ code: '40001' });
    expect(pool.connects).toBe(1);
    expect(client.destroyed).toBe(true);
  });

  it('retries only bounded serialization failures when explicitly enabled', async () => {
    const failing = new FakeClient({ onWork: () => { throw Object.assign(new Error('serialize'), { code: '40001' }); } });
    const ok = new FakeClient({ onWork: () => ({ rows: [{ n: 2 }], rowCount: 1, command: 'INSERT' }) });
    const pool = poolOf(failing, ok);
    const tx = new NodePostgresTransactor(pool, { maxSerializationRetries: 2, retryBaseDelayMs: 1 });
    const result = await tx.transaction(async (exec) => (await exec.query('INSERT INTO t VALUES (1)')).rows[0]);
    expect(result).toEqual({ n: 2 });
    expect(pool.connects).toBe(2);          // fresh connection per attempt
    expect(failing.destroyed).toBe(true);   // the poisoned first connection was discarded
    expect(ok.releasedWith).toBe(false);
  });

  it('bounds acquisition and destroys a late connection', async () => {
    const late = new FakeClient();
    const pool = new FakePool(() => new Promise((resolve) => setTimeout(() => resolve(late), 60)));
    const tx = new NodePostgresTransactor(pool, { acquireTimeoutMs: 20 });
    await expect(tx.transaction(async () => 'x')).rejects.toThrow(/acquisition timed out/);
    await new Promise((r) => setTimeout(r, 80)); // let the late connection arrive
    expect(late.destroyed).toBe(true);
    expect(late.queries).toHaveLength(0);       // never used
  });

  it('aborts and destroys an active connection when the caller signal fires mid-callback', async () => {
    const controller = new AbortController();
    const client = new FakeClient({ onWork: () => { controller.abort(); return new Promise<never>(() => {}); } }); // abort exactly when the work query runs
    const tx = new NodePostgresTransactor(poolOf(client));
    await expect(tx.transaction(async (exec) => exec.query('SELECT 1'), { signal: controller.signal })).rejects.toThrow();
    expect(client.destroyed).toBe(true);
  });

  it('requires a confirmed BEGIN before exposing the executor', async () => {
    let callbackInvoked = false;
    const client = new FakeClient({ begin: 'ROLLBACK' }); // BEGIN not confirmed
    const tx = new NodePostgresTransactor(poolOf(client));
    await expect(tx.transaction(async () => { callbackInvoked = true; })).rejects.toThrow(/BEGIN was not confirmed/);
    expect(callbackInvoked).toBe(false);
    expect(client.destroyed).toBe(true);
  });

  it('requires the statement_timeout readback to match before exposing the executor', async () => {
    let callbackInvoked = false;
    const client = new FakeClient({ statementTimeoutMs: 999 }); // echoes a value != the configured 30000
    const tx = new NodePostgresTransactor(poolOf(client));
    await expect(tx.transaction(async () => { callbackInvoked = true; })).rejects.toThrow(/statement_timeout readback did not match/);
    expect(callbackInvoked).toBe(false);
    expect(client.destroyed).toBe(true);
  });

  it('removes the caller abort listener after both success and a retry', async () => {
    const ctrl = new AbortController();
    let adds = 0, removes = 0;
    const sig = ctrl.signal;
    const add = sig.addEventListener.bind(sig);
    const remove = sig.removeEventListener.bind(sig);
    (sig as unknown as { addEventListener: typeof add }).addEventListener = ((type: string, ...rest: unknown[]) => { if (type === 'abort') adds++; return (add as (...a: unknown[]) => void)(type, ...rest); }) as typeof add;
    (sig as unknown as { removeEventListener: typeof remove }).removeEventListener = ((type: string, ...rest: unknown[]) => { if (type === 'abort') removes++; return (remove as (...a: unknown[]) => void)(type, ...rest); }) as typeof remove;

    const failing = new FakeClient({ onWork: () => { throw Object.assign(new Error('serialize'), { code: '40001' }); } });
    const ok = new FakeClient();
    const tx = new NodePostgresTransactor(poolOf(failing, ok), { maxSerializationRetries: 1, retryBaseDelayMs: 1 });
    await tx.transaction(async (exec) => exec.query('INSERT INTO t VALUES (1)'), { signal: sig });
    expect(adds).toBeGreaterThanOrEqual(1);
    expect(removes).toBe(adds); // balanced across the retry loop
  });

  it('surfaces a normal-release failure as PostCommitReleaseError without a second release attempt', async () => {
    const client = new FakeClient({ release: 'throw' });
    const tx = new NodePostgresTransactor(poolOf(client));
    const err = await tx.transaction(async () => 'committed').catch((e) => e);
    expect(err).toBeInstanceOf(PostCommitReleaseError);
    expect(err.committed).toBe(true);           // the data IS durable
    expect(client.releaseCount).toBe(1);        // exactly one release attempt
  });

  it('reports a lost COMMIT response as non-retryable outcome ambiguity', async () => {
    const client = new FakeClient({ commit: () => Promise.reject(new Error('socket hang up')) });
    const pool = poolOf(client);
    const tx = new NodePostgresTransactor(pool, { maxSerializationRetries: 3, retryBaseDelayMs: 1 });
    const err = await tx.transaction(async () => 'x').catch((e) => e);
    expect(err).toBeInstanceOf(AmbiguousCommitError);
    expect(err.committed).toBe('unknown');
    expect(pool.connects).toBe(1);              // NEVER auto-retried
    expect(client.destroyed).toBe(true);
  });

  it('does not start a query retained by a callback after abort', async () => {
    const controller = new AbortController();
    const client = new FakeClient();
    const tx = new NodePostgresTransactor(poolOf(client));
    await expect(tx.transaction(async (exec) => {
      controller.abort();                       // (caller-side) — but demonstrate the retained-exec guard:
      await exec.query('SELECT leaked');        // must reject on the aborted internal signal, not hit the client
    }, { signal: controller.signal })).rejects.toThrow();
    expect(client.queries).not.toContain('SELECT leaked');
    expect(client.destroyed).toBe(true);
  });

  it('attempts destroy exactly once and surfaces disposal failure as ConnectionDisposalError', async () => {
    const client = new FakeClient({ release: 'throw' });
    const tx = new NodePostgresTransactor(poolOf(client));
    const err = await tx.transaction(async () => { throw new Error('callback boom'); }).catch((e) => e);
    expect(err).toBeInstanceOf(ConnectionDisposalError);
    expect(err.committed).toBe(false);
    expect(client.releaseCount).toBe(1);        // no second release after a failed destroy
  });

  it('consumes an asynchronously-rejecting disposal observer without changing the outcome', async () => {
    let observed = false;
    const client = new FakeClient({ release: 'throw' });
    const tx = new NodePostgresTransactor(poolOf(client), {
      onDisposalError: () => { observed = true; return Promise.reject(new Error('telemetry down')); },
    });
    const err = await tx.transaction(async () => { throw new Error('callback boom'); }).catch((e) => e);
    expect(observed).toBe(true);
    expect(err).toBeInstanceOf(ConnectionDisposalError); // outcome unchanged by telemetry failure
  });

  it('(H1) capability-limits the callback executor: transaction/session control is blocked and rolls back', async () => {
    const evils = [
      'COMMIT', 'ROLLBACK', 'BEGIN', 'END', 'SAVEPOINT s1', 'RELEASE s1', 'DISCARD ALL',
      'SET TRANSACTION ISOLATION LEVEL READ COMMITTED',
      // session poisoning of a POOLED connection:
      'SET ROLE evil', 'SET SESSION AUTHORIZATION bob', "SET application_name = 'poison'", 'RESET ALL',
      'PREPARE TRANSACTION \'gid\'',
      // session-control smuggled through a SELECT (session-level set_config):
      "SELECT set_config('role', 'evil', false)", "SELECT set_config('search_path', 'pg_temp,pg_catalog', false)",
      // comment / separator evasion, incl. PostgreSQL NESTED block comments:
      '  /* sneaky */ commit', '/* outer /* inner */ */ COMMIT', '--x\nCOMMIT', 'INSERT INTO t VALUES (1); COMMIT',
    ];
    for (const evil of evils) {
      const client = new FakeClient();
      const tx = new NodePostgresTransactor(poolOf(client));
      const err = await tx.transaction(async (exec) => { await exec.query(evil); }).catch((e) => e);
      expect(err, `must reject: ${evil}`).toBeInstanceOf(ContractValidationError);
      expect(client.queries).not.toContain('COMMIT'); // the transactor never reached its own COMMIT
      expect(client.destroyed).toBe(true);            // and the connection is discarded
    }
  });

  it('(H1 backstop) the pre-COMMIT continuity sentinel fails closed when the tx-local scope is lost', async () => {
    // models a callback that lost the transaction by a path the static guard cannot
    // see: the tx-local continuity nonce no longer matches, so the transactor must
    // fail closed and NOT commit — even though the callback query itself was allowed.
    const client = new FakeClient({ continuityBroken: true });
    const tx = new NodePostgresTransactor(poolOf(client));
    const err = await tx.transaction(async (exec) => { await exec.query('SELECT 1'); }).catch((e) => e);
    expect(err).toBeInstanceOf(ContractValidationError);
    expect(String(err.message)).toContain('continuity');
    expect(client.queries).not.toContain('COMMIT'); // our COMMIT was never dispatched
    expect(client.destroyed).toBe(true);
  });

  it('(H1) allows ordinary data + read statements through the guarded executor', async () => {
    const client = new FakeClient({ onWork: () => ({ rows: [{ ok: 1 }], rowCount: 1, command: 'SELECT' }) });
    const tx = new NodePostgresTransactor(poolOf(client));
    await tx.transaction(async (exec) => {
      await exec.query('SELECT set_config($1, $2, true)', ['search_path', 'public']);
      await exec.query('SHOW transaction_isolation');
      await exec.query('INSERT INTO t VALUES (1)');
      await exec.query('SELECT 1; '); // a trailing statement separator is fine
    });
    expect(client.queries).toContain('COMMIT'); // committed normally
    expect(client.queries.at(-1)).toBe('DISCARD ALL');
  });

  it('(durability authority) forces synchronous_commit before COMMIT and fails closed if the readback does not match', async () => {
    const client = new FakeClient({ syncCommitBad: true });
    const tx = new NodePostgresTransactor(poolOf(client));
    const err = await tx.transaction(async () => 'x').catch((e) => e);
    expect(err).toBeInstanceOf(ContractValidationError);
    expect(String(err.message)).toContain('synchronous_commit');
    expect(client.queries).not.toContain('COMMIT'); // enforced BEFORE commit, so no commit
    expect(client.destroyed).toBe(true);
  });

  it('(session-cleanliness authority) DISCARD ALL failure after a durable commit -> PostCommitReleaseError + destroy', async () => {
    const client = new FakeClient({ discardFails: true });
    const tx = new NodePostgresTransactor(poolOf(client));
    const err = await tx.transaction(async () => 'x').catch((e) => e);
    expect(err).toBeInstanceOf(PostCommitReleaseError);
    expect(err.committed).toBe(true);              // the data IS durable
    expect(client.queries).toContain('COMMIT');    // commit happened
    expect(client.destroyed).toBe(true);           // but the un-scrubbed connection is discarded
  });

  it('rejects an unsafe synchronousCommit option (including durability-lowering off)', () => {
    for (const bad of ['maybe', 'off']) {
      expect(() => new NodePostgresTransactor(poolOf(new FakeClient()), { synchronousCommit: bad as unknown as 'on' }), bad).toThrow(ContractValidationError);
    }
  });

  it('(durability precondition) refuses to run when fsync or full_page_writes is off, before the callback', async () => {
    for (const script of [{ fsyncOff: true }, { fullPageWritesOff: true }]) {
      let callbackInvoked = false;
      const client = new FakeClient(script);
      const tx = new NodePostgresTransactor(poolOf(client));
      const err = await tx.transaction(async () => { callbackInvoked = true; }).catch((e) => e);
      expect(err).toBeInstanceOf(ContractValidationError);
      expect(String(err.message)).toMatch(/fsync|full_page_writes/);
      expect(callbackInvoked).toBe(false); // rejected before any work
      expect(client.queries).not.toContain('COMMIT');
      expect(client.destroyed).toBe(true);
    }
  });

  it('(durability TOCTOU) re-checks durable settings before COMMIT; a mid-work reload fails closed', async () => {
    // fsync/full_page_writes are SIGHUP-reloadable: 'on' at the early check, 'off' by the
    // pre-COMMIT re-check. The transactor must NOT commit.
    const client = new FakeClient({ durableFlipAfterWork: true });
    const tx = new NodePostgresTransactor(poolOf(client));
    const err = await tx.transaction(async (exec) => { await exec.query('INSERT INTO t VALUES (1)'); }).catch((e) => e);
    expect(err).toBeInstanceOf(ContractValidationError);
    expect(String(err.message)).toContain('fsync');
    expect(client.queries).not.toContain('COMMIT'); // re-check runs before COMMIT
    expect(client.destroyed).toBe(true);
  });

  it('(H2) clamps cleanup rollback to the transaction deadline, not the full rollback budget', async () => {
    const client = new FakeClient({ rollbackHangs: true, onWork: () => { throw new Error('callback boom'); } });
    const tx = new NodePostgresTransactor(poolOf(client), { transactionTimeoutMs: 150, rollbackTimeoutMs: 5_000 });
    const t0 = Date.now();
    await tx.transaction(async (exec) => exec.query('INSERT INTO t VALUES (1)')).catch(() => {});
    const ms = Date.now() - t0;
    expect(ms).toBeLessThan(1_500);   // bounded by the 150ms deadline, NOT the 5000ms rollback budget
    expect(client.destroyed).toBe(true);
  });

  it('owns the checked-out client error event for the tx lifetime and swallows a mid-tx connection error', async () => {
    const client = new FakeClient();
    const tx = new NodePostgresTransactor(poolOf(client));
    let duringCount = 0;
    await tx.transaction(async () => {
      duringCount = client.errorListeners.length;
      client.emitError(new Error('mid-tx socket blip')); // must NOT throw / crash — the listener swallows it
    });
    expect(duringCount).toBe(1);                    // attached while checked out
    expect(client.errorListeners).toHaveLength(0);  // released afterward (no listener leak)
  });

  it('exports the public outcome errors and the transactor from the module', () => {
    expect(typeof NodePostgresTransactor).toBe('function');
    expect(typeof AmbiguousCommitError).toBe('function');
    expect(typeof PostCommitReleaseError).toBe('function');
    expect(typeof ConnectionDisposalError).toBe('function');
  });

  it('rejects unsafe timeout / retry / observer configuration', () => {
    const pool = poolOf(new FakeClient());
    expect(() => new NodePostgresTransactor(pool, { statementTimeoutMs: 0 })).toThrow(ContractValidationError);
    expect(() => new NodePostgresTransactor(pool, { transactionTimeoutMs: -1 })).toThrow(ContractValidationError);
    expect(() => new NodePostgresTransactor(pool, { maxSerializationRetries: 101 })).toThrow(ContractValidationError);
    expect(() => new NodePostgresTransactor(pool, { retryBaseDelayMs: 0 })).toThrow(ContractValidationError);
    expect(() => new NodePostgresTransactor(pool, { statementTimeoutMs: 1.5 })).toThrow(ContractValidationError);
    expect(() => new NodePostgresTransactor(pool, { onDisposalError: 'nope' as unknown as () => void })).toThrow(ContractValidationError);
    expect(() => new NodePostgresTransactor({} as NodePostgresPool)).toThrow(/pool.connect is required/);
  });
});
