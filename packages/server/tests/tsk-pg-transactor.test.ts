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
}
class FakeClient implements NodePostgresClient {
  queries: string[] = [];
  releaseCount = 0;
  releasedWith: boolean | Error | undefined = undefined;
  get destroyed(): boolean { return this.releasedWith === true || this.releasedWith instanceof Error; }
  constructor(private readonly script: ClientScript = {}) {}
  async query(sql: string, params?: unknown[]): Promise<NodePostgresResult> {
    this.queries.push(sql);
    const st = String(this.script.statementTimeoutMs ?? 30_000);
    if (sql.startsWith('BEGIN')) return { rows: [], rowCount: null, command: this.script.begin ?? 'BEGIN' };
    if (sql.includes("set_config('statement_timeout'")) return { rows: [{ statement_timeout: st }], rowCount: 1, command: 'SELECT' };
    if (sql.includes("current_setting('statement_timeout')")) return { rows: [{ statement_timeout_ms: st }], rowCount: 1, command: 'SELECT' };
    if (sql === 'COMMIT') {
      const c = this.script.commit;
      if (typeof c === 'function') return c();
      return { rows: [], rowCount: null, command: c ?? 'COMMIT' };
    }
    if (sql === 'ROLLBACK') return { rows: [], rowCount: null, command: 'ROLLBACK' };
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
    expect(client.queries.at(-1)).toBe('COMMIT');
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
