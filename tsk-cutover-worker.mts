/**
 * PR2c child-process crash worker. Performs ONE control-cutover transition against the real control
 * PG (+ real Redis for advanceEpoch) and, on demand, dies by a REAL SIGKILL at a chosen point:
 *   CRASH=before-commit  → SIGKILL inside the transition's tx, BEFORE COMMIT (PG rolls the tx back)
 *   CRASH=after-commit   → run the transition to completion (COMMIT), THEN SIGKILL (tests idempotent resume)
 *   CRASH=none           → run to completion and exit 0 (resume / happy path)
 *
 * All inputs (URLs, keys, receipts) come from a handoff JSON (argv[2]); nothing is invented here.
 * Env: TRANSITION=bind|advance|import|ready|activate, CRASH=..., CRASH_TX_INDEX (1-based; advance=2).
 */
import { readFileSync, writeSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import pg from 'pg';
import { Redis } from 'ioredis';
import {
  NodePostgresTransactor, HaControlFencing, GuardSigner, assertControlSchemaReady, RedisFencingStore,
  type PgExecutor, type GuardKeyResolver, type SourceVerifyKeyResolver, type FenceProof,
} from './packages/server/dist/index.js';

const handoff = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const TRANSITION = process.env['TRANSITION'] ?? '';
const CRASH = process.env['CRASH'] ?? 'none';
const CRASH_TX_INDEX = Number(process.env['CRASH_TX_INDEX'] ?? '1');
const { SID, CMD, TARGET, ctrlKeyId, ctrlSecretHex, pubKeys, frozen, bReceipt, ctrlUrl, redisUrl, claimExpiresAtMs } = handoff;

const ctrlSecret = Buffer.from(ctrlSecretHex, 'hex');
const ctrlSigner = new GuardSigner(ctrlKeyId, ctrlSecret);
const ctrlResolver: GuardKeyResolver = { resolve: (k) => (k === ctrlKeyId ? ctrlSecret : null) };
const pub: Record<string, ReturnType<typeof createPublicKey>> = {};
for (const [kid, pem] of Object.entries(pubKeys as Record<string, string>)) pub[kid] = createPublicKey(pem);
const srcResolver: SourceVerifyKeyResolver = { resolve: (k) => pub[k] ?? null };

// A transactor wrapper that fires a REAL SIGKILL just before COMMIT of the armed tx (crash-before-commit).
// It only counts/arms AFTER arm() — so setup txs (schema attest) neither count toward CRASH_TX_INDEX nor crash.
class CrashingTransactor {
  private n = 0; private live = false;
  constructor(private readonly inner: NodePostgresTransactor) {}
  arm() { this.n = 0; this.live = true; }
  transaction<T>(fn: (exec: PgExecutor) => Promise<T>, opts?: { signal?: AbortSignal; onBeforeCommit?: (exec: PgExecutor) => Promise<void> }): Promise<T> {
    let armed = false;
    if (this.live) { this.n += 1; armed = CRASH === 'before-commit' && this.n === CRASH_TX_INDEX; }
    const idx = this.n;
    return this.inner.transaction(fn, {
      ...opts,
      onBeforeCommit: async (exec) => {
        if (opts?.onBeforeCommit) await opts.onBeforeCommit(exec);
        if (armed) { writeSync(1, `WORKER_CRASH_BEFORE_COMMIT tx#${idx} ${TRANSITION}\n`); process.kill(process.pid, 'SIGKILL'); await new Promise<never>(() => {}); }
      },
    });
  }
}

async function main() {
  const pool = new pg.Pool({ connectionString: ctrlUrl, max: 6 }); pool.on('error', () => {});
  const inner = new NodePostgresTransactor(pool as never);
  const crashTx = new CrashingTransactor(inner);
  const tx = crashTx as unknown as NodePostgresTransactor;
  const ready = await assertControlSchemaReady(tx as never, 'public'); // attest-only; token binds to `tx` (the wrapper)
  crashTx.arm(); // start counting/arming only for the transition's own tx(s)
  const ctl = new HaControlFencing(tx as never, ctrlSigner, ctrlResolver, ready, { minClaimRemainingMs: 5_000 });

  if (TRANSITION === 'bind') {
    await ctl.bindSourceFenced(SID, CMD, TARGET, frozen, srcResolver);
  } else if (TRANSITION === 'advance') {
    const redis = new Redis(redisUrl, { maxRetriesPerRequest: 2, lazyConnect: false }); redis.on('error', () => {});
    const store = new RedisFencingStore(redis, 'tsk:fence:' + SID);
    const proof: FenceProof = { safetyMarginMs: 0, claimExpiresAtMs };
    await ctl.advanceEpoch(SID, CMD, TARGET, 'Bnode', store, proof);
    await redis.quit().catch(() => {});
  } else if (TRANSITION === 'import') {
    await ctl.markImporting(SID, CMD, TARGET);
  } else if (TRANSITION === 'ready') {
    await ctl.markReady(SID, CMD, TARGET, bReceipt, srcResolver);
  } else if (TRANSITION === 'activate') {
    await ctl.activate(SID, CMD, TARGET);
  } else {
    throw new Error('unknown TRANSITION ' + TRANSITION);
  }

  if (CRASH === 'after-commit') { writeSync(1, `WORKER_CRASH_AFTER_COMMIT ${TRANSITION}\n`); process.kill(process.pid, 'SIGKILL'); await new Promise<never>(() => {}); }
  writeSync(1, `WORKER_DONE ${TRANSITION}\n`);
  await pool.end();
  process.exit(0);
}
main().catch((e) => { console.error('WORKER_ERROR', (e as Error).message); process.exit(2); });
