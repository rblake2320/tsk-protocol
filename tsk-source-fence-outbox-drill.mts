/**
 * PR2b-0 (M2) — NON-BYPASSABLE source lease gate through a real PgTskDurableOutbox, real PG16.
 * Proves: (a) with sourceLeaseGate configured, every append asserts the lease IN the append tx —
 * an active lease at the fence epoch appends, a revoked / wrong-epoch / expired lease fails closed
 * and NOTHING is committed; (b) the transactor PRE-COMMIT re-check catches a tx that passes the
 * per-append gate then STALLS past the signed deadline (slow signer) → clean rollback, no row.
 * Env: TSK_TEST_SOURCE_PG_URL (or TSK_TEST_POSTGRES_URL).
 *
 * BOUNDED / MECHANISM-ONLY. #10 stays OPEN. SourceFrozenReceipt + external witness + full A/B/control
 * crash drills land in later PR2b-0 commits.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import pg from 'pg';
import {
  TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA, provisionSchemaVersion,
  PgTskDurableOutbox, NodePostgresTransactor, ContractValidationError,
  signLeaseGrant, installLeaseGrant, SourceFenceQuarantineError,
  type PgTransactor, type StreamHeadSigner, type HotpMutationSanitizer, type SanitizedMutation,
  type TskHotpMutation, type GuardKeyResolver, type BareLeaseGrant,
} from './packages/server/dist/index.js';

const URL = process.env['TSK_TEST_SOURCE_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
if (!URL) throw new Error('TSK_TEST_SOURCE_PG_URL (source PG16) is required');
const SCHEMA = 'public';
const GUARD_KEY = 'guard-1';
const guardSecret = Buffer.alloc(32, 0x2b);
const resolver: GuardKeyResolver = { resolve: (kid) => (kid === GUARD_KEY ? guardSecret : null) };
const HOUR = 3_600_000;

const { privateKey } = generateKeyPairSync('ed25519');
const mkSigner = (delayMs = 0): StreamHeadSigner => ({ keyId: 'k1', alg: 'ed25519', async sign(d) { if (delayMs) await new Promise((r) => setTimeout(r, delayMs)); return edSign(null, Buffer.from(d, 'utf8'), privateKey).toString('base64url'); } });
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof raw.tumblerId !== 'string' || !Number.isInteger(raw.counter)) throw new ContractValidationError('bad'); return { tumblerId: raw.tumblerId, counter: raw.counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object') throw new ContractValidationError('unsanitized'); },
};

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK PR2b-0 non-bypassable source-gate outbox drill (real PG16)');
  const pool = new pg.Pool({ connectionString: URL, max: 4 }); pool.on('error', () => {});
  const serial = new NodePostgresTransactor(pool as never) as unknown as PgTransactor;
  await pool.query('DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, tsk_source_lease_history CASCADE');
  for (const s of TSK_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  for (const s of TSK_SOURCE_LEASE_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  const READY = await provisionSchemaVersion(serial, SCHEMA);

  const nowMs = async () => Number((await pool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  const seqOf = async (sid: string) => Number((await pool.query('SELECT sequence FROM tsk_outbox_source_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence);
  async function provision(sid: string, fence = 0) {
    await pool.query('INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1,$2)', [sid, fence]);
    await pool.query('INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [sid, 'e1']);
  }
  const cid = (prefix: string, sid: string) => `${prefix}-${sid.replace(/[^A-Za-z0-9:._-]/g, '_')}`;
  async function lease(sid: string, over: Partial<BareLeaseGrant>) {
    const g = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'active', holderNodeId: 'A', leaseId: 'l1', commandId: cid('grant', sid), leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 1, prevGrantDigest: null, ...over });
    await serial.transaction((exec) => installLeaseGrant(exec, resolver, g));
    return g;
  }
  const gate = { resolver, controlToASkewBoundMs: 0 };
  const mkOutbox = (sid: string, delayMs = 0) => new PgTskDurableOutbox(serial, READY, { streamId: sid, sanitizer, signer: mkSigner(delayMs), maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation', sourceLeaseGate: gate });
  const append = (ob: PgTskDurableOutbox, sid: string, fence: bigint, counter: number) => ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { tumblerId: 'T1', counter }, fenceToken: fence }));

  await check('append SUCCEEDS with an active lease at the fence epoch', async () => {
    const sid = 'tsk:ob:ok/v1'; await provision(sid); await lease(sid, {});
    const ob = mkOutbox(sid);
    await append(ob, sid, 0n, 10); await append(ob, sid, 0n, 11);
    assert.equal(await seqOf(sid), 2);
  });

  await check('append FAILS in-tx (nothing committed) when the lease is REVOKED', async () => {
    const sid = 'tsk:ob:revoked/v1'; await provision(sid); const g = await lease(sid, {});
    const ob = mkOutbox(sid);
    await append(ob, sid, 0n, 1); // ok while active
    const rev = signLeaseGrant(GUARD_KEY, guardSecret, { streamId: sid, leaseEpoch: 0, leaseStatus: 'revoked', holderNodeId: 'A', leaseId: 'l1', commandId: cid('revoke', sid), leaseExpiresAtMs: (await nowMs()) + HOUR, leaseGrantSeq: 2, prevGrantDigest: g.grantDigest });
    await serial.transaction((exec) => installLeaseGrant(exec, resolver, rev));
    const before = await seqOf(sid);
    await assert.rejects(() => append(ob, sid, 0n, 2), SourceFenceQuarantineError);
    assert.equal(await seqOf(sid), before, 'no row committed after revoke');
  });

  await check('append FAILS when the lease epoch != the fence epoch (stale writer)', async () => {
    const sid = 'tsk:ob:epoch/v1'; await provision(sid, 0); await lease(sid, { leaseEpoch: 1 }); // lease at epoch 1, fence at 0
    const ob = mkOutbox(sid);
    await assert.rejects(() => append(ob, sid, 0n, 1), /epoch .* != expected/);
    assert.equal(await seqOf(sid), 0);
  });

  await check('PRE-COMMIT re-check catches a tx that stalls past the signed deadline (slow signer) → rollback, no row', async () => {
    const sid = 'tsk:ob:stall/v1'; await provision(sid);
    await lease(sid, { leaseExpiresAtMs: (await nowMs()) + 40 }); // deadline ~40ms out
    const ob = mkOutbox(sid, 150); // signer stalls 150ms > 40ms deadline
    await assert.rejects(() => append(ob, sid, 0n, 1), /deadline elapsed/);
    assert.equal(await seqOf(sid), 0, 'the stalled append was rolled back by the pre-commit re-check');
  });

  console.log(`\n# ${passed} PR2b-0 non-bypassable source-gate outbox checks passed`);
  await pool.end().catch(() => {});
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
