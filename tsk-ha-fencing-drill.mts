/**
 * PR2a — HA fencing foundation drill (control DB). Validates HaControlFencing against a
 * REAL PostgreSQL 16 control DB: the signed forward-CAS provisioning saga, the epoch
 * witness, and the monotonic signed lease grant/renew/revoke + tamper detection.
 *
 * BOUNDED / MECHANISM-ONLY — NO split-brain/HA claim. #10 stays OPEN. Redis coordination,
 * the fence-advance saga, and the crash-at-each-step matrix land in subsequent PR2a commits.
 */
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  HA_CONTROL_PG_SCHEMA, HA_CONTROL_TABLES, HaControlFencing, GuardSigner,
  NodePostgresTransactor, MemoryFencingStore, FenceAuthorityQuarantineError,
  type GuardKeyResolver, type FenceProof,
} from './packages/server/dist/index.js';

const URL = process.env['TSK_TEST_CONTROL_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
if (!URL) throw new Error('TSK_TEST_CONTROL_PG_URL (control PG16) is required');
const { Pool } = pg;
const SID = 'tsk:pair:pr2a/v1';

const GUARD_KEY = 'guard-1';
const guardSecret = Buffer.alloc(32, 0x2b);
const resolver: GuardKeyResolver = { resolve: (kid) => (kid === GUARD_KEY ? guardSecret : null) };
const signer = new GuardSigner(GUARD_KEY, guardSecret);

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK PR2a HA fencing-foundation drill (real control PG16)');
  const pool = new Pool({ connectionString: URL, max: 4 }); pool.on('error', () => {});
  await pool.query(`DROP TABLE IF EXISTS ${HA_CONTROL_TABLES.join(', ')} CASCADE`);
  for (const s of HA_CONTROL_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  const ctl = new HaControlFencing(new NodePostgresTransactor(pool as never), signer, resolver);

  const histCount = async (t: string) => Number((await pool.query(`SELECT count(*)::int AS n FROM ${t} WHERE stream_id=$1`, [SID])).rows[0].n);

  await check('provisioning saga reaches provisioned via 3 signed forward-CAS transitions + witness genesis', async () => {
    const st = await ctl.provision(SID, 'genesis-nonce-abc');
    assert.equal(st.state, 'provisioned');
    assert.equal(st.stateSeq, 3);
    assert.equal(await histCount('tsk_ha_provisioning_history'), 3, 'intent+incomplete+provisioned history rows');
    const w = await ctl.witness(SID);
    assert.equal(w?.epoch, 0);
    assert.equal(w?.state, 'provisioned');
  });

  await check('provisioning is idempotent (re-run does not add transitions)', async () => {
    const st = await ctl.provision(SID, 'genesis-nonce-abc');
    assert.equal(st.state, 'provisioned');
    assert.equal(await histCount('tsk_ha_provisioning_history'), 3, 'no extra transitions on re-provision');
  });

  await check('lease: grant -> renew -> revoke are signed monotonic transitions (multi-row history)', async () => {
    const now = Date.now();
    const g1 = await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 30_000 });
    assert.equal(g1.grantSeq, 1); assert.equal(g1.status, 'active');
    const g2 = await ctl.writeLease({ streamId: SID, leaseId: 'l2', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 60_000 });
    assert.equal(g2.grantSeq, 2); // renewal advances grant_seq
    const g3 = await ctl.writeLease({ streamId: SID, leaseId: 'l2', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: now + 60_000 });
    assert.equal(g3.grantSeq, 3); assert.equal(g3.status, 'revoked');
    assert.equal(await histCount('tsk_ha_lease_history'), 3, 'grant/renew/revoke history rows (explicit history takes >1)');
    const cur = await ctl.lease(SID);
    assert.equal(cur?.grantSeq, 3); assert.equal(cur?.status, 'revoked');
  });

  await check('tamper detection: a corrupted head signature fails the guard verify on read', async () => {
    await pool.query("UPDATE tsk_ha_lease_head SET guard_signature = 'AAAA' WHERE stream_id=$1", [SID]);
    await assert.rejects(() => ctl.lease(SID), /guard signature/);
    // restore a valid head so cleanup is clean
    await pool.query('DELETE FROM tsk_ha_lease_head WHERE stream_id=$1', [SID]);
  });

  // ── M2: fence-advance saga (Redis coordinator via MemoryFencingStore; real Redis next milestone) ──
  const SID2 = 'tsk:pair:pr2a-advance/v1';
  await pool.query('DELETE FROM tsk_ha_cutover_history WHERE stream_id=$1', [SID2]);

  await check('fence-advance: provision -> grant -> intent -> revoke+expiry -> advanceEpoch bumps witness 0->1 and Redis-claims', async () => {
    await ctl.provision(SID2, 'genesis-2');
    const store = new MemoryFencingStore();
    await store.claim({ nodeId: 'A', fenceEpoch: 0, expiresAt: Date.now() + 60_000, commandId: 'genesis' }); // epoch-0 genesis claim
    const now = Date.now();
    await ctl.writeLease({ streamId: SID2, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 60_000 });
    await ctl.beginPromotionIntent(SID2, 'c1', 1);
    const proof: FenceProof = { controlNowMs: now + 61_000, safetyMarginMs: 0, claimExpiresAtMs: now + 120_000 };
    // A not proven fenced yet (lease still active) -> quarantine
    await assert.rejects(() => ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof), FenceAuthorityQuarantineError);
    await ctl.writeLease({ streamId: SID2, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: now + 60_000 });
    // revoked but not past expiry -> still quarantine
    await assert.rejects(() => ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, { ...proof, controlNowMs: now }), FenceAuthorityQuarantineError);
    // revoked AND past expiry+margin -> advance
    const res = await ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof);
    assert.equal(res.epoch, 1); assert.equal(res.fenceToken, '1');
    assert.equal((await ctl.witness(SID2))?.epoch, 1, 'witness advanced 0->1');
    assert.equal((await store.current())?.fenceEpoch, 1, 'Redis claimed epoch 1');
  });

  await check('Redis-loss quarantine: an absent Redis authority after provisioning fails closed', async () => {
    const SID3 = 'tsk:pair:pr2a-redisloss/v1';
    await ctl.provision(SID3, 'genesis-3');       // witness provisioned at epoch 0
    await ctl.beginPromotionIntent(SID3, 'cr', 1);
    const empty = new MemoryFencingStore();       // current() === null => Redis lost after provisioning
    const now = Date.now();
    await assert.rejects(
      () => ctl.advanceEpoch(SID3, 'cr', 1, 'B', empty, { controlNowMs: now, safetyMarginMs: 0, claimExpiresAtMs: now + 60_000 }),
      /Redis fence authority is absent/,
    );
  });

  await check('one active intent per stream: a different commandId is denied while an intent is in-flight (same is idempotent)', async () => {
    const SID4 = 'tsk:pair:pr2a-intent/v1';
    await ctl.provision(SID4, 'genesis-4');
    await ctl.beginPromotionIntent(SID4, 'c1', 1); // PREPARING (in-flight, not terminal)
    await assert.rejects(() => ctl.beginPromotionIntent(SID4, 'c2', 1), /in-flight intent/);
    const same = await ctl.beginPromotionIntent(SID4, 'c1', 1);
    assert.equal(same.phase, 'PREPARING');
  });

  console.log(`\n# ${passed} PR2a fencing-foundation checks passed`);
  await pool.end().catch(() => {});
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
