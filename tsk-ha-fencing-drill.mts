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
  NodePostgresTransactor, type GuardKeyResolver,
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

  console.log(`\n# ${passed} PR2a fencing-foundation checks passed`);
  await pool.end().catch(() => {});
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
