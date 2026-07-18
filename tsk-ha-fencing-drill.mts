/**
 * PR2a — HA fencing FOUNDATION drill (control DB). Validates HaControlFencing against a
 * REAL PostgreSQL 16 control DB: schema attestation + drift, the signed per-step provisioning
 * saga (with a Redis epoch-0 genesis claim), the SIGNED epoch witness, the monotonic
 * command-bound lease, replay-over-head / tamper / rotation defenses, the control-clock
 * fence-advance saga with a strict signed evidence payload + freeze-under-PREPARING + idempotent
 * retry, Redis-loss quarantine, one-active-intent, target==witness+1, integer-range rejection,
 * and a BARRIER-controlled concurrent-intent race (atomic admission — not a timing test).
 *
 * BOUNDED / MECHANISM-ONLY — NO split-brain/HA/uptime claim. #10 stays OPEN. `MemoryFencingStore`
 * is an in-process reference, NOT a fault-tolerant Redis. The full 3-node Redis Sentinel/quorum +
 * child-process SIGKILL crash matrix + measured RPO/RTO remain later PR2b/PR2c milestones.
 */
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  HA_CONTROL_PG_SCHEMA, HA_CONTROL_TABLES, HaControlFencing, GuardSigner,
  NodePostgresTransactor, MemoryFencingStore, FenceAuthorityQuarantineError,
  provisionControlSchema, assertControlSchemaReady,
  type GuardKeyResolver, type FenceProof, type ControlSchemaReadyToken,
} from './packages/server/dist/index.js';

const URL = process.env['TSK_TEST_CONTROL_PG_URL'] ?? process.env['TSK_TEST_POSTGRES_URL'];
if (!URL) throw new Error('TSK_TEST_CONTROL_PG_URL (control PG16) is required');
const { Pool } = pg;

const GUARD_KEY = 'guard-1';
const guardSecret = Buffer.alloc(32, 0x2b);
const resolver: GuardKeyResolver = { resolve: (kid) => (kid === GUARD_KEY ? guardSecret : null) };
const revokedResolver: GuardKeyResolver = { resolve: () => null };
const signer = new GuardSigner(GUARD_KEY, guardSecret);
const HOUR = 3_600_000;

let passed = 0;
async function check(name: string, fn: () => Promise<void>) { await fn(); passed++; console.log(`  ok - ${name}`); }

async function main() {
  console.log('# TSK PR2a HA fencing-foundation drill (real control PG16)');
  const pool = new Pool({ connectionString: URL, max: 6 }); pool.on('error', () => {});
  await pool.query(`DROP TABLE IF EXISTS ${HA_CONTROL_TABLES.join(', ')} CASCADE`);
  for (const s of HA_CONTROL_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await pool.query(s);
  const tx = new NodePostgresTransactor(pool as never);

  const stores = new Map<string, MemoryFencingStore>();
  const storeFor = (sid: string) => { let s = stores.get(sid); if (!s) { s = new MemoryFencingStore(); stores.set(sid, s); } return s; };
  const nowMs = async () => Number((await pool.query('SELECT (extract(epoch from clock_timestamp())*1000)::bigint AS ms')).rows[0].ms);
  const histCount = async (t: string, sid: string) => Number((await pool.query(`SELECT count(*)::int AS n FROM ${t} WHERE stream_id=$1`, [sid])).rows[0].n);
  const prov = async (ctl: HaControlFencing, sid: string, marker: string) => ctl.provision(sid, marker, storeFor(sid), 'A', (await nowMs()) + HOUR);

  // ── schema attestation + readiness capability + drift detection ──────────────
  let ready: ControlSchemaReadyToken = await provisionControlSchema(tx as never, 'public');
  let ctl = new HaControlFencing(tx as never, signer, resolver, ready);

  await check('schema attestation: a foreign/forged readiness token is rejected', async () => {
    const forged = Object.freeze({}) as unknown as ControlSchemaReadyToken;
    assert.throws(() => new HaControlFencing(tx as never, signer, resolver, forged), /forged or foreign token/);
  });

  await check('schema attestation: a post-provision catalog drift fails readiness closed', async () => {
    await pool.query('ALTER TABLE tsk_ha_lease_head ADD COLUMN drift_col int');
    await assert.rejects(() => assertControlSchemaReady(tx as never, 'public'), /drift/);
    await pool.query('ALTER TABLE tsk_ha_lease_head DROP COLUMN drift_col');
    await assertControlSchemaReady(tx as never, 'public'); // clean again
  });

  // ── signed per-step provisioning saga + Redis epoch-0 genesis ───────────────
  const SID = 'tsk:pair:pr2a/v1';
  await check('provisioning saga: 3 signed forward-CAS steps + signed witness genesis + Redis epoch-0', async () => {
    const st = await prov(ctl, SID, 'genesis-nonce-abc');
    assert.equal(st.state, 'provisioned'); assert.equal(st.stateSeq, 3);
    assert.equal(await histCount('tsk_ha_provisioning_history', SID), 3);
    assert.equal(await histCount('tsk_ha_epoch_witness_history', SID), 2, 'witness genesis incomplete + provisioned');
    const w = await ctl.witness(SID);
    assert.equal(w?.epoch, 0); assert.equal(w?.state, 'provisioned');
    assert.equal((await storeFor(SID).current())?.fenceEpoch, 0, 'Redis epoch-0 genesis claim present');
  });

  await check('provisioning is idempotent + rejects a conflicting genesis marker', async () => {
    const st = await prov(ctl, SID, 'genesis-nonce-abc');
    assert.equal(st.state, 'provisioned');
    assert.equal(await histCount('tsk_ha_provisioning_history', SID), 3, 'no extra transitions');
    await assert.rejects(() => prov(ctl, SID, 'DIFFERENT-marker'), /genesis marker conflict/);
  });

  // ── signed, monotonic, command-bound lease ───────────────────────────────────
  await check('lease: grant->renew->revoke signed monotonic; idempotent retry adds no seq', async () => {
    const now = await nowMs();
    const g1 = await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 30_000, grantCommandId: 'gc1' });
    assert.equal(g1.grantSeq, 1);
    const g2 = await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 60_000, grantCommandId: 'gc2' });
    assert.equal(g2.grantSeq, 2);
    const again = await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 60_000, grantCommandId: 'gc2' });
    assert.equal(again.grantSeq, 2, 'idempotent lost-ACK retry: same grantCommandId, no seq+1');
    const g3 = await ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: now + 60_000, grantCommandId: 'gc3' });
    assert.equal(g3.grantSeq, 3); assert.equal(g3.status, 'revoked');
    assert.equal(await histCount('tsk_ha_lease_history', SID), 3);
  });

  await check('lease rejects: wrong epoch, shortened max-expiry, unprovisioned stream, integer ranges', async () => {
    const now = await nowMs();
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 1, status: 'active', grantedMaxExpiryMs: now + 1000, grantCommandId: 'x' }), /must equal the current witness epoch/);
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: now + 1000, grantCommandId: 'x' }), /shorten the monotonic fence horizon/);
    await assert.rejects(() => ctl.writeLease({ streamId: 'tsk:unprov/v1', leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 1000, grantCommandId: 'x' }), FenceAuthorityQuarantineError);
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l', holderNodeId: 'A', epoch: -1, status: 'active', grantedMaxExpiryMs: now, grantCommandId: 'x' }), /epoch must be a safe integer/);
    await assert.rejects(() => ctl.writeLease({ streamId: SID, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: Number.POSITIVE_INFINITY, grantCommandId: 'x' }), /grantedMaxExpiryMs must be a safe integer/);
  });

  // ── H10 replay-over-head + tamper + rotation ────────────────────────────────
  const SIDr = 'tsk:pair:replay/v1';
  await check('H10: replaying an older valid lease row over the head is rejected (head!=latest history)', async () => {
    await prov(ctl, SIDr, 'g-replay');
    const now = await nowMs();
    await ctl.writeLease({ streamId: SIDr, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 1000, grantCommandId: 'r1' });
    await ctl.writeLease({ streamId: SIDr, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: now + 2000, grantCommandId: 'r2' });
    // overwrite the head with the older (seq-1) validly-signed row
    await pool.query('DELETE FROM tsk_ha_lease_head WHERE stream_id=$1', [SIDr]);
    await pool.query(`INSERT INTO tsk_ha_lease_head (stream_id, lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature)
      SELECT stream_id, lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_ha_lease_history WHERE stream_id=$1 AND grant_seq=1`, [SIDr]);
    await assert.rejects(() => ctl.lease(SIDr), /head is not the latest history row/);
  });

  await check('tamper + rotation/revocation: corrupted head signature and a revoked keyId both fail closed', async () => {
    await pool.query("UPDATE tsk_ha_lease_head SET guard_signature='AAAA' WHERE stream_id=$1", [SID]);
    await assert.rejects(() => ctl.lease(SID), /guard signature/);
    // restore the true head from history seq 3
    await pool.query('DELETE FROM tsk_ha_lease_head WHERE stream_id=$1', [SID]);
    await pool.query(`INSERT INTO tsk_ha_lease_head (stream_id, lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature)
      SELECT stream_id, lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_ha_lease_history WHERE stream_id=$1 AND grant_seq=3`, [SID]);
    const ctlRevoked = new HaControlFencing(tx as never, signer, revokedResolver, ready);
    await assert.rejects(() => ctlRevoked.lease(SID), /unknown or revoked guard keyId/);
  });

  // ── control-clock fence-advance saga + evidence + guards + freeze + idempotency ──
  await check('fence-advance: not-revoked and not-expired both quarantine; revoked+elapsed advances 0->1 with signed evidence', async () => {
    const SID2 = 'tsk:pair:advance/v1';
    await prov(ctl, SID2, 'g-adv');
    const store = storeFor(SID2);
    const past = (await nowMs()) - 5_000; // an already-elapsed lease (control clock is real; no sleep)
    await ctl.writeLease({ streamId: SID2, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'a1' });
    await ctl.beginPromotionIntent(SID2, 'c1', 1);
    // freeze-under-PREPARING: a new active grant is refused while the promotion is in-flight
    await assert.rejects(() => ctl.writeLease({ streamId: SID2, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'a2' }), /frozen while a promotion is in-flight/);
    const proof: FenceProof = { safetyMarginMs: 0, claimExpiresAtMs: (await nowMs()) + HOUR };
    // A not proven fenced yet (lease still active) -> quarantine
    await assert.rejects(() => ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof), FenceAuthorityQuarantineError);
    await ctl.writeLease({ streamId: SID2, leaseId: 'l1', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: past, grantCommandId: 'a3' });
    // revoked but a huge margin keeps A within the fence horizon -> still quarantine
    await assert.rejects(() => ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, { ...proof, safetyMarginMs: HOUR }), /not proven fenced/);
    // revoked AND elapsed past the margin -> advance with signed evidence
    const res = await ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof);
    assert.equal(res.epoch, 1); assert.equal(res.fenceToken, '1'); assert.equal(res.idempotent, false);
    assert.ok(res.evidence && res.evidence.witnessFrom === 0 && res.evidence.witnessTo === 1 && res.evidence.proofMode === 'lease-expiry-control-clock');
    assert.equal((await ctl.witness(SID2))?.epoch, 1, 'witness advanced 0->1');
    assert.equal((await store.current())?.fenceEpoch, 1, 'Redis claimed epoch 1');
    // H7 idempotent retry after commit -> returns existing, no new FENCED history
    const again = await ctl.advanceEpoch(SID2, 'c1', 1, 'B', store, proof);
    assert.equal(again.idempotent, true);
    assert.equal((await ctl.witness(SID2))?.epoch, 1, 'still epoch 1 after idempotent retry');
  });

  await check('Redis-loss quarantine: an absent Redis authority after provisioning fails closed', async () => {
    const SID3 = 'tsk:pair:redisloss/v1';
    await prov(ctl, SID3, 'g-rl');
    const past = (await nowMs()) - 5_000;
    await ctl.writeLease({ streamId: SID3, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'active', grantedMaxExpiryMs: past, grantCommandId: 'b1' });
    await ctl.beginPromotionIntent(SID3, 'cr', 1);
    await ctl.writeLease({ streamId: SID3, leaseId: 'l', holderNodeId: 'A', epoch: 0, status: 'revoked', grantedMaxExpiryMs: past, grantCommandId: 'b2' });
    const empty = new MemoryFencingStore(); // current() === null => Redis lost after provisioning
    const rlProof: FenceProof = { safetyMarginMs: 0, claimExpiresAtMs: (await nowMs()) + HOUR };
    await assert.rejects(() => ctl.advanceEpoch(SID3, 'cr', 1, 'B', empty, rlProof), /Redis fence authority is absent/);
  });

  await check('one active intent + target==witness+1 + integer-range rejection', async () => {
    const SID4 = 'tsk:pair:intent/v1';
    await prov(ctl, SID4, 'g-i');
    await assert.rejects(() => ctl.beginPromotionIntent(SID4, 'c1', 2), /must equal witness.epoch\+1/);
    await assert.rejects(() => ctl.beginPromotionIntent(SID4, 'c1', 0), /targetEpoch must be a safe integer/);
    await ctl.beginPromotionIntent(SID4, 'c1', 1);
    await assert.rejects(() => ctl.beginPromotionIntent(SID4, 'c2', 1), /in-flight intent/);
    const same = await ctl.beginPromotionIntent(SID4, 'c1', 1);
    assert.equal(same.phase, 'PREPARING');
  });

  await check('barrier-controlled concurrent intents: atomic admission yields exactly one winner', async () => {
    const SID5 = 'tsk:pair:race/v1';
    await prov(ctl, SID5, 'g-race');
    // launch both together; the per-stream advisory lock + SERIALIZABLE make admission atomic
    const results = await Promise.allSettled([
      ctl.beginPromotionIntent(SID5, 'cX', 1),
      ctl.beginPromotionIntent(SID5, 'cY', 1),
    ]);
    const winners = results.filter((r) => r.status === 'fulfilled');
    assert.equal(winners.length, 1, 'exactly one intent admitted');
    assert.equal(await histCount('tsk_ha_cutover_history', SID5), 1, 'only one PREPARING row appended');
    const head = (await pool.query('SELECT phase FROM tsk_ha_cutover_head WHERE stream_id=$1', [SID5])).rows[0];
    assert.equal(head.phase, 'PREPARING');
  });

  console.log(`\n# ${passed} PR2a fencing-foundation checks passed`);
  await pool.end().catch(() => {});
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
