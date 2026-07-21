import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import pg from 'pg';
import {
  HA_CONTROL_PG_SCHEMA, HA_CONTROL_TABLES, HA_CONTROL_V1_SOURCE_ACTIVATION_SCHEMA,
  HA_CONTROL_V1_MANIFEST_DIGEST, HA_CONTROL_MANIFEST_DIGEST,
  GuardSigner, NodePostgresTransactor, migrateControlSchemaV1ToV2,
  assertControlSchemaReady, signLeaseGrant,
  type GuardKeyResolver, type SourceVerifyKeyResolver, type ControlSchemaMigrationDb,
} from './packages/server/dist/index.js';

const URL = process.env['TSK_TEST_CONTROL_PG_URL'];
if (!URL) throw new Error('TSK_TEST_CONTROL_PG_URL is required (real PostgreSQL 16; no skip)');
const SCHEMA = 'public'; const STREAM = 'migration-stream'; const CMD = 'activate-1';
const CONTROL_KEY = 'control-1'; const CONTROL_SECRET = Buffer.alloc(32, 0x4d);
const SOURCE_GUARD_KEY = 'source-guard-1'; const sourceGuard = generateKeyPairSync('ed25519');
const signer = new GuardSigner(CONTROL_KEY, CONTROL_SECRET);
const controlResolver: GuardKeyResolver = { resolve: (keyId: string) => keyId === CONTROL_KEY ? CONTROL_SECRET : null };
const sourceResolver: SourceVerifyKeyResolver = { resolve: (keyId: string) => keyId === SOURCE_GUARD_KEY ? sourceGuard.publicKey : null };

const frame = (...parts: (string | number | null)[]): Buffer => Buffer.concat(parts.flatMap((part) => {
  if (part === null) return [Buffer.from([0])];
  const value = Buffer.from(String(part)); const length = Buffer.alloc(4); length.writeUInt32BE(value.length);
  return [Buffer.from([1]), length, value];
}));
const digest = (value: Buffer): string => createHash('sha256').update(value).digest('hex');
const cutMsg = (stream: string, epoch: number, command: string, seq: number, phase: string,
  evidence: string | null, prev: string | null, stateDigest: string): Buffer =>
  frame('tsk_ha_cutover/v1', stream, epoch, command, seq, phase, evidence, prev, stateDigest);

async function installV1(pool: pg.Pool, tamperGrant = false): Promise<void> {
  await pool.query(`DROP TABLE IF EXISTS ${HA_CONTROL_TABLES.join(', ')} CASCADE`);
  for (const statement of HA_CONTROL_PG_SCHEMA.split(';').map((s) => s.trim()).filter(Boolean)) {
    if (!/^CREATE TABLE IF NOT EXISTS tsk_ha_source_activation(?:_history)?\s*\(/.test(statement)) await pool.query(statement);
  }
  await pool.query(HA_CONTROL_V1_SOURCE_ACTIVATION_SCHEMA);
  await pool.query('INSERT INTO tsk_ha_schema(id,version,catalog_manifest) VALUES(1,1,$1)', [HA_CONTROL_V1_MANIFEST_DIGEST]);

  const receiptDigest = 'a'.repeat(64); const holder = 'node-b';
  const activeEvidence = JSON.stringify({ k: 'active/v1', bReceiptDigest: receiptDigest, bKeyId: holder });
  const stateDigest = digest(cutMsg(STREAM, 1, CMD, 1, 'ACTIVE', activeEvidence, null, ''));
  const signature = signer.sign(cutMsg(STREAM, 1, CMD, 1, 'ACTIVE', activeEvidence, null, stateDigest));
  const cutValues = [STREAM, 1, CMD, 1, 'ACTIVE', activeEvidence, null, stateDigest, CONTROL_KEY, signature];
  await pool.query('INSERT INTO tsk_ha_cutover_history(stream_id,epoch,command_id,seqno,phase,evidence,prev_state_digest,state_digest,guard_key_id,guard_signature) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', cutValues);
  await pool.query('INSERT INTO tsk_ha_cutover_head(stream_id,epoch,command_id,seqno,phase,evidence,prev_state_digest,state_digest,guard_key_id,guard_signature) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', cutValues);

  const grant = signLeaseGrant(SOURCE_GUARD_KEY, sourceGuard.privateKey, {
    streamId: STREAM, leaseEpoch: 1, leaseStatus: 'active', holderNodeId: holder,
    leaseId: 'bsrc-activate-1', commandId: CMD, leaseExpiresAtMs: Date.now() + 60_000,
    leaseGrantSeq: 1, prevGrantDigest: null,
  });
  await pool.query('INSERT INTO tsk_ha_source_activation(stream_id,command_id,epoch,b_key_id,b_receipt_digest,grant_digest,grant_json,guard_key_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
    [STREAM, CMD, 1, holder, receiptDigest, tamperGrant ? 'b'.repeat(64) : grant.grantDigest, JSON.stringify(grant), SOURCE_GUARD_KEY]);
}

async function main(): Promise<void> {
  const pool = new pg.Pool({ connectionString: URL, max: 3 }); pool.on('error', () => {});
  const tx = new NodePostgresTransactor(pool as never);
  const migrationDb: ControlSchemaMigrationDb = { async transaction<T>(fn: (exec: { query(sql: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number }> }) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const result = await fn({ query: async (sql, params = []) => {
        const value = await client.query(sql, params); return { rows: value.rows, rowCount: value.rowCount ?? 0 };
      } });
      await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
    finally { client.release(); }
  } };
  await installV1(pool);
  const migratedDigest = await migrateControlSchemaV1ToV2(migrationDb, SCHEMA, signer, controlResolver, sourceResolver);
  await assertControlSchemaReady(tx, SCHEMA);
  assert.equal(migratedDigest, HA_CONTROL_MANIFEST_DIGEST);
  const stamp = (await pool.query('SELECT version,catalog_manifest FROM tsk_ha_schema WHERE id=1')).rows[0];
  assert.equal(Number(stamp.version), 2); assert.equal(stamp.catalog_manifest, HA_CONTROL_MANIFEST_DIGEST);
  const migrated = (await pool.query('SELECT * FROM tsk_ha_source_activation_history WHERE stream_id=$1', [STREAM])).rows;
  assert.equal(migrated.length, 1); assert.equal(Number(migrated[0].activation_seq), 1);
  assert.equal(migrated[0].prev_activation_digest, null);
  assert.equal(migrated[0].grant_digest, JSON.parse(migrated[0].grant_json).grantDigest);
  console.log('  ok - exact v1 authority + signed legacy activation migrate atomically to attested v2');

  await installV1(pool, true);
  await assert.rejects(() => migrateControlSchemaV1ToV2(migrationDb, SCHEMA, signer, controlResolver, sourceResolver), /exactly bind|quarantine/i);
  const rolledBack = (await pool.query('SELECT version,catalog_manifest FROM tsk_ha_schema WHERE id=1')).rows[0];
  assert.equal(Number(rolledBack.version), 1); assert.equal(rolledBack.catalog_manifest, HA_CONTROL_V1_MANIFEST_DIGEST);
  assert.equal((await pool.query("SELECT pg_catalog.to_regclass('tsk_ha_source_activation_history') AS r")).rows[0].r, null);
  console.log('  ok - invalid legacy authority fails closed and the one-transaction migration rolls back');
  await pool.end();
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
