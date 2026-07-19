import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { ContractValidationError } from './ha-outbox-contract.js';
import type { PgExecutor, PgTransactor } from './tsk-hotp-outbox-pg.js';
import type { FencingStore, FenceRecord } from './promotion.js';
import { verifySourceFrozenReceipt, verifyBFinalizedReceipt } from './tsk-source-fence.js';
import type { SourceFrozenReceipt, BFinalizedReceipt, SourceVerifyKeyResolver } from './tsk-source-fence.js';

/**
 * PR2a — HA fencing FOUNDATION (control DB). Implements the reviewed design
 * (docs/PR2_HA_DESIGN.md §3) in a dedicated THIRD control PG, distinct from the
 * source/receiver PGs and from Redis.
 *
 * Every authority record — provisioning, epoch WITNESS, lease grant, and cutover —
 * is a SIGNED, append-only, prev-digest-CHAINED transition. Reads verify the FULL
 * chain AND head==latest-history (an older validly-signed row cannot be replayed
 * over the head). Every mutating op runs under an EXACT-SESSION SERIALIZABLE tx with
 * a pinned search_path, a per-stream advisory lock (atomic admission), and an
 * unforgeable schema-readiness capability (full pg_catalog manifest + version).
 *
 * BOUNDED / MECHANISM-ONLY: this makes NO split-brain, HA, or uptime claim. The
 * control-DB witness is the authoritative epoch FLOOR; Redis is the cross-node claim
 * coordinator, cross-checked (never trusted alone). A SINGLE Redis (the drill uses the
 * production RedisFencingStore against one instance) is mechanism-only, NOT a fault-tolerant
 * topology. "A proven fenced" here means the old lease is
 * revoked AND its control-DB-recorded, MONOTONIC max grant-expiry (+ a bounded safety
 * margin) has elapsed on the CONTROL clock (clock_timestamp() read in-tx) — it does
 * NOT by itself STONITH the old backend; binding a reaper/source-applier fence is
 * PR2b/PR2c. The promotion import/attest/activate is PR2b/PR2c. #10 stays OPEN.
 */

// ── bounds + grammars (H9: exhaust safe integers; enforce id/digest grammar) ──

export const CONTROL_SCHEMA_VERSION = 1;
const MAX_EPOCH = 2 ** 40;                    // >> any real promotion count, safely < 2^53
const MAX_SEQ = 2 ** 40;
const MAX_MS = 8.64e15;                        // JS Date range bound
const MAX_LEASE_HORIZON_MS = 24 * 3600 * 1000; // a granted max-expiry is at most this far ahead of control-now
const MAX_SAFETY_MARGIN_MS = 3600 * 1000;      // fence safety margin bounded to 1h
const MAX_CLAIM_REMAINING_MS = 3600 * 1000;    // configured worst-case final-tx+commit+skew budget, bounded to 1h
const STREAM_ID_RE = /^[A-Za-z0-9:._/-]{1,200}$/;
const ID_RE = /^[A-Za-z0-9:._-]{1,128}$/;      // leaseId, holder/nodeId, commandId, grantCommandId
const DIGEST_RE = /^[0-9a-f]{64}$/;
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const SCHEMA_RE = /^[a-z_][a-z0-9_]{0,62}$/;

function vInt(v: unknown, label: string, min: number, max: number): number {
  const n = typeof v === 'bigint' ? Number(v) : typeof v === 'string' ? Number(v) : (v as number);
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < min || n > max) {
    throw new ContractValidationError(`${label} must be a safe integer in [${min}, ${max}]`);
  }
  return n;
}
function vId(v: unknown, re: RegExp, label: string): string {
  if (typeof v !== 'string' || !re.test(v)) throw new ContractValidationError(`invalid ${label}`);
  return v;
}
function vDigest(v: unknown, label: string): string {
  if (typeof v !== 'string' || !DIGEST_RE.test(v)) throw new ContractValidationError(`invalid ${label} (expected 64-hex digest)`);
  return v;
}
function vNullableDigest(v: unknown, label: string): string | null {
  if (v === null || v === undefined) return null;
  return vDigest(v, label);
}

/** The authoritative source write token for an epoch (canonical non-negative decimal). */
export function fenceTokenForEpoch(epoch: number): string {
  return String(vInt(epoch, 'epoch', 0, MAX_EPOCH));
}
/** Thrown when the fencing authority is in a state where writes/promotion MUST fail
 *  closed: Redis absent/rolled-back, A not proven fenced, or a frozen invariant violated. */
export class FenceAuthorityQuarantineError extends ContractValidationError {}

/** Synchronously DECOUPLE + deep-freeze an untrusted, caller-owned receipt BEFORE the first await, so a
 *  concurrent caller mutation between the sync verify and the in-tx use cannot cause a TOCTOU (mirrors the
 *  §3 receiver `verifiedExportSnapshot` discipline). The frozen snapshot is the ONLY value used thereafter. */
function frozenSnapshot<T>(x: T): T {
  const snap = JSON.parse(JSON.stringify(x)) as T;
  const freeze = (o: unknown): void => { if (o && typeof o === 'object') { Object.freeze(o); for (const v of Object.values(o as Record<string, unknown>)) freeze(v); } };
  freeze(snap);
  return snap;
}

// ── guard signing (HMAC over length-prefixed, keyId-bound, canonical framing) ─

/** Resolves a guard keyId to its secret, or null if unknown/revoked (rotation + revocation). */
export interface GuardKeyResolver {
  resolve(keyId: string): Buffer | string | null;
}

function toSecret(s: Buffer | string): Buffer {
  const b = Buffer.isBuffer(s) ? Buffer.from(s) : Buffer.from(String(s), 'utf8'); // defensive COPY
  if (b.length < 32) throw new ContractValidationError('guard secret must be >= 32 bytes');
  return b;
}
/** Length-prefixed, tagged framing: each field is [1-byte present-tag][uint32-BE len][bytes],
 *  or a single [0] for null. No value can shift across a boundary and null/""/"null" are
 *  distinct — with NO in-band NUL byte (keeps source pure-ASCII). */
function frame(...parts: (string | number | null)[]): Buffer {
  const bufs: Buffer[] = [];
  for (const p of parts) {
    if (p === null) { bufs.push(Buffer.from([0])); continue; }
    const b = Buffer.from(String(p), 'utf8');
    const len = Buffer.alloc(4); len.writeUInt32BE(b.length, 0);
    bufs.push(Buffer.from([1]), len, b);
  }
  return Buffer.concat(bufs);
}
const sha256hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const b64u = (b: Buffer): string => b.toString('base64url');
const B64U_CANON = /^[A-Za-z0-9_-]+$/; // canonical base64url: no '=' padding, no '+'/'/', no stray chars
function ctEqB64u(a: string, expected: Buffer): boolean {
  if (typeof a !== 'string' || !B64U_CANON.test(a)) return false;         // reject non-canonical (M6)
  let got: Buffer;
  try { got = Buffer.from(a, 'base64url'); } catch { return false; }
  if (b64u(got) !== a) return false;                                      // round-trip: reject any non-canonical encoding
  return got.length === expected.length && timingSafeEqual(got, expected);
}
/** Bind the keyId INTO the signed input (M6) so a signature cannot be replayed under another keyId. */
const withKey = (keyId: string, msg: Buffer): Buffer => Buffer.concat([frame('tsk_ha_key', keyId), msg]);

export class GuardSigner {
  private readonly secret: Buffer;
  constructor(private readonly keyId: string, secret: Buffer | string) {
    if (!KEY_ID_RE.test(keyId)) throw new ContractValidationError('invalid guard keyId');
    this.secret = toSecret(secret); // defensive copy inside toSecret
  }
  get id(): string { return this.keyId; }
  sign(msg: Buffer): string { return b64u(createHmac('sha256', this.secret).update(withKey(this.keyId, msg)).digest()); }
}
export function verifyGuard(resolver: GuardKeyResolver, keyId: string, msg: Buffer, signature: string): void {
  if (!KEY_ID_RE.test(keyId)) throw new ContractValidationError('invalid guard keyId');
  const secretRaw = resolver.resolve(keyId);
  if (secretRaw === null) throw new ContractValidationError('unknown or revoked guard keyId');
  const expected = createHmac('sha256', toSecret(secretRaw)).update(withKey(keyId, msg)).digest();
  if (!ctEqB64u(signature, expected)) throw new ContractValidationError('invalid guard signature');
}

// ── canonical signed-field framings (fixed order; keyId bound via withKey) ────

const digestOf = (msg: Buffer): string => sha256hex(msg);
const provMsg = (s: string, genesis: string, state: string, seq: number, prev: string | null, digest: string): Buffer =>
  frame('tsk_ha_prov/v1', s, genesis, state, seq, prev, digest);
const witMsg = (s: string, epoch: number, state: string, seq: number, prev: string | null, digest: string): Buffer =>
  frame('tsk_ha_witness/v1', s, epoch, state, seq, prev, digest);
// sign the epoch-MS INTEGER (round-trips exactly) + grant_command_id; never the timestamptz/Date.
const leaseMsg = (s: string, leaseId: string, holder: string, epoch: number, seq: number, status: string, maxExpiryMs: number, grantCmd: string, prev: string | null, digest: string): Buffer =>
  frame('tsk_ha_lease/v1', s, leaseId, holder, epoch, seq, status, maxExpiryMs, grantCmd, prev, digest);
const cutMsg = (s: string, epoch: number, commandId: string, seqno: number, phase: string, evidence: string | null, prev: string | null, digest: string): Buffer =>
  frame('tsk_ha_cutover/v1', s, epoch, commandId, seqno, phase, evidence, prev, digest);
const claimDigest = (r: FenceRecord): string => sha256hex(frame('tsk_ha_claim/v1', r.nodeId, r.fenceEpoch, r.expiresAt, r.commandId));

/** (§3.4 + Erratum-R4) Cross-check the Redis claim vs the SIGNED witness floor before a fence.
 *  A NULL Redis record is the canonical GENESIS state ONLY while witness == 0 (RedisFencingStore
 *  models fence epochs as >= 1, so no record exists until the first promotion); NULL with
 *  witness > 0 is a loss/rollback → quarantine. A Redis-ahead state is admissible ONLY for the
 *  exact active intent (ambiguous mid-saga claim). Pure/deterministic — exhaustively unit-tested. */
export function assertRedisAuthority(r: FenceRecord | null, witnessEpoch: number, commandId: string, targetEpoch: number): void {
  if (r === null) {
    if (witnessEpoch === 0) return; // canonical genesis: no Redis record until the first promotion
    throw new FenceAuthorityQuarantineError(`Redis fence authority is absent with witness epoch ${witnessEpoch} > 0 — loss/rollback; quarantine`);
  }
  if (r.fenceEpoch < witnessEpoch) throw new FenceAuthorityQuarantineError(`Redis fence epoch ${r.fenceEpoch} < witness ${witnessEpoch} — authority rolled back; quarantine`);
  if (r.fenceEpoch > witnessEpoch && !(r.fenceEpoch === targetEpoch && r.commandId === commandId)) {
    throw new FenceAuthorityQuarantineError(`Redis epoch ${r.fenceEpoch} ahead of witness ${witnessEpoch} without the matching active intent — quarantine`);
  }
}

/** (H4 + R5-H2 + R7-HIGH2) Reconcile the Redis authority on an idempotent post-FENCED retry
 *  against the SIGNED FENCED evidence we matched. The Redis record MUST EXACTLY equal the signed
 *  tuple at `evidence.witnessTo` (epoch + active + node + command + expiry + claim digest). ANY
 *  other epoch — higher OR lower — quarantines: a genuine later promotion moves the cutover head
 *  off FENCED@target so this reconcile is never reached for it, therefore a Redis epoch ahead of
 *  the signed cutover we matched is authority-ahead-of-signed-state, NOT a blessing. A witness
 *  INTEGER is never trusted to bless an unauthenticated later record. Pure/deterministic. */
export function reconcileFencedRedis(r: FenceRecord | null, evidence: FenceEvidence, commandId: string): void {
  if (r === null) throw new FenceAuthorityQuarantineError('Redis authority absent on a FENCED retry — loss/rollback; quarantine');
  const fenced = evidence.witnessTo;
  if (r.fenceEpoch !== fenced) {
    throw new FenceAuthorityQuarantineError(`Redis epoch ${r.fenceEpoch} != the signed FENCED epoch ${fenced} on retry — rollback/ahead-of-signed-authority; quarantine`);
  }
  if (r.active !== true || r.nodeId !== evidence.redisNodeId || r.commandId !== commandId || r.expiresAt !== evidence.redisExpiresMs || claimDigest(r) !== evidence.redisClaimDigest) {
    throw new FenceAuthorityQuarantineError('Redis record does not match the signed FENCED evidence tuple on retry — quarantine');
  }
}
const CUTOVER_TERMINAL = new Set(['ACTIVE', 'ABORTED']);
const CUTOVER_FROZEN = new Set(['PREPARING', 'SOURCE_FENCED', 'FENCED', 'IMPORTING', 'READY']); // lease grants frozen while a promotion is in-flight

// ── control-DB schema (executable; hardened with range/grammar CHECKs, H9) ────

export const HA_CONTROL_PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS tsk_ha_schema (
  id int PRIMARY KEY CHECK (id = 1),
  version int NOT NULL CHECK (version >= 1),
  catalog_manifest text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tsk_ha_provisioning (
  stream_id text PRIMARY KEY,
  genesis_marker text NOT NULL,
  state text NOT NULL CHECK (state IN ('intent','incomplete','provisioned')),
  state_seq bigint NOT NULL CHECK (state_seq >= 1),
  prev_state_digest text CHECK (prev_state_digest IS NULL OR prev_state_digest ~ '^[0-9a-f]{64}$'),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  provisioned_at timestamptz
);
CREATE TABLE IF NOT EXISTS tsk_ha_provisioning_history (
  stream_id text NOT NULL,
  genesis_marker text NOT NULL,
  state text NOT NULL CHECK (state IN ('intent','incomplete','provisioned')),
  state_seq bigint NOT NULL CHECK (state_seq >= 1),
  prev_state_digest text CHECK (prev_state_digest IS NULL OR prev_state_digest ~ '^[0-9a-f]{64}$'),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, state_seq),
  UNIQUE (stream_id, state_digest)
);
CREATE TABLE IF NOT EXISTS tsk_ha_epoch_witness (
  stream_id text PRIMARY KEY REFERENCES tsk_ha_provisioning(stream_id),
  epoch bigint NOT NULL CHECK (epoch >= 0),
  state text NOT NULL CHECK (state IN ('incomplete','provisioned')),
  state_seq bigint NOT NULL CHECK (state_seq >= 1),
  prev_state_digest text CHECK (prev_state_digest IS NULL OR prev_state_digest ~ '^[0-9a-f]{64}$'),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tsk_ha_epoch_witness_history (
  stream_id text NOT NULL,
  epoch bigint NOT NULL CHECK (epoch >= 0),
  state text NOT NULL CHECK (state IN ('incomplete','provisioned')),
  state_seq bigint NOT NULL CHECK (state_seq >= 1),
  prev_state_digest text CHECK (prev_state_digest IS NULL OR prev_state_digest ~ '^[0-9a-f]{64}$'),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, state_seq),
  UNIQUE (stream_id, state_digest)
);
CREATE TABLE IF NOT EXISTS tsk_ha_lease_head (
  stream_id text PRIMARY KEY,
  lease_id text NOT NULL,
  holder_node_id text NOT NULL,
  epoch bigint NOT NULL CHECK (epoch >= 0),
  grant_seq bigint NOT NULL CHECK (grant_seq >= 1),
  status text NOT NULL CHECK (status IN ('active','revoked')),
  granted_max_expiry_ms bigint NOT NULL CHECK (granted_max_expiry_ms >= 0),
  grant_command_id text NOT NULL,
  prev_grant_digest text CHECK (prev_grant_digest IS NULL OR prev_grant_digest ~ '^[0-9a-f]{64}$'),
  grant_digest text NOT NULL CHECK (grant_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL
);
CREATE TABLE IF NOT EXISTS tsk_ha_lease_history (
  stream_id text NOT NULL,
  lease_id text NOT NULL,
  holder_node_id text NOT NULL,
  epoch bigint NOT NULL CHECK (epoch >= 0),
  grant_seq bigint NOT NULL CHECK (grant_seq >= 1),
  status text NOT NULL CHECK (status IN ('active','revoked')),
  granted_max_expiry_ms bigint NOT NULL CHECK (granted_max_expiry_ms >= 0),
  grant_command_id text NOT NULL,
  prev_grant_digest text CHECK (prev_grant_digest IS NULL OR prev_grant_digest ~ '^[0-9a-f]{64}$'),
  grant_digest text NOT NULL CHECK (grant_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, grant_seq),
  UNIQUE (stream_id, grant_digest),
  UNIQUE (stream_id, grant_command_id)
);
CREATE TABLE IF NOT EXISTS tsk_ha_cutover_head (
  stream_id text PRIMARY KEY,
  epoch bigint NOT NULL CHECK (epoch >= 0),
  command_id text NOT NULL,
  seqno bigint NOT NULL CHECK (seqno >= 1),
  phase text NOT NULL CHECK (phase IN ('PREPARING','SOURCE_FENCED','FENCED','IMPORTING','READY','ACTIVE','ABORTED')),
  evidence text,
  prev_state_digest text CHECK (prev_state_digest IS NULL OR prev_state_digest ~ '^[0-9a-f]{64}$'),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tsk_ha_cutover_history (
  stream_id text NOT NULL,
  epoch bigint NOT NULL CHECK (epoch >= 0),
  command_id text NOT NULL,
  seqno bigint NOT NULL CHECK (seqno >= 1),
  phase text NOT NULL CHECK (phase IN ('PREPARING','SOURCE_FENCED','FENCED','IMPORTING','READY','ACTIVE','ABORTED')),
  evidence text,
  prev_state_digest text CHECK (prev_state_digest IS NULL OR prev_state_digest ~ '^[0-9a-f]{64}$'),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, seqno),
  UNIQUE (stream_id, state_digest)
)
`.trim();

export const HA_CONTROL_TABLES = [
  'tsk_ha_schema', 'tsk_ha_provisioning', 'tsk_ha_provisioning_history',
  'tsk_ha_epoch_witness', 'tsk_ha_epoch_witness_history', 'tsk_ha_lease_head',
  'tsk_ha_lease_history', 'tsk_ha_cutover_head', 'tsk_ha_cutover_history',
] as const;
const MANIFEST_TABLES = [...HA_CONTROL_TABLES]; // attest the FULL set incl tsk_ha_schema (R4-H3)
// (R8-HIGH) governed tables locked ACCESS SHARE per critical tx to freeze the catalog against a
// concurrent ALTER/DROP between attest and mutation. Names are compile-time constants (not input).
const GOVERNED_LOCK_LIST = HA_CONTROL_TABLES.join(', ');

// ── exact-session critical tx: SERIALIZABLE + pinned search_path ─────────────

async function assertSerializable(exec: PgExecutor): Promise<void> {
  const level = String((await exec.query('SHOW transaction_isolation')).rows[0]?.transaction_isolation ?? '').toLowerCase();
  if (level !== 'serializable') throw new ContractValidationError(`control critical tx requires SERIALIZABLE; got '${level}'`);
}
async function pinSchema(exec: PgExecutor, schema: string): Promise<void> {
  if (!SCHEMA_RE.test(schema)) throw new ContractValidationError(`invalid schema identifier: ${schema}`);
  // (R10-CRITICAL) OMIT pg_catalog from search_path: when it is not listed, PG searches it FIRST for
  // ALL objects, so a configured-schema function/operator (e.g. a malicious public.clock_timestamp
  // that could spoof control time) can NEVER shadow a system builtin. pg_temp is LAST so a temp
  // table cannot shadow the authority RELATIONS (which resolve to the configured schema first).
  // Every system function/catalog below is ALSO pg_catalog-qualified as defense in depth.
  await exec.query('SELECT pg_catalog.set_config($1, $2, true)', ['search_path', `${schema}, pg_temp`]);
  const cur = (await exec.query('SELECT pg_catalog.current_schema() AS s')).rows[0]?.s;
  if (cur !== schema) throw new ContractValidationError(`schema context mismatch: current_schema=${String(cur)} pinned=${schema}`);
}
/** (R9-HIGH1) Assert every governed table resolves (UNQUALIFIED, as the authority SQL sees it) to
 *  a relation in the configured schema — never a pg_temp shadow. */
async function assertNoShadow(exec: PgExecutor, schema: string): Promise<void> {
  const rows = (await exec.query(
    `SELECT t.name, n.nspname
     FROM pg_catalog.unnest($1::text[]) AS t(name)
     LEFT JOIN pg_catalog.pg_class c ON c.oid = pg_catalog.to_regclass(t.name)
     LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace`, [[...HA_CONTROL_TABLES]])).rows;
  for (const r of rows) {
    if (r.nspname !== schema) {
      throw new ContractValidationError(`governed table ${String(r.name)} resolves to '${String(r.nspname)}' not '${schema}' — possible pg_temp shadow; quarantine`);
    }
  }
}
async function enterCriticalTx(exec: PgExecutor, schema: string): Promise<void> {
  await assertSerializable(exec);
  await pinSchema(exec, schema);
  await assertNoShadow(exec, schema);
}

// ── schema attestation + unforgeable readiness capability (H3) ───────────────

/**
 * Canonical FULL-catalog manifest of the control tables: columns (ordinal + default + type +
 * nullability), constraints, indexes, triggers, relkind/persistence/row-security, and RLS
 * policies — INCLUDING tsk_ha_schema. This is attested against a COMPILED pinned digest (below),
 * never trust-on-first-use. NOTE: point-in-time. Preserving it at runtime is a DB privilege
 * boundary — the runtime role MUST NOT hold DDL rights (no CREATE/ALTER/DROP) on this schema;
 * provisioning/migration run under a separate privileged role, offline from serving.
 */
async function controlManifest(exec: PgExecutor): Promise<string> {
  const tables = [...MANIFEST_TABLES];
  const cols = (await exec.query(
    `SELECT table_name, ordinal_position, column_name, data_type, is_nullable, COALESCE(column_default,'') AS column_default
     FROM information_schema.columns WHERE table_schema = pg_catalog.current_schema() AND table_name = ANY($1)
     ORDER BY table_name, ordinal_position`, [tables])).rows;
  const cons = (await exec.query(
    `SELECT rel.relname AS t, c.contype, pg_catalog.pg_get_constraintdef(c.oid) AS def
     FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class rel ON rel.oid = c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = pg_catalog.current_schema() AND rel.relname = ANY($1) AND c.contype IN ('p','c','u','f')
     ORDER BY rel.relname, c.contype, def`, [tables])).rows;
  const idx = (await exec.query(
    `SELECT tablename AS t, indexname AS n, indexdef AS def FROM pg_catalog.pg_indexes
     WHERE schemaname = pg_catalog.current_schema() AND tablename = ANY($1) ORDER BY tablename, indexname`, [tables])).rows;
  const trg = (await exec.query(
    `SELECT rel.relname AS t, tg.tgname AS n, pg_catalog.pg_get_triggerdef(tg.oid) AS def
     FROM pg_catalog.pg_trigger tg JOIN pg_catalog.pg_class rel ON rel.oid = tg.tgrelid JOIN pg_catalog.pg_namespace ns ON ns.oid = rel.relnamespace
     WHERE ns.nspname = pg_catalog.current_schema() AND rel.relname = ANY($1) AND NOT tg.tgisinternal ORDER BY rel.relname, tg.tgname`, [tables])).rows;
  const rel = (await exec.query(
    `SELECT rel.relname AS t, rel.relkind, rel.relpersistence, rel.relrowsecurity, rel.relforcerowsecurity
     FROM pg_catalog.pg_class rel JOIN pg_catalog.pg_namespace ns ON ns.oid = rel.relnamespace
     WHERE ns.nspname = pg_catalog.current_schema() AND rel.relname = ANY($1) ORDER BY rel.relname`, [tables])).rows;
  const pol = (await exec.query(
    `SELECT tablename AS t, policyname AS n, permissive, roles::text AS roles, cmd, COALESCE(qual,'') AS qual, COALESCE(with_check,'') AS wc
     FROM pg_catalog.pg_policies WHERE schemaname = pg_catalog.current_schema() AND tablename = ANY($1) ORDER BY tablename, policyname`, [tables])).rows;
  return [
    `V${CONTROL_SCHEMA_VERSION}`,
    ...cols.map((r) => `C|${r.table_name}|${r.ordinal_position}|${r.column_name}|${r.data_type}|${r.is_nullable}|${r.column_default}`),
    ...cons.map((r) => `K|${r.t}|${r.contype}|${r.def}`),
    ...idx.map((r) => `I|${r.t}|${r.n}|${r.def}`),
    ...trg.map((r) => `T|${r.t}|${r.n}|${r.def}`),
    ...rel.map((r) => `R|${r.t}|${r.relkind}|${r.relpersistence}|${r.relrowsecurity}|${r.relforcerowsecurity}`),
    ...pol.map((r) => `P|${r.t}|${r.n}|${r.permissive}|${r.roles}|${r.cmd}|${r.qual}|${r.wc}`),
  ].join('\n');
}

/** COMPILED expected full-catalog manifest digest — pinned in source, computed from
 *  HA_CONTROL_PG_SCHEMA on PostgreSQL 16. Attestation compares the LIVE catalog to THIS; a
 *  dropped/added CHECK, column, index, trigger, or policy fails closed. There is deliberately NO
 *  runtime/env override (R5-H1: that would let a deployment bless an arbitrary live schema and
 *  defeat the pin). To RE-PIN after an intentional DDL change, run provisionControlSchema against
 *  the new schema in an OFFLINE, code-reviewed step and copy the digest reported in the attestation
 *  error ("live catalog digest <D>") into this constant. */
export const HA_CONTROL_MANIFEST_DIGEST = '68d4710a6bc72db1cfa4734f03f052fc963daa74c7e27787f595b0b29f45f6c3';

/** Attest the live catalog hashes to the pinned expected manifest (fail-closed, NOT TOFU). */
async function attestControlSchema(exec: PgExecutor): Promise<string> {
  const live = await controlManifest(exec);
  const digest = sha256hex(Buffer.from(live, 'utf8'));
  if (digest !== HA_CONTROL_MANIFEST_DIGEST) {
    throw new ContractValidationError(`control schema attestation failed: live catalog digest ${digest} != pinned ${HA_CONTROL_MANIFEST_DIGEST}`);
  }
  return digest;
}

/** (R8/R11) Revalidate the singleton tsk_ha_schema authority stamp per op. Uses FOR SHARE (R11-HIGH):
 *  ACCESS SHARE blocks DDL but NOT a concurrent UPDATE/DELETE of the stamp row, so a plain SELECT had
 *  a DML TOCTOU. FOR SHARE row-locks the singleton so any concurrent stamp mutation blocks until this
 *  tx commits; exactly one row is required. */
async function revalidateAuthorityRow(exec: PgExecutor): Promise<void> {
  const rows = (await exec.query('SELECT version, catalog_manifest FROM tsk_ha_schema WHERE id = 1 FOR SHARE')).rows;
  if (rows.length !== 1) throw new ContractValidationError(`control schema authority row must be exactly one, got ${rows.length}`);
  if (vInt(rows[0].version, 'schema version', 1, MAX_EPOCH) !== CONTROL_SCHEMA_VERSION) throw new ContractValidationError('control schema authority version mismatch');
  if (String(rows[0].catalog_manifest) !== HA_CONTROL_MANIFEST_DIGEST) throw new ContractValidationError('control schema authority stamp (catalog_manifest) does not match the compiled pinned digest');
}

const READY_BRAND: unique symbol = Symbol('tsk_ha_control_schema_ready');
export interface ControlSchemaReadyToken { readonly [READY_BRAND]: true }
interface ReadyState { db: PgTransactor; schema: string; version: number; manifestDigest: string }
const READY_STATE = new WeakMap<object, ReadyState>();
function mintReady(state: ReadyState): ControlSchemaReadyToken {
  const token = Object.freeze({ [READY_BRAND]: true as const });
  READY_STATE.set(token, state);
  return token as ControlSchemaReadyToken;
}
function requireReady(token: ControlSchemaReadyToken, db: PgTransactor): { schema: string } {
  const st = READY_STATE.get(token as unknown as object);
  if (!st) throw new ContractValidationError('invalid control schema-readiness capability (forged or foreign token)');
  if (st.db !== db) throw new ContractValidationError('schema-readiness token is bound to a different PgTransactor');
  if (st.version !== CONTROL_SCHEMA_VERSION) throw new ContractValidationError('schema-readiness token attests a different version');
  return { schema: st.schema };
}
// NO test-only mint export: tests attest for real via provisionControlSchema/assertControlSchemaReady.

/** Attest the live catalog matches the manifest stamped at provision time AND the pinned
 *  version, then mint a transactor+schema-bound unforgeable readiness token. */
export async function assertControlSchemaReady(db: PgTransactor, schema: string): Promise<ControlSchemaReadyToken> {
  let manifestDigest = '';
  await db.transaction(async (exec) => {
    await enterCriticalTx(exec, schema);
    manifestDigest = await attestControlSchema(exec); // live catalog === COMPILED pinned expected (not TOFU)
    const rows = (await exec.query('SELECT version, catalog_manifest FROM tsk_ha_schema WHERE id = 1')).rows;
    if (!rows.length) throw new ContractValidationError('control schema is not provisioned (no tsk_ha_schema row)');
    if (vInt(rows[0].version, 'schema version', 1, MAX_EPOCH) !== CONTROL_SCHEMA_VERSION) {
      throw new ContractValidationError(`control schema version mismatch: db=${rows[0].version} expected=${CONTROL_SCHEMA_VERSION}`);
    }
    // (R5-H3) the PERSISTED authority row must also equal the compiled pinned digest — catch an
    // altered stamp even if the live catalog was reverted to match.
    if (String(rows[0].catalog_manifest) !== HA_CONTROL_MANIFEST_DIGEST) throw new ContractValidationError('control schema authority row (catalog_manifest) does not match the compiled pinned digest');
  });
  return mintReady({ db, schema, version: CONTROL_SCHEMA_VERSION, manifestDigest });
}

/** FRESH provisioning: attest the live structure against the pinned expected manifest, then stamp
 *  the version+digest (idempotent at the pinned version; a divergent existing row is rejected). */
export async function provisionControlSchema(db: PgTransactor, schema: string): Promise<ControlSchemaReadyToken> {
  let manifestDigest = '';
  await db.transaction(async (exec) => {
    await enterCriticalTx(exec, schema);
    manifestDigest = await attestControlSchema(exec); // fail-closed against the compiled pinned manifest
    const rows = (await exec.query('SELECT version, catalog_manifest FROM tsk_ha_schema WHERE id = 1 FOR UPDATE')).rows;
    if (rows.length) {
      if (vInt(rows[0].version, 'schema version', 1, MAX_EPOCH) === CONTROL_SCHEMA_VERSION) {
        if (String(rows[0].catalog_manifest) !== HA_CONTROL_MANIFEST_DIGEST) throw new ContractValidationError('control schema authority row (catalog_manifest) does not match the compiled pinned digest'); // R5-H3
        return;
      }
      throw new ContractValidationError('control schema already provisioned at a different version');
    }
    affectedOne(await exec.query('INSERT INTO tsk_ha_schema (id, version, catalog_manifest) VALUES (1, $1, $2)', [CONTROL_SCHEMA_VERSION, manifestDigest]), 'fresh control schema provision');
  });
  return mintReady({ db, schema, version: CONTROL_SCHEMA_VERSION, manifestDigest });
}

// ── public state shapes ──────────────────────────────────────────────────────

export interface ProvisioningState { streamId: string; genesisMarker: string; state: 'intent' | 'incomplete' | 'provisioned'; stateSeq: number; stateDigest: string; }
export interface WitnessState { streamId: string; epoch: number; state: 'incomplete' | 'provisioned'; stateSeq: number; stateDigest: string; }
export interface LeaseState { streamId: string; leaseId: string; holderNodeId: string; epoch: number; grantSeq: number; status: 'active' | 'revoked'; grantedMaxExpiryMs: number; grantCommandId: string; grantDigest: string; }
export interface CutoverState { streamId: string; epoch: number; commandId: string; seqno: number; phase: 'PREPARING' | 'SOURCE_FENCED' | 'FENCED' | 'IMPORTING' | 'READY' | 'ACTIVE' | 'ABORTED'; evidence: string | null; stateDigest: string; }
/** Caller-supplied bounds for a fence-advance. The control clock is read IN-TX (never trusted
 *  from the caller); only the bounded safety margin + the Redis claim TTL come from the caller.
 *  The min-claim-remaining budget is NOT here — it is a deployment policy bound to the authority
 *  (HaControlFencing) so a caller cannot weaken it per call (R5-M1). */
export interface FenceProof {
  safetyMarginMs: number;
  claimExpiresAtMs: number;
}
/** Deployment policy bound to the control authority (NOT per call). */
export interface HaControlPolicy {
  /** STRICTLY-POSITIVE configured worst-case (final-tx + commit + clock-skew) budget the Redis
   *  claim TTL MUST still cover at the FENCED commit, validated against the control-DB clock IN the
   *  final tx. MECHANISM EVIDENCE only — NOT a universal commit-time/source-precommit guarantee. */
  minClaimRemainingMs: number;
  /** (R7-HIGH1) When true (DEFAULT), EVERY control op re-attests the LIVE catalog against the
   *  compiled pinned manifest inside its own tx, so a post-mint DDL drift fails the NEXT op closed
   *  (the readiness token is point-in-time and does NOT by itself prevent later DDL). Set false ONLY
   *  under an explicit STARTUP-ONLY boundary where the runtime DB role holds NO DDL rights
   *  (CREATE/ALTER/DROP) on this schema — then drift is impossible under the operating identity and
   *  the per-op re-attestation is redundant. */
  attestEveryTx?: boolean;
}
export interface FenceEvidence {
  holderNodeId: string; grantSeq: number; grantDigest: string; maxExpiryMs: number;
  controlNowMs: number; safetyMarginMs: number;
  redisNodeId: string; redisEpoch: number; redisExpiresMs: number; redisClaimDigest: string;
  witnessFrom: number; witnessTo: number; proofMode: 'lease-expiry-control-clock';
}

const affectedOne = (res: { rowCount: number }, what: string): void => {
  if (res.rowCount !== 1) throw new ContractValidationError(`${what}: expected exactly 1 affected row, got ${res.rowCount}`);
};
/** A signed, chained history row + a way to recompute its digest and its signed message. */
interface Linked { seq: number; prev: string | null; digest: string; keyId: string; sig: string; digMsg: Buffer; sigMsg: Buffer; }
/** (H10) Verify an append-only history is contiguous from seq 1, prev-digest linked, each row's
 *  own digest recomputes and signature verifies, AND the head IS the latest history row — so an
 *  older validly-signed row cannot be replayed over the head. */
function verifyChain(resolver: GuardKeyResolver, history: Linked[], head: Linked): void {
  if (!history.length) throw new ContractValidationError('missing signed history');
  let prev: string | null = null;
  for (let i = 0; i < history.length; i++) {
    const l = history[i];
    if (l.seq !== i + 1) throw new ContractValidationError('non-contiguous history seq');
    if (l.prev !== prev) throw new ContractValidationError('broken prev-digest chain');
    if (digestOf(l.digMsg) !== l.digest) throw new ContractValidationError('history row digest mismatch');
    verifyGuard(resolver, l.keyId, l.sigMsg, l.sig);
    prev = l.digest;
  }
  const last = history[history.length - 1];
  if (head.seq !== last.seq || head.digest !== last.digest) throw new ContractValidationError('head is not the latest history row (replay/rollback detected)');
  if (digestOf(head.digMsg) !== head.digest) throw new ContractValidationError('head digest mismatch');
  verifyGuard(resolver, head.keyId, head.sigMsg, head.sig);
}

/**
 * Control-DB fencing authority. Construction REQUIRES an unforgeable readiness capability bound to
 * the same transactor + a pinned schema. The token is POINT-IN-TIME; by default (policy
 * `attestEveryTx`) every op ALSO re-attests the live catalog against the compiled pinned manifest
 * inside its own SERIALIZABLE tx, so a post-mint DDL drift fails the next op closed. Every op runs
 * exact-session SERIALIZABLE with a pinned search_path + a per-stream advisory lock (atomic admission).
 */
export class HaControlFencing {
  private readonly schema: string;
  private readonly minClaimRemainingMs: number;
  private readonly attestEveryTx: boolean;
  constructor(
    private readonly db: PgTransactor,
    private readonly signer: GuardSigner,
    private readonly resolver: GuardKeyResolver,
    ready: ControlSchemaReadyToken,
    policy: HaControlPolicy,
  ) {
    this.schema = requireReady(ready, db).schema;
    this.minClaimRemainingMs = vInt(policy?.minClaimRemainingMs, 'policy.minClaimRemainingMs', 1, MAX_CLAIM_REMAINING_MS); // strictly positive
    this.attestEveryTx = policy?.attestEveryTx !== false; // default true (R7-HIGH1)
  }

  /** Exact-session SERIALIZABLE + pinned schema + (R7-HIGH1) LIVE per-tx catalog re-attestation +
   *  per-stream advisory lock. The re-attestation makes the point-in-time readiness token safe
   *  against a post-mint DDL drift: any structural change fails the NEXT op closed. */
  private criticalTx<T>(streamId: string, fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    const sid = vId(streamId, STREAM_ID_RE, 'streamId');
    return this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      if (this.attestEveryTx) {
        // (R8-HIGH) freeze the governed catalog for THIS tx BEFORE attesting: ACCESS SHARE blocks a
        // concurrent ALTER/DROP (ACCESS EXCLUSIVE) until commit, closing the attest→mutate TOCTOU.
        await exec.query(`LOCK TABLE ${GOVERNED_LOCK_LIST} IN ACCESS SHARE MODE`);
        await attestControlSchema(exec);    // live catalog === compiled pinned digest (now frozen)
      }
      // (R9-HIGH2) the singleton authority-stamp check runs on EVERY op — the attestEveryTx opt-out
      // only assumes no DDL, but a DML mutation of version/catalog_manifest must still fail closed.
      await revalidateAuthorityRow(exec);
      await exec.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [sid]);
      return fn(exec);
    });
  }

  private async controlNowMs(exec: PgExecutor): Promise<number> {
    return vInt((await exec.query('SELECT (extract(epoch from pg_catalog.clock_timestamp()) * 1000)::bigint AS ms')).rows[0]?.ms, 'control now', 0, MAX_MS);
  }

  // ── provisioning saga (H5: durable signed per-step tx; Redis epoch-0 genesis) ──

  /** Provision a stream as a RESUMABLE, durable, per-step saga (control-DB only):
   *  Tx-a intent → Tx-b incomplete + signed witness genesis (epoch 0, incomplete) →
   *  Tx-c provisioned + signed witness (epoch 0, provisioned). NO Redis genesis claim — the
   *  production RedisFencingStore models fence epochs as >= 1, so the canonical genesis is a
   *  witness floor of 0 with a NULL Redis record; the FIRST Redis record is the FIRST promotion
   *  (epoch 1). Re-running resumes from the durable state; a conflicting genesis marker is
   *  REJECTED (M5). See docs/PR2_HA_DESIGN.md §Erratum-R4. */
  async provision(streamId: string, genesisMarker: string): Promise<ProvisioningState> {
    const sid = vId(streamId, STREAM_ID_RE, 'streamId');
    if (typeof genesisMarker !== 'string' || genesisMarker.length < 1 || genesisMarker.length > 512) throw new ContractValidationError('invalid genesisMarker');

    // Tx-a: intent
    await this.criticalTx(sid, async (exec) => {
      const cur = await this.readProvisioning(exec, sid);
      if (cur) { if (cur.genesisMarker !== genesisMarker) throw new ContractValidationError('genesis marker conflict for an existing stream'); return; }
      await this.provTransition(exec, sid, genesisMarker, 'intent', 1, null);
    });
    // Tx-b: incomplete + signed witness genesis
    await this.criticalTx(sid, async (exec) => {
      const cur = (await this.readProvisioning(exec, sid))!;
      if (cur.genesisMarker !== genesisMarker) throw new ContractValidationError('genesis marker conflict');
      if (cur.state === 'intent') {
        const next = await this.provTransition(exec, sid, genesisMarker, 'incomplete', cur.stateSeq + 1, cur.stateDigest);
        await this.witnessGenesis(exec, sid, 'incomplete', next.stateDigest);
      }
    });
    // Tx-c: provisioned + signed witness provisioned
    return this.criticalTx(sid, async (exec) => {
      const cur = (await this.readProvisioning(exec, sid))!;
      if (cur.genesisMarker !== genesisMarker) throw new ContractValidationError('genesis marker conflict');
      if (cur.state === 'incomplete') {
        const next = await this.provTransition(exec, sid, genesisMarker, 'provisioned', cur.stateSeq + 1, cur.stateDigest);
        await this.witnessAdvanceState(exec, sid, /*epoch*/ 0, 'provisioned');
        await exec.query('UPDATE tsk_ha_provisioning SET provisioned_at = now() WHERE stream_id = $1', [sid]);
        return next;
      }
      return cur;
    });
  }

  private async provTransition(exec: PgExecutor, s: string, genesis: string, state: ProvisioningState['state'], seq: number, prev: string | null): Promise<ProvisioningState> {
    const digest = digestOf(provMsg(s, genesis, state, seq, prev, ''));
    const sig = this.signer.sign(provMsg(s, genesis, state, seq, prev, digest));
    await exec.query('INSERT INTO tsk_ha_provisioning_history (stream_id, genesis_marker, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [s, genesis, state, seq, prev, digest, this.signer.id, sig]);
    if (prev === null) {
      await exec.query('INSERT INTO tsk_ha_provisioning (stream_id, genesis_marker, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [s, genesis, state, seq, prev, digest, this.signer.id, sig]);
    } else {
      affectedOne(await exec.query('UPDATE tsk_ha_provisioning SET state=$3, state_seq=$4, prev_state_digest=$5, state_digest=$6, guard_key_id=$7, guard_signature=$8 WHERE stream_id=$1 AND state_digest=$2',
        [s, prev, state, seq, prev, digest, this.signer.id, sig]), 'provisioning forward-CAS');
    }
    return { streamId: s, genesisMarker: genesis, state, stateSeq: seq, stateDigest: digest };
  }

  private async readProvisioning(exec: PgExecutor, s: string): Promise<ProvisioningState | null> {
    const head = (await exec.query('SELECT genesis_marker, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature FROM tsk_ha_provisioning WHERE stream_id=$1', [s])).rows[0];
    if (!head) return null;
    const hist = (await exec.query('SELECT genesis_marker, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature FROM tsk_ha_provisioning_history WHERE stream_id=$1 ORDER BY state_seq ASC', [s])).rows;
    const link = (r: Record<string, unknown>): Linked => {
      const genesis = String(r.genesis_marker), state = String(r.state), seq = vInt(r.state_seq, 'state_seq', 1, MAX_SEQ);
      const prev = vNullableDigest(r.prev_state_digest, 'prev_state_digest'), digest = vDigest(r.state_digest, 'state_digest');
      return { seq, prev, digest, keyId: String(r.guard_key_id), sig: String(r.guard_signature), digMsg: provMsg(s, genesis, state, seq, prev, ''), sigMsg: provMsg(s, genesis, state, seq, prev, digest) };
    };
    verifyChain(this.resolver, hist.map(link), link(head));
    return { streamId: s, genesisMarker: String(head.genesis_marker), state: head.state as ProvisioningState['state'], stateSeq: vInt(head.state_seq, 'state_seq', 1, MAX_SEQ), stateDigest: vDigest(head.state_digest, 'state_digest') };
  }

  // ── signed epoch witness ─────────────────────────────────────────────────────

  private async witnessGenesis(exec: PgExecutor, s: string, state: WitnessState['state'], _provPrev: string): Promise<void> {
    const seq = 1, prev: string | null = null, epoch = 0;
    const digest = digestOf(witMsg(s, epoch, state, seq, prev, ''));
    const sig = this.signer.sign(witMsg(s, epoch, state, seq, prev, digest));
    await exec.query('INSERT INTO tsk_ha_epoch_witness_history (stream_id, epoch, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING', [s, epoch, state, seq, prev, digest, this.signer.id, sig]);
    await exec.query('INSERT INTO tsk_ha_epoch_witness (stream_id, epoch, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (stream_id) DO NOTHING', [s, epoch, state, seq, prev, digest, this.signer.id, sig]);
  }

  /** Advance the witness to (epoch, state) as a signed forward-CAS from the current verified head. */
  private async witnessAdvanceState(exec: PgExecutor, s: string, epoch: number, state: WitnessState['state']): Promise<WitnessState> {
    const cur = await this.readWitness(exec, s);
    if (!cur) throw new ContractValidationError('witness genesis missing');
    const seq = cur.stateSeq + 1, prev = cur.stateDigest;
    const digest = digestOf(witMsg(s, epoch, state, seq, prev, ''));
    const sig = this.signer.sign(witMsg(s, epoch, state, seq, prev, digest));
    await exec.query('INSERT INTO tsk_ha_epoch_witness_history (stream_id, epoch, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [s, epoch, state, seq, prev, digest, this.signer.id, sig]);
    affectedOne(await exec.query('UPDATE tsk_ha_epoch_witness SET epoch=$3, state=$4, state_seq=$5, prev_state_digest=$6, state_digest=$7, guard_key_id=$8, guard_signature=$9, updated_at=now() WHERE stream_id=$1 AND state_digest=$2', [s, prev, epoch, state, seq, prev, digest, this.signer.id, sig]), 'witness forward-CAS');
    return { streamId: s, epoch, state, stateSeq: seq, stateDigest: digest };
  }

  private async readWitness(exec: PgExecutor, s: string): Promise<WitnessState | null> {
    const head = (await exec.query('SELECT epoch, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature FROM tsk_ha_epoch_witness WHERE stream_id=$1', [s])).rows[0];
    if (!head) return null;
    const hist = (await exec.query('SELECT epoch, state, state_seq, prev_state_digest, state_digest, guard_key_id, guard_signature FROM tsk_ha_epoch_witness_history WHERE stream_id=$1 ORDER BY state_seq ASC', [s])).rows;
    const link = (r: Record<string, unknown>): Linked => {
      const epoch = vInt(r.epoch, 'epoch', 0, MAX_EPOCH), state = String(r.state), seq = vInt(r.state_seq, 'state_seq', 1, MAX_SEQ);
      const prev = vNullableDigest(r.prev_state_digest, 'prev_state_digest'), digest = vDigest(r.state_digest, 'state_digest');
      return { seq, prev, digest, keyId: String(r.guard_key_id), sig: String(r.guard_signature), digMsg: witMsg(s, epoch, state, seq, prev, ''), sigMsg: witMsg(s, epoch, state, seq, prev, digest) };
    };
    verifyChain(this.resolver, hist.map(link), link(head));
    return { streamId: s, epoch: vInt(head.epoch, 'epoch', 0, MAX_EPOCH), state: head.state as WitnessState['state'], stateSeq: vInt(head.state_seq, 'state_seq', 1, MAX_SEQ), stateDigest: vDigest(head.state_digest, 'state_digest') };
  }

  async witness(streamId: string): Promise<WitnessState | null> {
    return this.criticalTx(streamId, (exec) => this.readWitness(exec, vId(streamId, STREAM_ID_RE, 'streamId')));
  }

  /** Read the current signed cutover head (full-chain verified). Null before the first intent. */
  async cutover(streamId: string): Promise<CutoverState | null> {
    return this.criticalTx(streamId, (exec) => this.readCutover(exec, vId(streamId, STREAM_ID_RE, 'streamId')));
  }

  // ── signed, monotonic, command-bound lease (H2/H4/H7/CRITICAL) ───────────────

  /** Grant/renew/revoke a lease as a SIGNED monotonic transition. Requires the stream provisioned
   *  and `epoch == witness.epoch`. `grantedMaxExpiryMs` is bounded to the control clock and is
   *  MONOTONIC non-decreasing across all grants for (epoch, holder) — a revoke can never shorten
   *  the fence horizon. A retry with the same `grantCommandId` is IDEMPOTENT (no seq+1). While a
   *  promotion is in-flight, `active` grants are FROZEN (only a revoke may land). */
  async writeLease(input: { streamId: string; leaseId: string; holderNodeId: string; epoch: number; status: 'active' | 'revoked'; grantedMaxExpiryMs: number; grantCommandId: string }): Promise<LeaseState> {
    const s = vId(input.streamId, STREAM_ID_RE, 'streamId');
    const leaseId = vId(input.leaseId, ID_RE, 'leaseId');
    const holder = vId(input.holderNodeId, ID_RE, 'holderNodeId');
    const grantCmd = vId(input.grantCommandId, ID_RE, 'grantCommandId');
    const epoch = vInt(input.epoch, 'epoch', 0, MAX_EPOCH);
    const reqMax = vInt(input.grantedMaxExpiryMs, 'grantedMaxExpiryMs', 0, MAX_MS);
    if (input.status !== 'active' && input.status !== 'revoked') throw new ContractValidationError('invalid lease status');
    return this.criticalTx(s, async (exec) => {
      const w = await this.readWitness(exec, s);
      if (!w || w.state !== 'provisioned') throw new FenceAuthorityQuarantineError('stream not provisioned');
      if (epoch !== w.epoch) throw new ContractValidationError(`lease epoch ${epoch} must equal the current witness epoch ${w.epoch}`);
      const now = await this.controlNowMs(exec);
      if (reqMax > now + MAX_LEASE_HORIZON_MS) throw new ContractValidationError('grantedMaxExpiryMs exceeds the control-clock horizon');
      const cut = await this.readCutover(exec, s);
      if (cut && CUTOVER_FROZEN.has(cut.phase) && input.status === 'active') {
        throw new FenceAuthorityQuarantineError('lease grants are frozen while a promotion is in-flight');
      }
      const cur = await this.readLease(exec, s);
      // (H2) grantCommandId binds the FULL tuple: a prior grant with this command must match every
      // field (idempotent lost-ACK retry, no new seq); a reuse with a DIFFERENT tuple is rejected.
      const byCmd = (await exec.query('SELECT lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_digest FROM tsk_ha_lease_history WHERE stream_id=$1 AND grant_command_id=$2', [s, grantCmd])).rows[0];
      if (byCmd) {
        if (String(byCmd.lease_id) !== leaseId || String(byCmd.holder_node_id) !== holder || vInt(byCmd.epoch, 'epoch', 0, MAX_EPOCH) !== epoch || String(byCmd.status) !== input.status || vInt(byCmd.granted_max_expiry_ms, 'granted_max_expiry_ms', 0, MAX_MS) !== reqMax) {
          throw new FenceAuthorityQuarantineError('grantCommandId reused with a different lease tuple — quarantine');
        }
        return { streamId: s, leaseId, holderNodeId: holder, epoch, grantSeq: vInt(byCmd.grant_seq, 'grant_seq', 1, MAX_SEQ), status: input.status, grantedMaxExpiryMs: reqMax, grantCommandId: grantCmd, grantDigest: vDigest(byCmd.grant_digest, 'grant_digest') };
      }
      // (CRIT) holder+leaseId are IMMUTABLE within an epoch — the first grant fixes the writer
      // identity, so a same-epoch holder pivot (A active long, B revoked) is impossible.
      const firstAtEpoch = (await exec.query('SELECT holder_node_id, lease_id FROM tsk_ha_lease_history WHERE stream_id=$1 AND epoch=$2 ORDER BY grant_seq ASC LIMIT 1', [s, epoch])).rows[0];
      if (firstAtEpoch && (String(firstAtEpoch.holder_node_id) !== holder || String(firstAtEpoch.lease_id) !== leaseId)) {
        throw new FenceAuthorityQuarantineError('lease holder/leaseId is immutable within an epoch — advance the epoch to change the writer');
      }
      // monotonic max-expiry across ALL grants at this epoch (no holder pivot can shorten it)
      const priorMax = vInt((await exec.query('SELECT COALESCE(pg_catalog.max(granted_max_expiry_ms), 0) AS m FROM tsk_ha_lease_history WHERE stream_id=$1 AND epoch=$2', [s, epoch])).rows[0].m, 'prior max expiry', 0, MAX_MS);
      if (reqMax < priorMax) throw new ContractValidationError(`grantedMaxExpiryMs ${reqMax} would shorten the monotonic fence horizon ${priorMax}`);
      const grantSeq = (cur?.grantSeq ?? 0) + 1;
      const prev = cur?.grantDigest ?? null;
      const digest = digestOf(leaseMsg(s, leaseId, holder, epoch, grantSeq, input.status, reqMax, grantCmd, prev, ''));
      const sig = this.signer.sign(leaseMsg(s, leaseId, holder, epoch, grantSeq, input.status, reqMax, grantCmd, prev, digest));
      await exec.query('INSERT INTO tsk_ha_lease_history (stream_id, lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
        [s, leaseId, holder, epoch, grantSeq, input.status, reqMax, grantCmd, prev, digest, this.signer.id, sig]);
      if (prev === null) {
        await exec.query('INSERT INTO tsk_ha_lease_head (stream_id, lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
          [s, leaseId, holder, epoch, grantSeq, input.status, reqMax, grantCmd, prev, digest, this.signer.id, sig]);
      } else {
        affectedOne(await exec.query('UPDATE tsk_ha_lease_head SET lease_id=$3, holder_node_id=$4, epoch=$5, grant_seq=$6, status=$7, granted_max_expiry_ms=$8, grant_command_id=$9, prev_grant_digest=$10, grant_digest=$11, guard_key_id=$12, guard_signature=$13 WHERE stream_id=$1 AND grant_digest=$2',
          [s, prev, leaseId, holder, epoch, grantSeq, input.status, reqMax, grantCmd, prev, digest, this.signer.id, sig]), 'lease forward-CAS');
      }
      return { streamId: s, leaseId, holderNodeId: holder, epoch, grantSeq, status: input.status, grantedMaxExpiryMs: reqMax, grantCommandId: grantCmd, grantDigest: digest };
    });
  }

  async lease(streamId: string): Promise<LeaseState | null> {
    return this.criticalTx(streamId, (exec) => this.readLease(exec, vId(streamId, STREAM_ID_RE, 'streamId')));
  }

  private async readLease(exec: PgExecutor, s: string): Promise<LeaseState | null> {
    const head = (await exec.query('SELECT lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_ha_lease_head WHERE stream_id=$1', [s])).rows[0];
    if (!head) return null;
    const hist = (await exec.query('SELECT lease_id, holder_node_id, epoch, grant_seq, status, granted_max_expiry_ms, grant_command_id, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_ha_lease_history WHERE stream_id=$1 ORDER BY grant_seq ASC', [s])).rows;
    const link = (r: Record<string, unknown>): Linked => {
      const leaseId = String(r.lease_id), holder = String(r.holder_node_id), epoch = vInt(r.epoch, 'epoch', 0, MAX_EPOCH), seq = vInt(r.grant_seq, 'grant_seq', 1, MAX_SEQ);
      const status = String(r.status), maxMs = vInt(r.granted_max_expiry_ms, 'granted_max_expiry_ms', 0, MAX_MS), grantCmd = String(r.grant_command_id);
      const prev = vNullableDigest(r.prev_grant_digest, 'prev_grant_digest'), digest = vDigest(r.grant_digest, 'grant_digest');
      return { seq, prev, digest, keyId: String(r.guard_key_id), sig: String(r.guard_signature), digMsg: leaseMsg(s, leaseId, holder, epoch, seq, status, maxMs, grantCmd, prev, ''), sigMsg: leaseMsg(s, leaseId, holder, epoch, seq, status, maxMs, grantCmd, prev, digest) };
    };
    verifyChain(this.resolver, hist.map(link), link(head));
    return { streamId: s, leaseId: String(head.lease_id), holderNodeId: String(head.holder_node_id), epoch: vInt(head.epoch, 'epoch', 0, MAX_EPOCH), grantSeq: vInt(head.grant_seq, 'grant_seq', 1, MAX_SEQ), status: head.status as 'active' | 'revoked', grantedMaxExpiryMs: vInt(head.granted_max_expiry_ms, 'granted_max_expiry_ms', 0, MAX_MS), grantCommandId: String(head.grant_command_id), grantDigest: vDigest(head.grant_digest, 'grant_digest') };
  }

  // ── signed cutover (intent + fence-advance) ──────────────────────────────────

  private async readCutover(exec: PgExecutor, s: string): Promise<CutoverState | null> {
    const head = (await exec.query('SELECT epoch, command_id, seqno, phase, evidence, prev_state_digest, state_digest, guard_key_id, guard_signature FROM tsk_ha_cutover_head WHERE stream_id=$1', [s])).rows[0];
    if (!head) return null;
    const hist = (await exec.query('SELECT epoch, command_id, seqno, phase, evidence, prev_state_digest, state_digest, guard_key_id, guard_signature FROM tsk_ha_cutover_history WHERE stream_id=$1 ORDER BY seqno ASC', [s])).rows;
    const link = (r: Record<string, unknown>): Linked => {
      const epoch = vInt(r.epoch, 'epoch', 0, MAX_EPOCH), commandId = String(r.command_id), seqno = vInt(r.seqno, 'seqno', 1, MAX_SEQ);
      const phase = String(r.phase), evidence = r.evidence === null || r.evidence === undefined ? null : String(r.evidence);
      const prev = vNullableDigest(r.prev_state_digest, 'prev_state_digest'), digest = vDigest(r.state_digest, 'state_digest');
      return { seq: seqno, prev, digest, keyId: String(r.guard_key_id), sig: String(r.guard_signature), digMsg: cutMsg(s, epoch, commandId, seqno, phase, evidence, prev, ''), sigMsg: cutMsg(s, epoch, commandId, seqno, phase, evidence, prev, digest) };
    };
    verifyChain(this.resolver, hist.map(link), link(head));
    return { streamId: s, epoch: vInt(head.epoch, 'epoch', 0, MAX_EPOCH), commandId: String(head.command_id), seqno: vInt(head.seqno, 'seqno', 1, MAX_SEQ), phase: head.phase as CutoverState['phase'], evidence: head.evidence === null || head.evidence === undefined ? null : String(head.evidence), stateDigest: vDigest(head.state_digest, 'state_digest') };
  }

  private async cutTransition(exec: PgExecutor, s: string, epoch: number, commandId: string, seqno: number, phase: CutoverState['phase'], evidence: string | null, prev: string | null): Promise<CutoverState> {
    const digest = digestOf(cutMsg(s, epoch, commandId, seqno, phase, evidence, prev, ''));
    const sig = this.signer.sign(cutMsg(s, epoch, commandId, seqno, phase, evidence, prev, digest));
    await exec.query('INSERT INTO tsk_ha_cutover_history (stream_id, epoch, command_id, seqno, phase, evidence, prev_state_digest, state_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [s, epoch, commandId, seqno, phase, evidence, prev, digest, this.signer.id, sig]);
    if (prev === null) {
      affectedOne(await exec.query("INSERT INTO tsk_ha_cutover_head (stream_id, epoch, command_id, seqno, phase, evidence, prev_state_digest, state_digest, guard_key_id, guard_signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", [s, epoch, commandId, seqno, phase, evidence, prev, digest, this.signer.id, sig]), 'cutover insert');
    } else {
      affectedOne(await exec.query('UPDATE tsk_ha_cutover_head SET epoch=$3, command_id=$4, seqno=$5, phase=$6, evidence=$7, prev_state_digest=$8, state_digest=$9, guard_key_id=$10, guard_signature=$11, updated_at=now() WHERE stream_id=$1 AND state_digest=$2',
        [s, prev, epoch, commandId, seqno, phase, evidence, prev, digest, this.signer.id, sig]), 'cutover forward-CAS');
    }
    return { streamId: s, epoch, commandId, seqno, phase, evidence, stateDigest: digest };
  }

  /** (H8) Admit exactly ONE active intent per stream. Requires the stream provisioned and
   *  `targetEpoch == witness.epoch + 1`. Same commandId+epoch → idempotent resume; a different
   *  in-flight command → deny. Atomic under the per-stream advisory lock + affected=1 CAS. */
  async beginPromotionIntent(streamId: string, commandId: string, targetEpoch: number): Promise<CutoverState> {
    const s = vId(streamId, STREAM_ID_RE, 'streamId');
    const cmd = vId(commandId, ID_RE, 'commandId');
    const target = vInt(targetEpoch, 'targetEpoch', 1, MAX_EPOCH);
    return this.criticalTx(s, async (exec) => {
      const w = await this.readWitness(exec, s);
      if (!w || w.state !== 'provisioned') throw new FenceAuthorityQuarantineError('stream not provisioned');
      if (target !== w.epoch + 1) throw new ContractValidationError(`targetEpoch ${target} must equal witness.epoch+1 (${w.epoch + 1})`);
      const cur = await this.readCutover(exec, s);
      if (cur && !CUTOVER_TERMINAL.has(cur.phase)) {
        if (cur.commandId === cmd && cur.epoch === target) return cur; // idempotent resume
        throw new FenceAuthorityQuarantineError(`an in-flight intent (${cur.commandId}/${cur.phase}) blocks a new promotion`);
      }
      const seqno = (cur?.seqno ?? 0) + 1;
      return this.cutTransition(exec, s, target, cmd, seqno, 'PREPARING', null, cur ? cur.stateDigest : null);
    });
  }

  /**
   * Advance the epoch (fence the old writer) for a SOURCE_FENCED intent — the source freeze MUST already be
   * bound (bindSourceFenced) before a control can FENCE. This makes the §4 ordering a single-chokepoint
   * invariant: FENCED is unreachable without a durably-bound, source-signed frozen receipt. NO cross-tx
   * TOCTOU: grants are frozen once a promotion is in-flight, and the final witness/FENCED tx RE-READS and RE-ASSERTS
   * the exact revoked lease (by digest), the control clock vs the MONOTONIC max grant-expiry,
   * and the full Redis claim tuple. The control clock is read IN-TX (never from the caller).
   * A completed advance is idempotent (H7). Returns the fence token + the signed evidence.
   */
  async advanceEpoch(streamId: string, commandId: string, targetEpoch: number, holderNodeId: string, fencingStore: FencingStore, proof: FenceProof): Promise<{ epoch: number; fenceToken: string; evidence: FenceEvidence | null; idempotent: boolean }> {
    const s = vId(streamId, STREAM_ID_RE, 'streamId');
    const cmd = vId(commandId, ID_RE, 'commandId');
    const target = vInt(targetEpoch, 'targetEpoch', 1, MAX_EPOCH);
    const newHolder = vId(holderNodeId, ID_RE, 'holderNodeId');
    const margin = vInt(proof.safetyMarginMs, 'safetyMarginMs', 0, MAX_SAFETY_MARGIN_MS);
    const claimExpiry = vInt(proof.claimExpiresAtMs, 'claimExpiresAtMs', 1, MAX_MS);
    const minRemaining = this.minClaimRemainingMs; // deployment policy (strictly positive), not per call (R5-M1)

    // Tx1: preconditions + capture the FROZEN revoked-lease evidence + Redis-not-lost cross-check.
    const pre = await this.criticalTx(s, async (exec) => {
      const cut = await this.readCutover(exec, s);
      if (cut && cut.phase === 'FENCED' && cut.commandId === cmd && cut.epoch === target) {
        return { done: true as const, evidence: cut.evidence };
      }
      const w = await this.readWitness(exec, s);
      if (!cut || cut.phase !== 'SOURCE_FENCED' || cut.commandId !== cmd || cut.epoch !== target) throw new ContractValidationError('no matching SOURCE_FENCED intent for this promotion — bind the source freeze (bindSourceFenced) before fencing');
      if (!w || w.state !== 'provisioned') throw new FenceAuthorityQuarantineError('stream not provisioned');
      if (w.epoch !== target - 1) throw new ContractValidationError(`witness epoch ${w.epoch} is not targetEpoch-1 (${target - 1})`);
      const ev = await this.proveOldFenced(exec, s, target, margin);
      assertRedisAuthority(await fencingStore.current(), w.epoch, cmd, target);
      return { done: false as const, ev, witnessFrom: w.epoch };
    });
    if (pre.done) { // H7 idempotent retry — RECONCILE Redis vs the SIGNED FENCED evidence (R5-H2/R7-HIGH2), never blind
      if (!pre.evidence) throw new FenceAuthorityQuarantineError('FENCED cutover is missing its signed evidence — quarantine');
      reconcileFencedRedis(await fencingStore.current(), decodeEvidence(pre.evidence), cmd);
      return { epoch: target, fenceToken: fenceTokenForEpoch(target), evidence: null, idempotent: true };
    }

    // Redis claim (external resource); verify the FULL tuple readback (H4).
    await fencingStore.claim({ nodeId: newHolder, fenceEpoch: target, expiresAt: claimExpiry, commandId: cmd });
    const r = await fencingStore.current();
    if (!r || r.active !== true || r.nodeId !== newHolder || r.fenceEpoch !== target || r.commandId !== cmd || r.expiresAt !== claimExpiry) {
      throw new FenceAuthorityQuarantineError('Redis claim tuple did not read back exactly — quarantine');
    }
    const redisClaimDigest = claimDigest(r);

    // Tx2: RE-ASSERT everything under the advisory lock, then advance witness + write signed FENCED.
    return this.criticalTx(s, async (exec) => {
      const cut = await this.readCutover(exec, s);
      if (cut && cut.phase === 'FENCED' && cut.commandId === cmd && cut.epoch === target) {
        if (!cut.evidence) throw new FenceAuthorityQuarantineError('FENCED cutover is missing its signed evidence — quarantine');
        reconcileFencedRedis(await fencingStore.current(), decodeEvidence(cut.evidence), cmd); // R5-H2/R7-HIGH2
        return { epoch: target, fenceToken: fenceTokenForEpoch(target), evidence: null, idempotent: true };
      }
      if (!cut || cut.phase !== 'SOURCE_FENCED' || cut.commandId !== cmd || cut.epoch !== target) throw new ContractValidationError('intent changed under promotion — abort');
      const w = await this.readWitness(exec, s);
      if (!w || w.state !== 'provisioned' || w.epoch !== target - 1) throw new FenceAuthorityQuarantineError('witness changed under promotion — abort');
      const ev2 = await this.proveOldFenced(exec, s, target, margin); // re-read exact revoked lease + control clock
      if (ev2.grantDigest !== pre.ev.grantDigest) throw new FenceAuthorityQuarantineError('the fenced lease changed under promotion (frozen invariant violated) — abort');
      const rr = await fencingStore.current();
      const nowFinal = await this.controlNowMs(exec);
      if (!rr || rr.active !== true || rr.nodeId !== newHolder || rr.fenceEpoch !== target || rr.commandId !== cmd || rr.expiresAt !== claimExpiry) throw new FenceAuthorityQuarantineError('Redis tuple changed before FENCED — abort');
      // (H3) the Redis claim TTL MUST still cover the configured worst-case final-tx+commit+skew
      // budget, measured against the control DB clock IN this tx. Mechanism evidence only — the
      // non-bypassable commit-time/source-precommit fence is a later milestone.
      if (rr.expiresAt < nowFinal + minRemaining) throw new FenceAuthorityQuarantineError(`Redis claim TTL (${rr.expiresAt - nowFinal}ms remaining) is below the configured min budget ${minRemaining}ms — quarantine`);
      await this.witnessAdvanceState(exec, s, target, 'provisioned');
      const evidence: FenceEvidence = { holderNodeId: ev2.holderNodeId, grantSeq: ev2.grantSeq, grantDigest: ev2.grantDigest, maxExpiryMs: ev2.maxExpiryMs, controlNowMs: ev2.controlNowMs, safetyMarginMs: margin, redisNodeId: rr.nodeId, redisEpoch: rr.fenceEpoch, redisExpiresMs: rr.expiresAt, redisClaimDigest, witnessFrom: target - 1, witnessTo: target, proofMode: 'lease-expiry-control-clock' };
      await this.cutTransition(exec, s, target, cmd, cut.seqno + 1, 'FENCED', encodeEvidence(evidence), cut.stateDigest);
      return { epoch: target, fenceToken: fenceTokenForEpoch(target), evidence, idempotent: false };
    });
  }

  /** Control's OWN durable PG system_identifier — the deployment-topology anchor for the B != control
   *  proof at READY. Read IN-TX from the control DB's pg_control_system(); never from the caller. */
  private async controlSystemId(exec: PgExecutor): Promise<string> {
    return String((await exec.query('SELECT system_identifier::text AS s FROM pg_catalog.pg_control_system()')).rows[0]?.s);
  }

  /**
   * (§4-a) PREPARING → SOURCE_FENCED. BIND the source-signed SourceFrozenReceipt (the frozen N on A) into
   * the signed control cutover head BEFORE the control declares the Redis/witness FENCED. The receipt is
   * ed25519-verified against A's PUBLIC key and MUST bind this exact stream+command; its digest + N +
   * head@N + state@N + sourceNodeId + the REVOKE that fenced A are recorded as the signed cutover evidence.
   * Idempotent resume. This is the ordering gate: nothing imports until the freeze is durably bound here.
   */
  async bindSourceFenced(streamId: string, commandId: string, targetEpoch: number, frozenReceipt: SourceFrozenReceipt, frozenResolver: SourceVerifyKeyResolver): Promise<CutoverState> {
    const s = vId(streamId, STREAM_ID_RE, 'streamId');
    const cmd = vId(commandId, ID_RE, 'commandId');
    const target = vInt(targetEpoch, 'targetEpoch', 1, MAX_EPOCH);
    // (H1) synchronously DECOUPLE + freeze the caller-owned receipt and capture the resolver BEFORE any await;
    // everything below uses ONLY the immutable snapshot, so a concurrent caller mutation cannot TOCTOU us.
    const fr = frozenSnapshot(frozenReceipt);
    const resolver = frozenResolver;
    verifySourceFrozenReceipt(resolver, fr); // verifies A's ed25519 signature over the frozen receipt — throws on tamper
    if (fr.commandId !== cmd) throw new FenceAuthorityQuarantineError('frozen receipt commandId != cutover command — quarantine');
    if (fr.streamId !== s) throw new FenceAuthorityQuarantineError('frozen receipt streamId != cutover stream — quarantine');
    // the freeze at source epoch E promotes to control target epoch E+1 — reject a cross-epoch splice.
    if (fr.epoch !== target - 1) throw new FenceAuthorityQuarantineError(`frozen receipt epoch ${fr.epoch} != targetEpoch-1 (${target - 1}) — cross-epoch freeze; quarantine`);
    // canonical bound-field set — written as evidence AND re-asserted on an idempotent retry (H3).
    const bound = { k: 'source_fenced/v1', frozenReceiptDigest: fr.receiptDigest, sourceEpoch: fr.epoch, n: fr.n,
      headAtN: fr.signedHeadDigestAtN, stateAtN: fr.sourceStateDigestAtN, sourceNodeId: fr.sourceNodeId,
      revokeCommandId: fr.revokeCommandId, leaseId: fr.leaseId, leaseGrantDigest: fr.leaseGrantDigest, sourceKeyId: fr.sourceKeyId };
    const ev = JSON.stringify(bound);
    return this.criticalTx(s, async (exec) => {
      const cur = await this.readCutover(exec, s);
      if (cur && cur.phase === 'SOURCE_FENCED' && cur.commandId === cmd && cur.epoch === target) {
        // (H3) idempotent ONLY if the incoming receipt equals the stored signed evidence, byte-for-byte.
        if (cur.evidence !== ev) throw new FenceAuthorityQuarantineError('SOURCE_FENCED retry with a DIFFERENT frozen receipt than the bound one — quarantine');
        return cur;
      }
      if (!cur || cur.phase !== 'PREPARING' || cur.commandId !== cmd || cur.epoch !== target) throw new FenceAuthorityQuarantineError('no matching PREPARING intent to bind SOURCE_FENCED — quarantine');
      return this.cutTransition(exec, s, target, cmd, cur.seqno + 1, 'SOURCE_FENCED', ev, cur.stateDigest);
    });
  }

  /**
   * (§4-c) FENCED → IMPORTING. Open the import window — but ONLY once (a) the Redis/witness FENCED is the
   * current head for this command/epoch AND (b) a SOURCE_FENCED freeze was durably bound in history for the
   * SAME command/epoch. Enforcement of the §4 ordering is PRIMARILY at advanceEpoch (which now requires the
   * SOURCE_FENCED phase, so FENCED is unreachable without a bound freeze); this (b) check is DEFENSE-IN-DEPTH
   * — an independent re-assertion at the import boundary, not the sole gate. Idempotent resume.
   */
  async markImporting(streamId: string, commandId: string, targetEpoch: number): Promise<CutoverState> {
    const s = vId(streamId, STREAM_ID_RE, 'streamId');
    const cmd = vId(commandId, ID_RE, 'commandId');
    const target = vInt(targetEpoch, 'targetEpoch', 1, MAX_EPOCH);
    return this.criticalTx(s, async (exec) => {
      const cur = await this.readCutover(exec, s);
      if (cur && cur.phase === 'IMPORTING' && cur.commandId === cmd && cur.epoch === target) return cur; // idempotent
      if (!cur || cur.phase !== 'FENCED' || cur.commandId !== cmd || cur.epoch !== target) throw new FenceAuthorityQuarantineError('no matching FENCED cutover to begin IMPORTING — quarantine');
      const sf = (await exec.query("SELECT evidence FROM tsk_ha_cutover_history WHERE stream_id=$1 AND command_id=$2 AND epoch=$3 AND phase='SOURCE_FENCED'", [s, cmd, target])).rows[0];
      if (!sf) throw new FenceAuthorityQuarantineError('cannot IMPORT: no bound SOURCE_FENCED freeze receipt for this command/epoch — quarantine');
      return this.cutTransition(exec, s, target, cmd, cur.seqno + 1, 'IMPORTING', cur.evidence, cur.stateDigest);
    });
  }

  /**
   * (§4-d) IMPORTING → READY. Control VERIFIES B's ed25519 signature over the BFinalizedReceipt (whose bound
   * fields embed the source+guard signatures, transitively binding them — this does NOT independently re-verify
   * the source/guard public-key signatures, which were checked at export/finalize), then binds it to THIS cutover:
   *   • commandId + streamId match the active cutover command;
   *   • frozenReceiptDigest / n / head@N / state@N match the SOURCE_FENCED-bound freeze byte-for-byte;
   *   • the freeze epoch is targetEpoch-1 and B's receipt epoch equals it (no cross-epoch splice);
   *   • B's system_identifier is DISTINCT from BOTH the signed source system_identifier (B != source) AND
   *     control's OWN durable PG system_identifier (B != control — the capability §4 was deferred to hold).
   * The READY head (control-signed) records B's finalize digest + both distinct system_identifiers, so a
   * READY state EXISTS only if control proved B != control against its own identity. B has already flipped;
   * this is control durably ratifying the flip. Idempotent resume.
   */
  async markReady(streamId: string, commandId: string, targetEpoch: number, bReceipt: BFinalizedReceipt, bResolver: SourceVerifyKeyResolver): Promise<CutoverState> {
    const s = vId(streamId, STREAM_ID_RE, 'streamId');
    const cmd = vId(commandId, ID_RE, 'commandId');
    const target = vInt(targetEpoch, 'targetEpoch', 1, MAX_EPOCH);
    // (H1) synchronously DECOUPLE + freeze the caller-owned receipt and capture the resolver BEFORE any await.
    const br = frozenSnapshot(bReceipt);
    const resolver = bResolver;
    // verifies B's ed25519 signature over the receipt (whose bound fields INCLUDE the source+guard signature
    // strings, so any of them tampering breaks B's signature); it does NOT independently re-verify the source
    // or guard public-key signatures — that was done at export/finalize time and is transitively bound here.
    verifyBFinalizedReceipt(resolver, br);
    if (br.commandId !== cmd) throw new FenceAuthorityQuarantineError('BFinalizedReceipt commandId != cutover command — quarantine');
    if (br.streamId !== s) throw new FenceAuthorityQuarantineError('BFinalizedReceipt streamId != cutover stream — quarantine');
    return this.criticalTx(s, async (exec) => {
      const cur = await this.readCutover(exec, s);
      // Accept ONLY an IMPORTING cutover (fresh) or an already-READY one (idempotent retry) for this cmd/epoch.
      const isReadyRetry = !!cur && cur.phase === 'READY' && cur.commandId === cmd && cur.epoch === target;
      if (!cur || (!isReadyRetry && (cur.phase !== 'IMPORTING' || cur.commandId !== cmd || cur.epoch !== target))) throw new FenceAuthorityQuarantineError('no matching IMPORTING cutover to mark READY — quarantine');
      const sfRow = (await exec.query("SELECT evidence FROM tsk_ha_cutover_history WHERE stream_id=$1 AND command_id=$2 AND epoch=$3 AND phase='SOURCE_FENCED'", [s, cmd, target])).rows[0];
      if (!sfRow || sfRow.evidence === null) throw new FenceAuthorityQuarantineError('no bound SOURCE_FENCED evidence to bind READY against — quarantine');
      const sf = JSON.parse(String(sfRow.evidence)) as { frozenReceiptDigest: string; n: number; headAtN: string; stateAtN: string; sourceEpoch: number };
      // B's finalize MUST bind the EXACT frozen N control bound at SOURCE_FENCED (no cross-freeze splice).
      if (br.frozenReceiptDigest !== sf.frozenReceiptDigest) throw new FenceAuthorityQuarantineError('BFinalizedReceipt frozenReceiptDigest != the bound SOURCE_FENCED freeze — quarantine');
      if (br.n !== sf.n || br.signedHeadDigestAtN !== sf.headAtN || br.sourceStateDigestAtN !== sf.stateAtN) throw new FenceAuthorityQuarantineError('BFinalizedReceipt N/head@N/state@N != the bound freeze — quarantine');
      // epoch binding: the bound freeze is at source epoch target-1, and B's receipt must be at that SAME epoch.
      if (sf.sourceEpoch !== target - 1) throw new FenceAuthorityQuarantineError(`bound SOURCE_FENCED sourceEpoch ${sf.sourceEpoch} != targetEpoch-1 (${target - 1}) — quarantine`);
      if (br.epoch !== sf.sourceEpoch) throw new FenceAuthorityQuarantineError(`BFinalizedReceipt epoch ${br.epoch} != the bound freeze sourceEpoch ${sf.sourceEpoch} — cross-epoch splice; quarantine`);
      // Distinctness: B != source (signed in the receipt) AND B != control (control's OWN in-tx sysid).
      const controlSystemId = await this.controlSystemId(exec);
      if (br.bSystemId === br.sourceSystemId) throw new FenceAuthorityQuarantineError('B system_identifier == source — not a distinct node; quarantine');
      if (br.bSystemId === controlSystemId) throw new FenceAuthorityQuarantineError('B system_identifier == control — not a distinct node; quarantine');
      const ev = JSON.stringify({ k: 'ready/v1', bReceiptDigest: br.receiptDigest, generationId: br.generationId, manifestDigest: br.manifestDigest, manifestRoot: br.manifestRoot,
        frozenReceiptDigest: br.frozenReceiptDigest, n: br.n, bSystemId: br.bSystemId, sourceSystemId: br.sourceSystemId, controlSystemId, bKeyId: br.bKeyId });
      if (isReadyRetry) {
        // (H3) idempotent ONLY if the incoming receipt equals the stored signed READY evidence, byte-for-byte.
        if (cur!.evidence !== ev) throw new FenceAuthorityQuarantineError('READY retry with a DIFFERENT B receipt than the ratified one — quarantine');
        return cur!;
      }
      return this.cutTransition(exec, s, target, cmd, cur!.seqno + 1, 'READY', ev, cur!.stateDigest);
    });
  }

  /** Prove the OLD holder is fenced WITHOUT touching A's PG: an exact current revoked lease at
   *  epoch target-1 whose MONOTONIC max grant-expiry (+ bounded margin) has elapsed on the control
   *  clock read in THIS tx. A missing lease is NOT acceptable. */
  private async proveOldFenced(exec: PgExecutor, s: string, target: number, margin: number): Promise<{ holderNodeId: string; grantSeq: number; grantDigest: string; maxExpiryMs: number; controlNowMs: number }> {
    const lease = await this.readLease(exec, s);
    if (!lease) throw new FenceAuthorityQuarantineError('no lease to fence — A not proven fenced');
    if (lease.epoch !== target - 1) throw new FenceAuthorityQuarantineError(`lease epoch ${lease.epoch} != targetEpoch-1 (${target - 1}) — A not proven fenced`);
    if (lease.status !== 'revoked') throw new FenceAuthorityQuarantineError('lease is not revoked — A not proven fenced');
    // max-expiry over ALL grants at epoch target-1 (holder+leaseId is immutable per epoch, so this
    // covers every writer that could hold epoch target-1) — a revoke can never shorten it.
    const maxExpiryMs = vInt((await exec.query('SELECT COALESCE(pg_catalog.max(granted_max_expiry_ms), 0) AS m FROM tsk_ha_lease_history WHERE stream_id=$1 AND epoch=$2', [s, lease.epoch])).rows[0].m, 'max grant expiry', 0, MAX_MS);
    const now = await this.controlNowMs(exec);
    if (now < maxExpiryMs + margin) throw new FenceAuthorityQuarantineError('lease grant has not expired past the safety margin — A not proven fenced (wait or STONITH)');
    return { holderNodeId: lease.holderNodeId, grantSeq: lease.grantSeq, grantDigest: lease.grantDigest, maxExpiryMs, controlNowMs: now };
  }
}

/** Canonical, order-fixed evidence encoding bound into the signed FENCED transition (H6). */
export function encodeEvidence(e: FenceEvidence): string {
  return b64u(frame('tsk_ha_evidence/v1', e.holderNodeId, e.grantSeq, e.grantDigest, e.maxExpiryMs, e.controlNowMs, e.safetyMarginMs, e.redisNodeId, e.redisEpoch, e.redisExpiresMs, e.redisClaimDigest, e.witnessFrom, e.witnessTo, e.proofMode));
}

/** Parse the tagged length-prefixed framing back into field strings (evidence has no null fields). */
function unframe(buf: Buffer): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < buf.length) {
    const tag = buf[i]; i += 1;
    if (tag === 0) { out.push(''); continue; }
    if (tag !== 1) throw new ContractValidationError('malformed evidence frame tag');
    if (i + 4 > buf.length) throw new ContractValidationError('truncated evidence frame length');
    const len = buf.readUInt32BE(i); i += 4;
    if (i + len > buf.length) throw new ContractValidationError('truncated evidence frame body');
    out.push(buf.subarray(i, i + len).toString('utf8')); i += len;
  }
  return out;
}

/** Decode + validate a signed FENCED evidence string (inverse of encodeEvidence). */
export function decodeEvidence(s: string): FenceEvidence {
  if (typeof s !== 'string' || !B64U_CANON.test(s)) throw new ContractValidationError('invalid evidence encoding');
  const f = unframe(Buffer.from(s, 'base64url'));
  if (f.length !== 14 || f[0] !== 'tsk_ha_evidence/v1') throw new ContractValidationError('unexpected evidence layout');
  if (f[13] !== 'lease-expiry-control-clock') throw new ContractValidationError('unknown evidence proofMode');
  return {
    holderNodeId: vId(f[1], ID_RE, 'evidence.holderNodeId'),
    grantSeq: vInt(f[2], 'evidence.grantSeq', 1, MAX_SEQ),
    grantDigest: vDigest(f[3], 'evidence.grantDigest'),
    maxExpiryMs: vInt(f[4], 'evidence.maxExpiryMs', 0, MAX_MS),
    controlNowMs: vInt(f[5], 'evidence.controlNowMs', 0, MAX_MS),
    safetyMarginMs: vInt(f[6], 'evidence.safetyMarginMs', 0, MAX_SAFETY_MARGIN_MS),
    redisNodeId: vId(f[7], ID_RE, 'evidence.redisNodeId'),
    redisEpoch: vInt(f[8], 'evidence.redisEpoch', 1, MAX_EPOCH),
    redisExpiresMs: vInt(f[9], 'evidence.redisExpiresMs', 0, MAX_MS),
    redisClaimDigest: vDigest(f[10], 'evidence.redisClaimDigest'),
    witnessFrom: vInt(f[11], 'evidence.witnessFrom', 0, MAX_EPOCH),
    witnessTo: vInt(f[12], 'evidence.witnessTo', 1, MAX_EPOCH),
    proofMode: 'lease-expiry-control-clock',
  };
}
