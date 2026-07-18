/**
 * PR2b-0 — non-bypassable SOURCE in-tx fence/lease gate (docs/PR2B_DESIGN.md §A).
 *
 * Additive to the merged #10 outbox: the outbox already checks `tsk_outbox_fence.fence_token`
 * FOR UPDATE in the append tx; this layers a control-issued, guard-signed LEASE (epoch / status /
 * expiry / monotonic grant_seq + prev-digest chain + append-only history) so that a stale-epoch or
 * unleased writer loses in its own SERIALIZABLE commit — even after passing a Redis pre-check.
 *
 * A-PG NEVER reads the control clock or control DB in its tx: the lease deadline is a SIGNED absolute
 * `lease_expires_at_ms` (control clock) that A evaluates against A's OWN `clock_timestamp()` with an
 * explicit measured/bounded control↔A skew. The LOCK-based revoke (a conflicting UPDATE that waits
 * for in-flight FOR SHARE appends) is the freeze AUTHORITY; time expiry is only a secondary bound.
 *
 * This module ships the lease STORAGE + guard-verified install + the in-tx gate primitive. The
 * append-tx wiring, the transactor pre-commit recheck, the SourceFrozenReceipt, and the external
 * restore/fork witness land in subsequent PR2b-0 commits.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { ContractValidationError } from './ha-outbox-contract.js';
import type { PgExecutor } from './tsk-hotp-outbox-pg.js';
import type { GuardKeyResolver } from './ha-control-fencing.js';

// ── bounds + grammar ─────────────────────────────────────────────────────────

const MAX_EPOCH = 2 ** 40;
const MAX_SEQ = 2 ** 40;
const MAX_MS = 8.64e15;
const MAX_SKEW_MS = 3600 * 1000; // bounded control↔A skew
const STREAM_ID_RE = /^[A-Za-z0-9:._/-]{1,512}$/;
const ID_RE = /^[A-Za-z0-9:._-]{1,128}$/;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const B64U_CANON = /^[A-Za-z0-9_-]+$/;

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
function vNullableDigest(v: unknown, label: string): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v !== 'string' || !DIGEST_RE.test(v)) throw new ContractValidationError(`invalid ${label}`);
  return v;
}

// ── guard signing (matches PR2a's keyId-bound, length-prefixed HMAC framing) ──

function toSecret(s: Buffer | string): Buffer {
  const b = Buffer.isBuffer(s) ? Buffer.from(s) : Buffer.from(String(s), 'utf8'); // defensive copy
  if (b.length < 32) throw new ContractValidationError('guard secret must be >= 32 bytes');
  return b;
}
/** Length-prefixed, tagged framing (no in-band NUL): [1][len][bytes] per field, [0] for null. */
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
const withKey = (keyId: string, msg: Buffer): Buffer => Buffer.concat([frame('tsk_ha_key', keyId), msg]);
function ctEqB64u(a: string, expected: Buffer): boolean {
  if (typeof a !== 'string' || !B64U_CANON.test(a)) return false;
  let got: Buffer;
  try { got = Buffer.from(a, 'base64url'); } catch { return false; }
  if (got.toString('base64url') !== a) return false;
  return got.length === expected.length && timingSafeEqual(got, expected);
}
function verifyGuard(resolver: GuardKeyResolver, keyId: string, msg: Buffer, signature: string): void {
  if (!KEY_ID_RE.test(keyId)) throw new ContractValidationError('invalid guard keyId');
  const secret = resolver.resolve(keyId);
  if (secret === null) throw new ContractValidationError('unknown or revoked guard keyId');
  const expected = createHmac('sha256', toSecret(secret)).update(withKey(keyId, msg)).digest();
  if (!ctEqB64u(signature, expected)) throw new ContractValidationError('invalid guard signature');
}

/** Canonical signed message for a lease grant/revocation (control signs; source verifies — same
 *  framing, so control and source cannot diverge). `digest` is '' when computing the digest. */
function leaseGrantMsg(g: Omit<LeaseGrant, 'grantDigest' | 'guardKeyId' | 'guardSignature'>, digest: string): Buffer {
  return frame('tsk_source_lease/v1', g.streamId, g.leaseEpoch, g.leaseStatus, g.holderNodeId, g.leaseId,
    g.commandId, g.leaseExpiresAtMs, g.leaseGrantSeq, g.prevGrantDigest, digest);
}

// ── control-issued lease grant / revocation ──────────────────────────────────

export interface LeaseGrant {
  streamId: string; leaseEpoch: number; leaseStatus: 'active' | 'revoked'; holderNodeId: string;
  leaseId: string; commandId: string; leaseExpiresAtMs: number; leaseGrantSeq: number;
  prevGrantDigest: string | null; grantDigest: string; guardKeyId: string; guardSignature: string;
}
export type BareLeaseGrant = Omit<LeaseGrant, 'grantDigest' | 'guardKeyId' | 'guardSignature'>;

/** CONTROL-SIDE issuer: compute the grant digest + guard signature over the exact canonical tuple.
 *  The guard holds the signing key; the source only verifies (both use `leaseGrantMsg`). */
export function signLeaseGrant(guardKeyId: string, guardSecret: Buffer | string, bare: BareLeaseGrant): LeaseGrant {
  if (!KEY_ID_RE.test(guardKeyId)) throw new ContractValidationError('invalid guard keyId');
  vId(bare.streamId, STREAM_ID_RE, 'streamId'); vId(bare.holderNodeId, ID_RE, 'holderNodeId');
  vId(bare.leaseId, ID_RE, 'leaseId'); vId(bare.commandId, ID_RE, 'commandId');
  vInt(bare.leaseEpoch, 'leaseEpoch', 0, MAX_EPOCH); vInt(bare.leaseGrantSeq, 'leaseGrantSeq', 1, MAX_SEQ);
  vInt(bare.leaseExpiresAtMs, 'leaseExpiresAtMs', 0, MAX_MS);
  if (bare.leaseStatus !== 'active' && bare.leaseStatus !== 'revoked') throw new ContractValidationError('invalid leaseStatus');
  vNullableDigest(bare.prevGrantDigest, 'prevGrantDigest');
  const digest = sha256hex(leaseGrantMsg(bare, ''));
  const secret = toSecret(guardSecret);
  const signature = createHmac('sha256', secret).update(withKey(guardKeyId, leaseGrantMsg(bare, digest))).digest().toString('base64url');
  return { ...bare, grantDigest: digest, guardKeyId, guardSignature: signature };
}
/** Recompute the grant digest + verify the guard signature over the exact canonical tuple. */
export function verifyLeaseGrant(resolver: GuardKeyResolver, g: LeaseGrant): void {
  vId(g.streamId, STREAM_ID_RE, 'streamId'); vId(g.holderNodeId, ID_RE, 'holderNodeId');
  vId(g.leaseId, ID_RE, 'leaseId'); vId(g.commandId, ID_RE, 'commandId');
  vInt(g.leaseEpoch, 'leaseEpoch', 0, MAX_EPOCH); vInt(g.leaseGrantSeq, 'leaseGrantSeq', 1, MAX_SEQ);
  vInt(g.leaseExpiresAtMs, 'leaseExpiresAtMs', 0, MAX_MS);
  if (g.leaseStatus !== 'active' && g.leaseStatus !== 'revoked') throw new ContractValidationError('invalid leaseStatus');
  vNullableDigest(g.prevGrantDigest, 'prevGrantDigest');
  const expect = sha256hex(leaseGrantMsg(g, ''));
  if (expect !== g.grantDigest) throw new ContractValidationError('lease grant digest mismatch');
  verifyGuard(resolver, g.guardKeyId, leaseGrantMsg(g, g.grantDigest), g.guardSignature);
}

// ── DDL: signed lease head + append-only history ─────────────────────────────

export const TSK_SOURCE_LEASE_SCHEMA = `
CREATE TABLE IF NOT EXISTS tsk_source_lease (
  stream_id            text PRIMARY KEY,
  lease_epoch          bigint NOT NULL CHECK (lease_epoch >= 0),
  lease_status         text   NOT NULL CHECK (lease_status IN ('active','revoked')),
  holder_node_id       text   NOT NULL,
  lease_id             text   NOT NULL,
  command_id           text   NOT NULL,
  lease_expires_at_ms  bigint NOT NULL CHECK (lease_expires_at_ms >= 0),
  lease_grant_seq      bigint NOT NULL CHECK (lease_grant_seq >= 1),
  prev_grant_digest    text CHECK (prev_grant_digest IS NULL OR prev_grant_digest ~ '^[0-9a-f]{64}$'),
  grant_digest         text   NOT NULL CHECK (grant_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id         text   NOT NULL,
  guard_signature      text   NOT NULL,
  updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tsk_source_lease_history (
  stream_id            text NOT NULL,
  lease_epoch          bigint NOT NULL CHECK (lease_epoch >= 0),
  lease_status         text   NOT NULL CHECK (lease_status IN ('active','revoked')),
  holder_node_id       text   NOT NULL,
  lease_id             text   NOT NULL,
  command_id           text   NOT NULL,
  lease_expires_at_ms  bigint NOT NULL CHECK (lease_expires_at_ms >= 0),
  lease_grant_seq      bigint NOT NULL CHECK (lease_grant_seq >= 1),
  prev_grant_digest    text CHECK (prev_grant_digest IS NULL OR prev_grant_digest ~ '^[0-9a-f]{64}$'),
  grant_digest         text   NOT NULL CHECK (grant_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id         text   NOT NULL,
  guard_signature      text   NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, lease_grant_seq),
  UNIQUE (stream_id, grant_digest),
  UNIQUE (stream_id, command_id)
)
`.trim();

export const TSK_SOURCE_LEASE_TABLES = ['tsk_source_lease', 'tsk_source_lease_history'] as const;

export class SourceFenceQuarantineError extends ContractValidationError {}

export interface LeaseState {
  streamId: string; leaseEpoch: number; leaseStatus: 'active' | 'revoked'; holderNodeId: string;
  leaseId: string; commandId: string; leaseExpiresAtMs: number; leaseGrantSeq: number; grantDigest: string;
}

const affectedOne = (res: { rowCount: number }, what: string): void => {
  if (res.rowCount !== 1) throw new ContractValidationError(`${what}: expected exactly 1 affected row, got ${res.rowCount}`);
};

/**
 * Install a control-issued, guard-verified `LeaseGrant`/`LeaseRevocation` on the source PG within an
 * existing tx: verify the signature; enforce a strictly-increasing `lease_grant_seq` whose
 * `prev_grant_digest` chains the current head; append the signed history row; forward-CAS the head.
 * Idempotent lost-ACK: the same `command_id` + identical tuple is a no-op; a reused `command_id` with
 * a different tuple → quarantine (also enforced by `UNIQUE(stream_id, command_id)`).
 */
export async function installLeaseGrant(exec: PgExecutor, resolver: GuardKeyResolver, g: LeaseGrant): Promise<LeaseState> {
  verifyLeaseGrant(resolver, g);
  const cur = await readSourceLease(exec, resolver, g.streamId);
  // idempotent: this exact grant already installed (by grant_seq + digest) → no-op
  if (cur && cur.leaseGrantSeq === g.leaseGrantSeq && cur.grantDigest === g.grantDigest) return cur;
  // command idempotency: same command already installed with the SAME tuple → return it; different → reject
  const byCmd = (await exec.query('SELECT lease_grant_seq, grant_digest FROM tsk_source_lease_history WHERE stream_id=$1 AND command_id=$2', [g.streamId, g.commandId])).rows[0];
  if (byCmd) {
    if (String(byCmd.grant_digest) !== g.grantDigest) throw new SourceFenceQuarantineError('lease command_id reused with a different grant tuple — quarantine');
    return (await readSourceLeaseAtSeq(exec, resolver, g.streamId, vInt(byCmd.lease_grant_seq, 'lease_grant_seq', 1, MAX_SEQ)))!;
  }
  const expectedSeq = (cur?.leaseGrantSeq ?? 0) + 1;
  if (g.leaseGrantSeq !== expectedSeq) throw new SourceFenceQuarantineError(`lease_grant_seq ${g.leaseGrantSeq} is not strictly-increasing (expected ${expectedSeq})`);
  const expectedPrev = cur?.grantDigest ?? null;
  if ((g.prevGrantDigest ?? null) !== expectedPrev) throw new SourceFenceQuarantineError('lease prev_grant_digest does not chain the current head');
  const cols = 'stream_id, lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature';
  const vals = [g.streamId, g.leaseEpoch, g.leaseStatus, g.holderNodeId, g.leaseId, g.commandId, g.leaseExpiresAtMs, g.leaseGrantSeq, g.prevGrantDigest, g.grantDigest, g.guardKeyId, g.guardSignature];
  await exec.query(`INSERT INTO tsk_source_lease_history (${cols}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, vals);
  if (expectedPrev === null) {
    await exec.query(`INSERT INTO tsk_source_lease (${cols}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, vals);
  } else {
    affectedOne(await exec.query('UPDATE tsk_source_lease SET lease_epoch=$2, lease_status=$3, holder_node_id=$4, lease_id=$5, command_id=$6, lease_expires_at_ms=$7, lease_grant_seq=$8, prev_grant_digest=$9, grant_digest=$10, guard_key_id=$11, guard_signature=$12, updated_at=now() WHERE stream_id=$1 AND grant_digest=$13', [...vals, expectedPrev]), 'source lease forward-CAS');
  }
  return { streamId: g.streamId, leaseEpoch: g.leaseEpoch, leaseStatus: g.leaseStatus, holderNodeId: g.holderNodeId, leaseId: g.leaseId, commandId: g.commandId, leaseExpiresAtMs: g.leaseExpiresAtMs, leaseGrantSeq: g.leaseGrantSeq, grantDigest: g.grantDigest };
}

function rowToLease(streamId: string, r: Record<string, unknown>): { state: LeaseState; digMsg: Buffer; sigMsg: Buffer; sig: string; keyId: string; digest: string } {
  const leaseEpoch = vInt(r.lease_epoch, 'lease_epoch', 0, MAX_EPOCH);
  const leaseStatus = String(r.lease_status) as 'active' | 'revoked';
  const holderNodeId = String(r.holder_node_id), leaseId = String(r.lease_id), commandId = String(r.command_id);
  const leaseExpiresAtMs = vInt(r.lease_expires_at_ms, 'lease_expires_at_ms', 0, MAX_MS);
  const leaseGrantSeq = vInt(r.lease_grant_seq, 'lease_grant_seq', 1, MAX_SEQ);
  const prevGrantDigest = vNullableDigest(r.prev_grant_digest, 'prev_grant_digest');
  const digest = String(r.grant_digest);
  if (!DIGEST_RE.test(digest)) throw new ContractValidationError('invalid grant_digest');
  const bare = { streamId, leaseEpoch, leaseStatus, holderNodeId, leaseId, commandId, leaseExpiresAtMs, leaseGrantSeq, prevGrantDigest };
  return { state: { ...bare, grantDigest: digest }, digMsg: leaseGrantMsg(bare, ''), sigMsg: leaseGrantMsg(bare, digest), sig: String(r.guard_signature), keyId: String(r.guard_key_id), digest };
}

/** Read + verify the current signed lease head (tamper-evident). Returns null if unleased. */
export async function readSourceLease(exec: PgExecutor, resolver: GuardKeyResolver, streamId: string): Promise<LeaseState | null> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const r = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease WHERE stream_id=$1', [s])).rows[0];
  if (!r) return null;
  const m = rowToLease(s, r);
  if (sha256hex(m.digMsg) !== m.digest) throw new ContractValidationError('lease head digest mismatch');
  verifyGuard(resolver, m.keyId, m.sigMsg, m.sig);
  return m.state;
}

async function readSourceLeaseAtSeq(exec: PgExecutor, resolver: GuardKeyResolver, streamId: string, seq: number): Promise<LeaseState | null> {
  const r = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease_history WHERE stream_id=$1 AND lease_grant_seq=$2', [streamId, seq])).rows[0];
  if (!r) return null;
  const m = rowToLease(streamId, r);
  if (sha256hex(m.digMsg) !== m.digest) throw new ContractValidationError('lease history digest mismatch');
  verifyGuard(resolver, m.keyId, m.sigMsg, m.sig);
  return m.state;
}

/**
 * (§A.2) THE GATE — assert the source is writable at `expectedEpoch` within the append tx.
 * Takes `FOR SHARE` on the lease head (held to commit); requires an active lease at the expected
 * epoch whose SIGNED absolute deadline has not passed on A's OWN clock (+ bounded skew). The
 * conflicting revoke UPDATE cannot commit until in-flight FOR SHARE appends finish, then new appends
 * fail here. Missing lease → fail closed.
 */
export async function assertSourceLeaseWritable(exec: PgExecutor, resolver: GuardKeyResolver, streamId: string, expectedEpoch: number, controlToASkewBoundMs: number): Promise<LeaseState> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const epoch = vInt(expectedEpoch, 'expectedEpoch', 0, MAX_EPOCH);
  const skew = vInt(controlToASkewBoundMs, 'controlToASkewBoundMs', 0, MAX_SKEW_MS);
  const r = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease WHERE stream_id=$1 FOR SHARE', [s])).rows[0];
  if (!r) throw new SourceFenceQuarantineError('no source lease — writer is not leased; fail closed');
  const m = rowToLease(s, r);
  if (sha256hex(m.digMsg) !== m.digest) throw new ContractValidationError('lease head digest mismatch');
  verifyGuard(resolver, m.keyId, m.sigMsg, m.sig);
  const st = m.state;
  if (st.leaseStatus !== 'active') throw new SourceFenceQuarantineError(`source lease is ${st.leaseStatus} — fenced; fail closed`);
  if (st.leaseEpoch !== epoch) throw new SourceFenceQuarantineError(`source lease epoch ${st.leaseEpoch} != expected ${epoch} — stale writer; fail closed`);
  // A's own clock; the signed deadline is on the control clock, bounded by the measured skew.
  const nowMs = vInt((await exec.query("SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint AS ms")).rows[0]?.ms, 'A clock now', 0, MAX_MS);
  if (nowMs >= st.leaseExpiresAtMs - skew) throw new SourceFenceQuarantineError('source lease deadline elapsed on A clock (+skew) — fail closed');
  return st;
}
