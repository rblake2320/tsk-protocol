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
import { createHash, sign as edSign, verify as edVerify, createPublicKey, createPrivateKey, type KeyObject } from 'node:crypto';

import { ContractValidationError } from './ha-outbox-contract.js';
import type { PgExecutor } from './tsk-hotp-outbox-pg.js';

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

// ── asymmetric ed25519 signing (C1: verifiers hold PUBLIC keys ONLY, never signer material) ──

/** Resolves a keyId to its ed25519 PUBLIC verify key (KeyObject or PEM/DER), or null if
 *  unknown/revoked. Verifiers (source, receiver B, control) hold ONLY public keys — so a verifier
 *  can NEVER forge a signature (unlike symmetric HMAC, where the verifier holds the signer secret). */
export interface SourceVerifyKeyResolver { resolve(keyId: string): KeyObject | string | null; }

function toPublicKey(k: KeyObject | string): KeyObject {
  const key = typeof k === 'string' ? createPublicKey(k) : k;
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') throw new ContractValidationError('verify key must be an ed25519 public key');
  return key;
}
function toPrivateKey(k: KeyObject | string): KeyObject {
  const key = typeof k === 'string' ? createPrivateKey(k) : k;
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new ContractValidationError('signing key must be an ed25519 private key');
  return key;
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
/** Bind the keyId INTO the signed bytes so a signature cannot be replayed under another keyId. */
const withKey = (keyId: string, msg: Buffer): Buffer => Buffer.concat([frame('tsk_src_key', keyId), msg]);

/** ed25519-sign over withKey(keyId, msg); returns a base64url signature. Holder of the PRIVATE key only. */
function edSignB64u(keyId: string, privateKey: KeyObject | string, msg: Buffer): string {
  if (!KEY_ID_RE.test(keyId)) throw new ContractValidationError('invalid keyId');
  return edSign(null, withKey(keyId, msg), toPrivateKey(privateKey)).toString('base64url');
}
/** Verify an ed25519 base64url signature over withKey(keyId, msg) using the resolver's PUBLIC key. */
function verifySig(resolver: SourceVerifyKeyResolver, keyId: string, msg: Buffer, signature: string): void {
  if (!KEY_ID_RE.test(keyId)) throw new ContractValidationError('invalid keyId');
  if (typeof signature !== 'string' || !B64U_CANON.test(signature)) throw new ContractValidationError('invalid signature encoding');
  const pub = resolver.resolve(keyId);
  if (pub === null) throw new ContractValidationError('unknown or revoked keyId');
  let sigBuf: Buffer;
  try { sigBuf = Buffer.from(signature, 'base64url'); } catch { throw new ContractValidationError('invalid signature encoding'); }
  if (!edVerify(null, withKey(keyId, msg), toPublicKey(pub), sigBuf)) throw new ContractValidationError('invalid signature');
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
export function signLeaseGrant(guardKeyId: string, guardPrivateKey: KeyObject | string, bare: BareLeaseGrant): LeaseGrant {
  if (!KEY_ID_RE.test(guardKeyId)) throw new ContractValidationError('invalid guard keyId');
  vId(bare.streamId, STREAM_ID_RE, 'streamId'); vId(bare.holderNodeId, ID_RE, 'holderNodeId');
  vId(bare.leaseId, ID_RE, 'leaseId'); vId(bare.commandId, ID_RE, 'commandId');
  vInt(bare.leaseEpoch, 'leaseEpoch', 0, MAX_EPOCH); vInt(bare.leaseGrantSeq, 'leaseGrantSeq', 1, MAX_SEQ);
  vInt(bare.leaseExpiresAtMs, 'leaseExpiresAtMs', 0, MAX_MS);
  if (bare.leaseStatus !== 'active' && bare.leaseStatus !== 'revoked') throw new ContractValidationError('invalid leaseStatus');
  vNullableDigest(bare.prevGrantDigest, 'prevGrantDigest');
  const digest = sha256hex(leaseGrantMsg(bare, ''));
  const signature = edSignB64u(guardKeyId, guardPrivateKey, leaseGrantMsg(bare, digest));
  return { ...bare, grantDigest: digest, guardKeyId, guardSignature: signature };
}
/** Recompute the grant digest + verify the guard signature over the exact canonical tuple. */
export function verifyLeaseGrant(resolver: SourceVerifyKeyResolver, g: LeaseGrant): void {
  vId(g.streamId, STREAM_ID_RE, 'streamId'); vId(g.holderNodeId, ID_RE, 'holderNodeId');
  vId(g.leaseId, ID_RE, 'leaseId'); vId(g.commandId, ID_RE, 'commandId');
  vInt(g.leaseEpoch, 'leaseEpoch', 0, MAX_EPOCH); vInt(g.leaseGrantSeq, 'leaseGrantSeq', 1, MAX_SEQ);
  vInt(g.leaseExpiresAtMs, 'leaseExpiresAtMs', 0, MAX_MS);
  if (g.leaseStatus !== 'active' && g.leaseStatus !== 'revoked') throw new ContractValidationError('invalid leaseStatus');
  vNullableDigest(g.prevGrantDigest, 'prevGrantDigest');
  const expect = sha256hex(leaseGrantMsg(g, ''));
  if (expect !== g.grantDigest) throw new ContractValidationError('lease grant digest mismatch');
  verifySig(resolver, g.guardKeyId, leaseGrantMsg(g, g.grantDigest), g.guardSignature);
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
export async function installLeaseGrant(exec: PgExecutor, resolver: SourceVerifyKeyResolver, g: LeaseGrant): Promise<LeaseState> {
  verifyLeaseGrant(resolver, g);
  // (H2) serialize installs per stream so concurrent grants/revokes cannot interleave.
  await exec.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [g.streamId]);
  const cur = await readSourceLease(exec, resolver, g.streamId);
  // (H2) the head MUST be the latest history row (no replay of an older validly-signed head).
  if (cur) {
    const maxSeq = vInt((await exec.query('SELECT COALESCE(max(lease_grant_seq), 0) AS m FROM tsk_source_lease_history WHERE stream_id=$1', [g.streamId])).rows[0].m, 'max lease seq', 0, MAX_SEQ);
    if (cur.leaseGrantSeq !== maxSeq) throw new SourceFenceQuarantineError('lease head is not the latest history row (replay/rollback) — quarantine');
  }
  // idempotent: this exact grant already installed (by grant_seq + digest) → no-op
  if (cur && cur.leaseGrantSeq === g.leaseGrantSeq && cur.grantDigest === g.grantDigest) return cur;
  // command idempotency: same command already installed with the SAME tuple → return it; different → reject
  const byCmd = (await exec.query('SELECT lease_grant_seq, grant_digest FROM tsk_source_lease_history WHERE stream_id=$1 AND command_id=$2', [g.streamId, g.commandId])).rows[0];
  if (byCmd) {
    if (String(byCmd.grant_digest) !== g.grantDigest) throw new SourceFenceQuarantineError('lease command_id reused with a different grant tuple — quarantine');
    return (await readSourceLeaseAtSeq(exec, resolver, g.streamId, vInt(byCmd.lease_grant_seq, 'lease_grant_seq', 1, MAX_SEQ)))!;
  }
  // (H2) epoch monotonicity: a grant cannot regress the lease epoch.
  if (cur && g.leaseEpoch < cur.leaseEpoch) throw new SourceFenceQuarantineError(`lease epoch ${g.leaseEpoch} regresses the current ${cur.leaseEpoch} — quarantine`);
  // (H2) holder/leaseId are IMMUTABLE within an epoch — the first grant fixes the writer identity.
  const firstAtEpoch = (await exec.query('SELECT holder_node_id, lease_id FROM tsk_source_lease_history WHERE stream_id=$1 AND lease_epoch=$2 ORDER BY lease_grant_seq ASC LIMIT 1', [g.streamId, g.leaseEpoch])).rows[0];
  if (firstAtEpoch && (String(firstAtEpoch.holder_node_id) !== g.holderNodeId || String(firstAtEpoch.lease_id) !== g.leaseId)) {
    throw new SourceFenceQuarantineError('lease holder/leaseId is immutable within an epoch — advance the epoch to change the writer');
  }
  // (C4/H2) TERMINAL revoke: once revoked at an epoch, no new ACTIVE grant at that epoch — the freeze
  // is terminal; a new writer requires an epoch advance (prevents same-epoch reactivation of A).
  if (g.leaseStatus === 'active') {
    const revoked = (await exec.query("SELECT 1 FROM tsk_source_lease_history WHERE stream_id=$1 AND lease_epoch=$2 AND lease_status='revoked' LIMIT 1", [g.streamId, g.leaseEpoch])).rows[0];
    if (revoked) throw new SourceFenceQuarantineError('epoch is terminally revoked — no same-epoch reactivation; advance the epoch');
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
export async function readSourceLease(exec: PgExecutor, resolver: SourceVerifyKeyResolver, streamId: string): Promise<LeaseState | null> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const r = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease WHERE stream_id=$1', [s])).rows[0];
  if (!r) return null;
  const m = rowToLease(s, r);
  if (sha256hex(m.digMsg) !== m.digest) throw new ContractValidationError('lease head digest mismatch');
  verifySig(resolver, m.keyId, m.sigMsg, m.sig);
  return m.state;
}

async function readSourceLeaseAtSeq(exec: PgExecutor, resolver: SourceVerifyKeyResolver, streamId: string, seq: number): Promise<LeaseState | null> {
  const r = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease_history WHERE stream_id=$1 AND lease_grant_seq=$2', [streamId, seq])).rows[0];
  if (!r) return null;
  const m = rowToLease(streamId, r);
  if (sha256hex(m.digMsg) !== m.digest) throw new ContractValidationError('lease history digest mismatch');
  verifySig(resolver, m.keyId, m.sigMsg, m.sig);
  return m.state;
}

/**
 * (§A.2) THE GATE — assert the source is writable at `expectedEpoch` within the append tx.
 * Takes `FOR SHARE` on the lease head (held to commit); requires an active lease at the expected
 * epoch whose SIGNED absolute deadline has not passed on A's OWN clock (+ bounded skew). The
 * conflicting revoke UPDATE cannot commit until in-flight FOR SHARE appends finish, then new appends
 * fail here. Missing lease → fail closed.
 */
export async function assertSourceLeaseWritable(exec: PgExecutor, resolver: SourceVerifyKeyResolver, streamId: string, expectedEpoch: number, controlToASkewBoundMs: number): Promise<LeaseState> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const epoch = vInt(expectedEpoch, 'expectedEpoch', 0, MAX_EPOCH);
  const skew = vInt(controlToASkewBoundMs, 'controlToASkewBoundMs', 0, MAX_SKEW_MS);
  const r = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease WHERE stream_id=$1 FOR SHARE', [s])).rows[0];
  if (!r) throw new SourceFenceQuarantineError('no source lease — writer is not leased; fail closed');
  const m = rowToLease(s, r);
  if (sha256hex(m.digMsg) !== m.digest) throw new ContractValidationError('lease head digest mismatch');
  verifySig(resolver, m.keyId, m.sigMsg, m.sig);
  const st = m.state;
  if (st.leaseStatus !== 'active') throw new SourceFenceQuarantineError(`source lease is ${st.leaseStatus} — fenced; fail closed`);
  if (st.leaseEpoch !== epoch) throw new SourceFenceQuarantineError(`source lease epoch ${st.leaseEpoch} != expected ${epoch} — stale writer; fail closed`);
  // A's own clock; the signed deadline is on the control clock, bounded by the measured skew.
  const nowMs = vInt((await exec.query("SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint AS ms")).rows[0]?.ms, 'A clock now', 0, MAX_MS);
  if (nowMs >= st.leaseExpiresAtMs - skew) throw new SourceFenceQuarantineError('source lease deadline elapsed on A clock (+skew) — fail closed');
  return st;
}

// ── SourceFrozenReceipt (§1) — attest the frozen N after the revoke commits ──

/** Source-signed attestation of the frozen source authority at the fence. `N` is provable ONLY
 *  after the A-PG revoke commits (this reads a REVOKED lease + the committed source head). */
export interface SourceFrozenReceipt {
  streamId: string; commandId: string; epoch: number; n: number;
  signedHeadDigestAtN: string; sourceStateDigestAtN: string; sourceNodeId: string;
  // (C4) bind the REVOKE that fenced A: its command, the fenced writer's lease identity + grant digest.
  revokeCommandId: string; leaseId: string; leaseGrantDigest: string;
  receiptDigest: string; sourceKeyId: string; sourceSignature: string;
}
type BareFrozenReceipt = Omit<SourceFrozenReceipt, 'receiptDigest' | 'sourceKeyId' | 'sourceSignature'>;
function frozenReceiptMsg(b: BareFrozenReceipt, digest: string): Buffer {
  return frame('tsk_source_frozen/v2', b.streamId, b.commandId, b.epoch, b.n, b.signedHeadDigestAtN, b.sourceStateDigestAtN, b.sourceNodeId,
    b.revokeCommandId, b.leaseId, b.leaseGrantDigest, digest);
}

/** Canonical digest of the state-at-`N`: the (tumblerId → latest HOTP counter at seq ≤ N) map,
 *  sorted APPLICATION-CANONICALLY by tumblerId bytes (NOT DB collation), so B's independent replay
 *  reproduces it exactly regardless of the server's LC_COLLATE. */
export async function computeSourceStateDigest(exec: PgExecutor, streamId: string, n: number): Promise<string> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const N = vInt(n, 'n', 0, MAX_SEQ);
  // DISTINCT ON picks the latest counter per tumbler (via sequence DESC); the outer order is then
  // re-imposed in JS by raw tumblerId bytes — the DB's ORDER BY collation never reaches the digest.
  const rows = (await exec.query('SELECT DISTINCT ON (tumbler_id) tumbler_id, hotp_counter FROM tsk_outbox_rows WHERE stream_id=$1 AND sequence <= $2 ORDER BY tumbler_id, sequence DESC', [s, N])).rows;
  const pairs = rows.map((r) => [String(r.tumbler_id), vInt(r.hotp_counter, 'hotp_counter', 1, 2 ** 31 - 1)] as [string, number]);
  pairs.sort((a, b) => Buffer.compare(Buffer.from(a[0], 'utf8'), Buffer.from(b[0], 'utf8')));
  const parts: (string | number)[] = ['tsk_source_state/v1', s, N, pairs.length];
  for (const [t, c] of pairs) parts.push(t, c);
  return sha256hex(frame(...parts));
}

/** CONTROL/SOURCE issuer: sign a frozen receipt over the exact canonical tuple (source custody). */
export function signSourceFrozenReceipt(sourceKeyId: string, sourcePrivateKey: KeyObject | string, b: BareFrozenReceipt): SourceFrozenReceipt {
  if (!KEY_ID_RE.test(sourceKeyId)) throw new ContractValidationError('invalid source keyId');
  vId(b.streamId, STREAM_ID_RE, 'streamId'); vId(b.commandId, ID_RE, 'commandId'); vId(b.sourceNodeId, ID_RE, 'sourceNodeId');
  vId(b.revokeCommandId, ID_RE, 'revokeCommandId'); vId(b.leaseId, ID_RE, 'leaseId');
  vInt(b.epoch, 'epoch', 0, MAX_EPOCH); vInt(b.n, 'n', 0, MAX_SEQ);
  if (!DIGEST_RE.test(b.signedHeadDigestAtN)) throw new ContractValidationError('invalid signedHeadDigestAtN');
  if (!DIGEST_RE.test(b.sourceStateDigestAtN)) throw new ContractValidationError('invalid sourceStateDigestAtN');
  if (!DIGEST_RE.test(b.leaseGrantDigest)) throw new ContractValidationError('invalid leaseGrantDigest');
  const receiptDigest = sha256hex(frozenReceiptMsg(b, ''));
  const sourceSignature = edSignB64u(sourceKeyId, sourcePrivateKey, frozenReceiptMsg(b, receiptDigest));
  return { ...b, receiptDigest, sourceKeyId, sourceSignature };
}

/** Verify a frozen receipt's digest + source signature (the resolver holds the source PUBLIC key). */
export function verifySourceFrozenReceipt(resolver: SourceVerifyKeyResolver, r: SourceFrozenReceipt): void {
  const bare: BareFrozenReceipt = { streamId: r.streamId, commandId: r.commandId, epoch: r.epoch, n: r.n, signedHeadDigestAtN: r.signedHeadDigestAtN, sourceStateDigestAtN: r.sourceStateDigestAtN, sourceNodeId: r.sourceNodeId, revokeCommandId: r.revokeCommandId, leaseId: r.leaseId, leaseGrantDigest: r.leaseGrantDigest };
  if (sha256hex(frozenReceiptMsg(bare, '')) !== r.receiptDigest) throw new ContractValidationError('frozen receipt digest mismatch');
  verifySig(resolver, r.sourceKeyId, frozenReceiptMsg(bare, r.receiptDigest), r.sourceSignature);
}

/**
 * Emit a SourceFrozenReceipt AFTER the A-PG revoke has committed. Asserts the lease is REVOKED at
 * `epoch` (the freeze is proven, not merely control-clock expiry), reads the committed final source
 * head `N` + `signedHeadDigest@N` from the source checkpoint, computes `sourceStateDigest@N`, and
 * source-signs the receipt. Fails closed if the lease is not revoked at `epoch`.
 */
export async function emitSourceFrozenReceipt(exec: PgExecutor, resolver: SourceVerifyKeyResolver, sourceKeyId: string, sourcePrivateKey: KeyObject | string, input: { streamId: string; commandId: string; epoch: number; sourceNodeId: string }): Promise<SourceFrozenReceipt> {
  const s = vId(input.streamId, STREAM_ID_RE, 'streamId');
  const commandId = vId(input.commandId, ID_RE, 'commandId');
  const epoch = vInt(input.epoch, 'epoch', 0, MAX_EPOCH);
  const sourceNodeId = vId(input.sourceNodeId, ID_RE, 'sourceNodeId');
  // (C4) SERIALIZABLE-lock the EXACT revoked lease head FOR UPDATE + the checkpoint, so the frozen N
  // is captured against a state that cannot change under this tx.
  const lr = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease WHERE stream_id=$1 FOR UPDATE', [s])).rows[0];
  if (!lr) throw new SourceFenceQuarantineError('cannot freeze: no source lease');
  const m = rowToLease(s, lr);
  if (sha256hex(m.digMsg) !== m.digest) throw new ContractValidationError('lease head digest mismatch');
  verifySig(resolver, m.keyId, m.sigMsg, m.sig);
  const lease = m.state;
  if (lease.leaseEpoch !== epoch) throw new SourceFenceQuarantineError(`cannot freeze: lease epoch ${lease.leaseEpoch} != ${epoch}`);
  if (lease.leaseStatus !== 'revoked') throw new SourceFenceQuarantineError('cannot freeze: lease is not revoked — N is not provably frozen');
  if (lease.holderNodeId !== sourceNodeId) throw new SourceFenceQuarantineError(`cannot freeze: sourceNodeId ${sourceNodeId} != fenced lease holder ${lease.holderNodeId}`);
  const cp = (await exec.query('SELECT sequence, head_digest FROM tsk_outbox_source_checkpoint WHERE stream_id=$1 FOR UPDATE', [s])).rows[0];
  if (!cp) throw new SourceFenceQuarantineError('cannot freeze: no source checkpoint');
  const n = vInt(cp.sequence, 'source sequence', 0, MAX_SEQ);
  const headDigest = String(cp.head_digest || '') || GENESIS_HEAD_ZERO;
  if (!DIGEST_RE.test(headDigest)) throw new ContractValidationError('invalid source head_digest at freeze');
  const sourceStateDigestAtN = await computeSourceStateDigest(exec, s, n);
  return signSourceFrozenReceipt(sourceKeyId, sourcePrivateKey, { streamId: s, commandId, epoch, n, signedHeadDigestAtN: headDigest, sourceStateDigestAtN, sourceNodeId, revokeCommandId: lease.commandId, leaseId: lease.leaseId, leaseGrantDigest: lease.grantDigest });
}

const GENESIS_HEAD_ZERO = '0'.repeat(64);

// ── external restore/fork witness (§A.3) — lives on the CONTROL DB ────────────

/** An external, guard-signed, monotonic witness of the source's high-water state. It lives on the
 *  CONTROL DB (the source cannot roll it back), so a source-PG RESTORE that rolls back grant_seq /
 *  source seq / head is detected as a regression, and a divergent head at the same seq as a FORK. */
export const TSK_SOURCE_WITNESS_SCHEMA = `
CREATE TABLE IF NOT EXISTS tsk_source_witness (
  stream_id            text PRIMARY KEY,
  source_system_id     text   NOT NULL,
  max_grant_seq        bigint NOT NULL CHECK (max_grant_seq >= 0),
  max_source_seq       bigint NOT NULL CHECK (max_source_seq >= 0),
  source_head_digest   text   NOT NULL CHECK (source_head_digest ~ '^[0-9a-f]{64}$'),
  witness_seq          bigint NOT NULL CHECK (witness_seq >= 1),
  prev_witness_digest  text CHECK (prev_witness_digest IS NULL OR prev_witness_digest ~ '^[0-9a-f]{64}$'),
  witness_digest       text   NOT NULL CHECK (witness_digest ~ '^[0-9a-f]{64}$'),
  guard_key_id         text   NOT NULL,
  guard_signature      text   NOT NULL,
  updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tsk_source_witness_history (
  stream_id text NOT NULL, source_system_id text NOT NULL, max_grant_seq bigint NOT NULL,
  max_source_seq bigint NOT NULL, source_head_digest text NOT NULL, witness_seq bigint NOT NULL,
  prev_witness_digest text, witness_digest text NOT NULL, guard_key_id text NOT NULL,
  guard_signature text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, witness_seq), UNIQUE (stream_id, witness_digest)
)
`.trim();

export const TSK_SOURCE_WITNESS_TABLES = ['tsk_source_witness', 'tsk_source_witness_history'] as const;

export interface SourceLiveState { sourceSystemId: string; grantSeq: number; sourceSeq: number; headDigest: string; }
export interface WitnessState { streamId: string; sourceSystemId: string; maxGrantSeq: number; maxSourceSeq: number; headDigest: string; witnessSeq: number; witnessDigest: string; }

const witnessMsg = (s: string, sysId: string, gs: number, ss: number, head: string, wseq: number, prev: string | null, digest: string): Buffer =>
  frame('tsk_source_witness/v1', s, sysId, gs, ss, head, wseq, prev, digest);

function vHeadDigest(v: unknown, label: string): string {
  const d = String(v);
  if (!DIGEST_RE.test(d)) throw new ContractValidationError(`invalid ${label}`);
  return d;
}

/** Read + verify the current signed witness head (tamper-evident). Null if none. */
export async function readSourceWitness(exec: PgExecutor, resolver: SourceVerifyKeyResolver, streamId: string): Promise<WitnessState | null> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const r = (await exec.query('SELECT source_system_id, max_grant_seq, max_source_seq, source_head_digest, witness_seq, prev_witness_digest, witness_digest, guard_key_id, guard_signature FROM tsk_source_witness WHERE stream_id=$1', [s])).rows[0];
  if (!r) return null;
  const sysId = String(r.source_system_id), gs = vInt(r.max_grant_seq, 'max_grant_seq', 0, MAX_SEQ), ss = vInt(r.max_source_seq, 'max_source_seq', 0, MAX_SEQ);
  const head = vHeadDigest(r.source_head_digest, 'source_head_digest'), wseq = vInt(r.witness_seq, 'witness_seq', 1, MAX_SEQ);
  const prev = vNullableDigest(r.prev_witness_digest, 'prev_witness_digest'), digest = vHeadDigest(r.witness_digest, 'witness_digest');
  if (sha256hex(witnessMsg(s, sysId, gs, ss, head, wseq, prev, '')) !== digest) throw new ContractValidationError('witness digest mismatch');
  verifySig(resolver, String(r.guard_key_id), witnessMsg(s, sysId, gs, ss, head, wseq, prev, digest), String(r.guard_signature));
  return { streamId: s, sourceSystemId: sysId, maxGrantSeq: gs, maxSourceSeq: ss, headDigest: head, witnessSeq: wseq, witnessDigest: digest };
}

/** (§A.3) Assert the live source high-water state is consistent with the external witness. A regression
 *  (grant_seq / source seq below the witness = restore/rollback), a divergent head at the witness seq
 *  (= same-height fork), or a changed system_identifier → QUARANTINE. No witness yet → genesis (ok). */
export function assertSourceWitnessConsistent(witness: WitnessState | null, live: SourceLiveState): void {
  if (witness === null) return; // genesis — the first advance stamps it
  if (live.sourceSystemId !== witness.sourceSystemId) throw new SourceFenceQuarantineError(`source system_identifier changed (${live.sourceSystemId} != witnessed ${witness.sourceSystemId}) — restore/clone; quarantine`);
  if (live.grantSeq < witness.maxGrantSeq) throw new SourceFenceQuarantineError(`live grant_seq ${live.grantSeq} < witnessed ${witness.maxGrantSeq} — restore/rollback; quarantine`);
  if (live.sourceSeq < witness.maxSourceSeq) throw new SourceFenceQuarantineError(`live source seq ${live.sourceSeq} < witnessed ${witness.maxSourceSeq} — restore/rollback; quarantine`);
  if (live.sourceSeq === witness.maxSourceSeq && vHeadDigest(live.headDigest, 'live.headDigest') !== witness.headDigest) {
    throw new SourceFenceQuarantineError('live head digest diverges from the witness at the same source seq — same-height FORK; quarantine');
  }
}

/** Monotonically advance the external witness (guard-signed forward-CAS). Rejects a regression/fork
 *  (via assertSourceWitnessConsistent against the incoming high-water) before stamping. */
export async function advanceSourceWitness(exec: PgExecutor, resolver: SourceVerifyKeyResolver, guardKeyId: string, guardPrivateKey: KeyObject | string, entry: SourceLiveState & { streamId: string }): Promise<WitnessState> {
  const s = vId(entry.streamId, STREAM_ID_RE, 'streamId');
  const sysId = vId(entry.sourceSystemId, ID_RE, 'sourceSystemId');
  const gs = vInt(entry.grantSeq, 'grantSeq', 0, MAX_SEQ), ss = vInt(entry.sourceSeq, 'sourceSeq', 0, MAX_SEQ);
  const head = vHeadDigest(entry.headDigest, 'headDigest');
  if (!KEY_ID_RE.test(guardKeyId)) throw new ContractValidationError('invalid guard keyId');
  const cur = await readSourceWitness(exec, resolver, s);
  // idempotent re-advance (crash-resume): an identical high-water is a no-op, not a new witness seq.
  if (cur && cur.sourceSystemId === sysId && cur.maxGrantSeq === gs && cur.maxSourceSeq === ss && cur.headDigest === head) return cur;
  assertSourceWitnessConsistent(cur, { sourceSystemId: sysId, grantSeq: gs, sourceSeq: ss, headDigest: head });
  const wseq = (cur?.witnessSeq ?? 0) + 1;
  const prev = cur?.witnessDigest ?? null;
  const digest = sha256hex(witnessMsg(s, sysId, gs, ss, head, wseq, prev, ''));
  const sig = edSignB64u(guardKeyId, guardPrivateKey, witnessMsg(s, sysId, gs, ss, head, wseq, prev, digest));
  const cols = 'stream_id, source_system_id, max_grant_seq, max_source_seq, source_head_digest, witness_seq, prev_witness_digest, witness_digest, guard_key_id, guard_signature';
  const vals = [s, sysId, gs, ss, head, wseq, prev, digest, guardKeyId, sig];
  await exec.query(`INSERT INTO tsk_source_witness_history (${cols}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, vals);
  if (prev === null) {
    await exec.query(`INSERT INTO tsk_source_witness (${cols}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, vals);
  } else {
    affectedOne(await exec.query('UPDATE tsk_source_witness SET source_system_id=$2, max_grant_seq=$3, max_source_seq=$4, source_head_digest=$5, witness_seq=$6, prev_witness_digest=$7, witness_digest=$8, guard_key_id=$9, guard_signature=$10, updated_at=now() WHERE stream_id=$1 AND witness_digest=$11', [...vals, prev]), 'witness forward-CAS');
  }
  return { streamId: s, sourceSystemId: sysId, maxGrantSeq: gs, maxSourceSeq: ss, headDigest: head, witnessSeq: wseq, witnessDigest: digest };
}
