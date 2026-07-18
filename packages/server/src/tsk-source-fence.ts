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
import { createHash, sign as edSign, verify as edVerify, createPrivateKey, type KeyObject } from 'node:crypto';

import { ContractValidationError, assertStreamHeadBinds } from './ha-outbox-contract.js';
import type { OutboxRecordHeader, SignedStreamHead, StreamHeadAlg } from './ha-outbox-contract.js';
import type { PgExecutor, PgTransactor } from './tsk-hotp-outbox-pg.js';

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

/** Resolves a keyId to its ed25519 PUBLIC verify `KeyObject`, or null if unknown/revoked. Verifiers
 *  (source, receiver B, control) hold ONLY public keys — so a verifier can NEVER forge a signature.
 *  (H2) The resolver returns a `KeyObject` ONLY — never a PEM/DER string. A string public key would let
 *  `createPublicKey(<PRIVATE PKCS8 PEM>)` silently DERIVE a public key from private material handed to
 *  the verifier, so the verifier's config could hold the signer's private key while appearing
 *  "public-only". A public `KeyObject` provably carries no private bytes; a private/secret `KeyObject`
 *  is rejected at the boundary below. */
export interface SourceVerifyKeyResolver { resolve(keyId: string): KeyObject | null; }

function toPublicKey(k: KeyObject): KeyObject {
  // (H2) accept ONLY a public ed25519 KeyObject — reject strings/PEM/DER and any private/secret material.
  if (k === null || typeof k !== 'object' || typeof (k as KeyObject).asymmetricKeyType === 'undefined') {
    throw new ContractValidationError('verify key must be a public ed25519 KeyObject (no PEM/DER/private material)');
  }
  if (k.type !== 'public' || k.asymmetricKeyType !== 'ed25519') throw new ContractValidationError('verify key must be an ed25519 PUBLIC key (private/secret material rejected)');
  return k;
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
  // (H4) readSourceLease verifies the head IS the exact latest row of a contiguous signed chain from
  // genesis (no replay of an older validly-signed head, no same-seq fork/relabel, no deleted intermediate).
  const cur = await readSourceLease(exec, resolver, g.streamId);
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

/** (H2/H4) Verify the FULL signed lease chain given an already-read+verified head: every history row
 *  is signed + digest-valid, the seq is contiguous 1..N from genesis, each `prev_grant_digest` chains
 *  the prior row, and the head is EXACTLY the latest history row (same seq AND digest). A same-seq
 *  fork, a relabelled head, a deleted intermediate row, or a head that is not the latest → quarantine. */
async function verifyLeaseHistoryChain(exec: PgExecutor, resolver: SourceVerifyKeyResolver, s: string, head: LeaseState | null): Promise<void> {
  const rows = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease_history WHERE stream_id=$1 ORDER BY lease_grant_seq ASC', [s])).rows;
  if (rows.length === 0) {
    if (head !== null) throw new SourceFenceQuarantineError('lease head present with no history — fork/relabel; quarantine');
    return;
  }
  let prev: string | null = null;
  let last: LeaseState | null = null;
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i] as Record<string, unknown>;
    const m = rowToLease(s, row);
    if (sha256hex(m.digMsg) !== m.digest) throw new ContractValidationError('lease history digest mismatch');
    verifySig(resolver, m.keyId, m.sigMsg, m.sig);
    if (m.state.leaseGrantSeq !== i + 1) throw new SourceFenceQuarantineError(`lease history seq ${m.state.leaseGrantSeq} is not contiguous from genesis (expected ${i + 1}) — quarantine`);
    if (vNullableDigest(row.prev_grant_digest, 'prev_grant_digest') !== prev) throw new SourceFenceQuarantineError('lease history prev_grant_digest chain broken — fork/relabel; quarantine');
    prev = m.digest; last = m.state;
  }
  if (head === null || last === null || head.leaseGrantSeq !== last.leaseGrantSeq || head.grantDigest !== last.grantDigest) {
    throw new SourceFenceQuarantineError('lease head is not the exact latest history row (fork/relabel/rollback) — quarantine');
  }
}

/** Read + verify the current signed lease head AND its full contiguous signed chain from genesis
 *  (H2 — a decision-grade read is never head-only). Returns null if unleased. */
export async function readSourceLease(exec: PgExecutor, resolver: SourceVerifyKeyResolver, streamId: string): Promise<LeaseState | null> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const r = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease WHERE stream_id=$1', [s])).rows[0];
  const head = r ? verifiedLeaseHead(s, r as Record<string, unknown>, resolver) : null;
  await verifyLeaseHistoryChain(exec, resolver, s, head);
  return head;
}

function verifiedLeaseHead(s: string, r: Record<string, unknown>, resolver: SourceVerifyKeyResolver): LeaseState {
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
export async function assertSourceLeaseWritable(exec: PgExecutor, resolver: SourceVerifyKeyResolver, streamId: string, expectedEpoch: number, controlToASkewBoundMs: number, bound: { holderNodeId: string; leaseId: string; grantDigest: string }): Promise<LeaseState> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const epoch = vInt(expectedEpoch, 'expectedEpoch', 0, MAX_EPOCH);
  const skew = vInt(controlToASkewBoundMs, 'controlToASkewBoundMs', 0, MAX_SKEW_MS);
  // (H1) identity binding is MANDATORY — the caller MUST pass the authorized writer identity.
  if (!bound || typeof bound !== 'object') throw new ContractValidationError('assertSourceLeaseWritable requires an authorized {holderNodeId, leaseId, grantDigest} binding');
  vId(bound.holderNodeId, ID_RE, 'bound.holderNodeId'); vId(bound.leaseId, ID_RE, 'bound.leaseId');
  if (!DIGEST_RE.test(bound.grantDigest)) throw new ContractValidationError('invalid bound.grantDigest');
  const r = (await exec.query('SELECT lease_epoch, lease_status, holder_node_id, lease_id, command_id, lease_expires_at_ms, lease_grant_seq, prev_grant_digest, grant_digest, guard_key_id, guard_signature FROM tsk_source_lease WHERE stream_id=$1 FOR SHARE', [s])).rows[0];
  if (!r) throw new SourceFenceQuarantineError('no source lease — writer is not leased; fail closed');
  const st = verifiedLeaseHead(s, r as Record<string, unknown>, resolver);
  // (M1) BOUNDED per-append check — O(1), no history scan. The `bound.grantDigest` comes from a
  // `SourceFenceReadyToken` that was minted only after `assertSourceFenceReady` FULL-CHAIN-verified the
  // lease AND pinned this exact grantDigest; so a head whose signed grantDigest still equals `bound`
  // is the same verified-chain high-water. A renewal changes the head grantDigest → a new token must be
  // minted (re-verifying the chain). DEPLOYMENT BOUNDARY: the runtime source role MUST have no
  // UPDATE/DELETE on tsk_source_lease / _history except via the separately-authorized installer — the
  // append path deliberately does NOT re-scan the whole chain on every write (availability).
  if (st.leaseStatus !== 'active') throw new SourceFenceQuarantineError(`source lease is ${st.leaseStatus} — fenced; fail closed`);
  if (st.leaseEpoch !== epoch) throw new SourceFenceQuarantineError(`source lease epoch ${st.leaseEpoch} != expected ${epoch} — stale writer; fail closed`);
  // A's own clock; the signed deadline is on the control clock, bounded by the measured skew.
  const nowMs = vInt((await exec.query("SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint AS ms")).rows[0]?.ms, 'A clock now', 0, MAX_MS);
  if (nowMs >= st.leaseExpiresAtMs - skew) throw new SourceFenceQuarantineError('source lease deadline elapsed on A clock (+skew) — fail closed');
  // (C2/H1) identity binding (MANDATORY): the live lease must be the SAME holder+leaseId+grant this
  // writer was authorized for. A different writer that is legitimately leased at the same epoch (holder
  // pivot or a renewed grant this writer was not authorized for) fails closed rather than silently writing.
  if (st.holderNodeId !== bound.holderNodeId) throw new SourceFenceQuarantineError(`source lease holder ${st.holderNodeId} != authorized ${bound.holderNodeId} — fail closed`);
  if (st.leaseId !== bound.leaseId) throw new SourceFenceQuarantineError(`source lease id ${st.leaseId} != authorized ${bound.leaseId} — fail closed`);
  if (st.grantDigest !== bound.grantDigest) throw new SourceFenceQuarantineError('source lease grant digest != authorized grant — fail closed');
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

const GENESIS_HEAD_ZERO = '0'.repeat(64);

/** Options for the owned frozen-receipt emitter. `leaseResolver` = guard PUBLIC key (verify the lease
 *  chain); `headResolver` = outbox head-signer PUBLIC key (verify the signed ledger). */
export interface FrozenReceiptOptions {
  sourceKeyId: string; sourcePrivateKey: KeyObject | string;
  leaseResolver: SourceVerifyKeyResolver; headResolver: SourceVerifyKeyResolver;
}

/**
 * (H4/R4) Emit a SourceFrozenReceipt AFTER the A-PG revoke has committed — a TRANSACTOR-OWNED,
 * SERIALIZABLE, schema-pinned, attested authority (the raw `signSourceFrozenReceipt` is NOT on the
 * public API). Full-chain-verifies the terminally-REVOKED lease at `epoch` with the exact holder, then
 * derives the frozen head `N` from the SIGNED append-only ledger via the shared full-range verifier
 * (the mutable checkpoint pointer must agree) and computes `sourceStateDigest@N` before source-signing.
 * Fails closed unless the lease is revoked at `epoch` for the exact holder.
 */
export async function emitSourceFrozenReceipt(db: PgTransactor, schema: string, opts: FrozenReceiptOptions, input: { streamId: string; commandId: string; epoch: number; sourceNodeId: string }): Promise<SourceFrozenReceipt> {
  const s = vId(input.streamId, STREAM_ID_RE, 'streamId');
  const commandId = vId(input.commandId, ID_RE, 'commandId');
  const epoch = vInt(input.epoch, 'epoch', 0, MAX_EPOCH);
  const sourceNodeId = vId(input.sourceNodeId, ID_RE, 'sourceNodeId');
  return db.transaction(async (exec) => {
    await enterSourceTx(exec, schema);
    await attestSourceLease(exec);
    // lock + FULL-CHAIN verify the terminally-revoked lease (the freeze is proven, not clock expiry)
    await exec.query('SELECT 1 FROM tsk_source_lease WHERE stream_id=$1 FOR UPDATE', [s]);
    const lease = await readSourceLease(exec, opts.leaseResolver, s);
    if (!lease) throw new SourceFenceQuarantineError('cannot freeze: no source lease');
    if (lease.leaseEpoch !== epoch) throw new SourceFenceQuarantineError(`cannot freeze: lease epoch ${lease.leaseEpoch} != ${epoch}`);
    if (lease.leaseStatus !== 'revoked') throw new SourceFenceQuarantineError('cannot freeze: lease is not revoked — N is not provably frozen');
    if (lease.holderNodeId !== sourceNodeId) throw new SourceFenceQuarantineError(`cannot freeze: sourceNodeId ${sourceNodeId} != fenced lease holder ${lease.holderNodeId}`);
    // derive N + head@N from the SIGNED ledger (checkpoint pointer must agree); N=0 = genesis freeze
    const cp = (await exec.query('SELECT source_epoch, sequence, head_digest FROM tsk_outbox_source_checkpoint WHERE stream_id=$1 FOR UPDATE', [s])).rows[0];
    if (!cp) throw new SourceFenceQuarantineError('cannot freeze: no source checkpoint');
    const cpEpoch = String(cp.source_epoch);
    const n = vInt(cp.sequence, 'source sequence', 0, MAX_SEQ);
    let headDigest = GENESIS_HEAD_ZERO;
    if (n >= 1) {
      headDigest = await verifyOutboxLedgerRange(exec, opts.headResolver, s, cpEpoch, 0, GENESIS_HEAD_ZERO, n);
      if (vHeadDigest(cp.head_digest, 'cp head') !== headDigest) throw new SourceFenceQuarantineError('checkpoint pointer diverges from the signed ledger head at N — quarantine');
    }
    const sourceStateDigestAtN = await computeSourceStateDigest(exec, s, n);
    return signSourceFrozenReceipt(opts.sourceKeyId, opts.sourcePrivateKey, { streamId: s, commandId, epoch, n, signedHeadDigestAtN: headDigest, sourceStateDigestAtN, sourceNodeId, revokeCommandId: lease.commandId, leaseId: lease.leaseId, leaseGrantDigest: lease.grantDigest });
  });
}

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

/** (C5) A SOURCE-SIGNED checkpoint attestation the witness advance verifies (never caller-supplied
 *  state): the source's current `(sourceSeq, sourceHeadDigest, grantSeq, system_id)` PLUS a
 *  continuity anchor — the source's head AT a prior seq (`priorSeq`/`priorHeadDigest`), which the
 *  witness pins to its own last-witnessed height so a restore+fork that grew BEYOND that height is
 *  caught (the source's head at the witnessed height would diverge). */
export interface SourceCheckpointReceipt {
  streamId: string; sourceSystemId: string; sourceSeq: number; sourceHeadDigest: string; grantSeq: number;
  priorSeq: number; priorHeadDigest: string; receiptDigest: string; sourceKeyId: string; sourceSignature: string;
}
type BareCheckpointReceipt = Omit<SourceCheckpointReceipt, 'receiptDigest' | 'sourceKeyId' | 'sourceSignature'>;
function checkpointReceiptMsg(b: BareCheckpointReceipt, digest: string): Buffer {
  return frame('tsk_source_checkpoint/v1', b.streamId, b.sourceSystemId, b.sourceSeq, b.sourceHeadDigest, b.grantSeq, b.priorSeq, b.priorHeadDigest, digest);
}
/** LOW-LEVEL signer over the exact canonical tuple (source custody). NB: this signs whatever caller
 *  state it is given — it does NOT derive from the committed ledger. The runtime/production path MUST
 *  use `issueSourceCheckpointReceipt` (atomic, schema-pinned, locked DB derivation); this primitive is
 *  retained only for protocol/continuity unit tests and internal use by the issuer. */
export function signSourceCheckpointReceipt(sourceKeyId: string, sourcePrivateKey: KeyObject | string, b: BareCheckpointReceipt): SourceCheckpointReceipt {
  vId(b.streamId, STREAM_ID_RE, 'streamId'); vId(b.sourceSystemId, ID_RE, 'sourceSystemId');
  vInt(b.sourceSeq, 'sourceSeq', 0, MAX_SEQ); vInt(b.grantSeq, 'grantSeq', 0, MAX_SEQ); vInt(b.priorSeq, 'priorSeq', 0, MAX_SEQ);
  vHeadDigest(b.sourceHeadDigest, 'sourceHeadDigest'); vHeadDigest(b.priorHeadDigest, 'priorHeadDigest');
  const receiptDigest = sha256hex(checkpointReceiptMsg(b, ''));
  const sourceSignature = edSignB64u(sourceKeyId, sourcePrivateKey, checkpointReceiptMsg(b, receiptDigest));
  return { ...b, receiptDigest, sourceKeyId, sourceSignature };
}
/** Verify a checkpoint receipt's digest + source signature (resolver holds the source PUBLIC key). */
export function verifySourceCheckpointReceipt(resolver: SourceVerifyKeyResolver, r: SourceCheckpointReceipt): void {
  const bare: BareCheckpointReceipt = { streamId: r.streamId, sourceSystemId: r.sourceSystemId, sourceSeq: r.sourceSeq, sourceHeadDigest: r.sourceHeadDigest, grantSeq: r.grantSeq, priorSeq: r.priorSeq, priorHeadDigest: r.priorHeadDigest };
  if (sha256hex(checkpointReceiptMsg(bare, '')) !== r.receiptDigest) throw new ContractValidationError('checkpoint receipt digest mismatch');
  verifySig(resolver, r.sourceKeyId, checkpointReceiptMsg(bare, r.receiptDigest), r.sourceSignature);
}

const witnessMsg = (s: string, sysId: string, gs: number, ss: number, head: string, wseq: number, prev: string | null, digest: string): Buffer =>
  frame('tsk_source_witness/v1', s, sysId, gs, ss, head, wseq, prev, digest);

function vHeadDigest(v: unknown, label: string): string {
  const d = String(v);
  if (!DIGEST_RE.test(d)) throw new ContractValidationError(`invalid ${label}`);
  return d;
}

function verifiedWitnessHead(s: string, r: Record<string, unknown>, resolver: SourceVerifyKeyResolver): WitnessState {
  const sysId = String(r.source_system_id), gs = vInt(r.max_grant_seq, 'max_grant_seq', 0, MAX_SEQ), ss = vInt(r.max_source_seq, 'max_source_seq', 0, MAX_SEQ);
  const head = vHeadDigest(r.source_head_digest, 'source_head_digest'), wseq = vInt(r.witness_seq, 'witness_seq', 1, MAX_SEQ);
  const prev = vNullableDigest(r.prev_witness_digest, 'prev_witness_digest'), digest = vHeadDigest(r.witness_digest, 'witness_digest');
  if (sha256hex(witnessMsg(s, sysId, gs, ss, head, wseq, prev, '')) !== digest) throw new ContractValidationError('witness digest mismatch');
  verifySig(resolver, String(r.guard_key_id), witnessMsg(s, sysId, gs, ss, head, wseq, prev, digest), String(r.guard_signature));
  return { streamId: s, sourceSystemId: sysId, maxGrantSeq: gs, maxSourceSeq: ss, headDigest: head, witnessSeq: wseq, witnessDigest: digest };
}

/** (H2/H4) Verify the FULL signed witness chain given an already-read+verified head: every
 *  witness_history row is signed + digest-valid, `witness_seq` is contiguous 1..N, each
 *  `prev_witness_digest` chains the prior row, and the head is EXACTLY the latest history row. */
async function verifyWitnessHistoryChain(exec: PgExecutor, resolver: SourceVerifyKeyResolver, s: string, head: WitnessState | null): Promise<void> {
  const rows = (await exec.query('SELECT source_system_id, max_grant_seq, max_source_seq, source_head_digest, witness_seq, prev_witness_digest, witness_digest, guard_key_id, guard_signature FROM tsk_source_witness_history WHERE stream_id=$1 ORDER BY witness_seq ASC', [s])).rows;
  if (rows.length === 0) {
    if (head !== null) throw new SourceFenceQuarantineError('witness head present with no history — fork/relabel; quarantine');
    return;
  }
  let prev: string | null = null;
  let lastSeq = 0, lastDigest = '';
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i] as Record<string, unknown>;
    const sysId = String(r.source_system_id), gs = vInt(r.max_grant_seq, 'max_grant_seq', 0, MAX_SEQ), ss = vInt(r.max_source_seq, 'max_source_seq', 0, MAX_SEQ);
    const hd = vHeadDigest(r.source_head_digest, 'source_head_digest'), wseq = vInt(r.witness_seq, 'witness_seq', 1, MAX_SEQ);
    const pv = vNullableDigest(r.prev_witness_digest, 'prev_witness_digest'), dg = vHeadDigest(r.witness_digest, 'witness_digest');
    if (sha256hex(witnessMsg(s, sysId, gs, ss, hd, wseq, pv, '')) !== dg) throw new ContractValidationError('witness history digest mismatch');
    verifySig(resolver, String(r.guard_key_id), witnessMsg(s, sysId, gs, ss, hd, wseq, pv, dg), String(r.guard_signature));
    if (wseq !== i + 1) throw new SourceFenceQuarantineError(`witness history seq ${wseq} is not contiguous from genesis (expected ${i + 1}) — quarantine`);
    if ((pv ?? null) !== prev) throw new SourceFenceQuarantineError('witness history prev_witness_digest chain broken — fork/relabel; quarantine');
    prev = dg; lastSeq = wseq; lastDigest = dg;
  }
  if (head === null || head.witnessSeq !== lastSeq || head.witnessDigest !== lastDigest) {
    throw new SourceFenceQuarantineError('witness head is not the exact latest history row (fork/relabel/rollback) — quarantine');
  }
}

/** Read + verify the current signed witness head AND its full contiguous signed chain from genesis
 *  (H2 — a decision-grade read is never head-only). Null if none. */
export async function readSourceWitness(exec: PgExecutor, resolver: SourceVerifyKeyResolver, streamId: string): Promise<WitnessState | null> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const r = (await exec.query('SELECT source_system_id, max_grant_seq, max_source_seq, source_head_digest, witness_seq, prev_witness_digest, witness_digest, guard_key_id, guard_signature FROM tsk_source_witness WHERE stream_id=$1', [s])).rows[0];
  const head = r ? verifiedWitnessHead(s, r as Record<string, unknown>, resolver) : null;
  await verifyWitnessHistoryChain(exec, resolver, s, head);
  return head;
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

/** (C5) In-tx primitive: advance the external witness from a SOURCE-SIGNED checkpoint receipt (never
 *  caller-supplied state). Verifies the source signature; enforces system_id + grant/seq monotonicity;
 *  a CONTINUITY proof at the last-witnessed height (receipt.priorSeq/priorHeadDigest must equal the
 *  witness's (maxSourceSeq, headDigest), catching a restore+fork that grew BEYOND that height); and
 *  the FULL witness chain (H4). Then guard-signed forward-CAS. Per-stream advisory-locked. The caller
 *  must already be in the control tx (the owned-tx `advanceSourceWitness` pins schema + attests). */
export async function advanceSourceWitnessInTx(exec: PgExecutor, resolver: SourceVerifyKeyResolver, guardKeyId: string, guardPrivateKey: KeyObject | string, receipt: SourceCheckpointReceipt): Promise<WitnessState> {
  if (!KEY_ID_RE.test(guardKeyId)) throw new ContractValidationError('invalid guard keyId');
  verifySourceCheckpointReceipt(resolver, receipt); // SOURCE-signed, not caller-supplied state
  const s = vId(receipt.streamId, STREAM_ID_RE, 'streamId');
  const sysId = receipt.sourceSystemId, gs = receipt.grantSeq, ss = receipt.sourceSeq, head = receipt.sourceHeadDigest;
  await exec.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [s]);
  await attestSourceWitness(exec); // (H3) the witness catalog must match its compiled pin before we mutate it
  const cur = await readSourceWitness(exec, resolver, s); // (H2/H4) chain-verified head (full contiguous signed chain)
  // idempotent re-advance (crash-resume): an identical high-water is a no-op, not a new witness seq.
  if (cur && cur.sourceSystemId === sysId && cur.maxGrantSeq === gs && cur.maxSourceSeq === ss && cur.headDigest === head) return cur;
  if (cur) {
    if (sysId !== cur.sourceSystemId) throw new SourceFenceQuarantineError(`source system_identifier changed (${sysId} != witnessed ${cur.sourceSystemId}) — restore/clone; quarantine`);
    if (gs < cur.maxGrantSeq) throw new SourceFenceQuarantineError(`grant_seq ${gs} < witnessed ${cur.maxGrantSeq} — restore/rollback; quarantine`);
    if (ss < cur.maxSourceSeq) throw new SourceFenceQuarantineError(`source seq ${ss} < witnessed ${cur.maxSourceSeq} — restore/rollback; quarantine`);
    // (C5) continuity at the witnessed height — catches a restore+fork that grew past it. The issuer
    // proves the FULL range (priorSeq, ss] from the signed ledger, so this pin closes the prefix.
    if (receipt.priorSeq !== cur.maxSourceSeq) throw new SourceFenceQuarantineError(`checkpoint priorSeq ${receipt.priorSeq} != witnessed height ${cur.maxSourceSeq} — quarantine`);
    if (receipt.priorHeadDigest !== cur.headDigest) throw new SourceFenceQuarantineError('checkpoint head at the witnessed height diverges from the witness — restore/FORK; quarantine');
  } else {
    // (H2/R4) the FIRST witness advance MUST anchor at genesis (priorSeq=0, genesis head) so the issuer's
    // proven range is (0, N] = the FULL 1..N prefix — a genesis stamp cannot skip 1..W-1.
    if (receipt.priorSeq !== 0) throw new SourceFenceQuarantineError(`first witness advance must anchor at genesis (priorSeq=0), got ${receipt.priorSeq} — quarantine`);
    if (receipt.priorHeadDigest !== GENESIS_HEAD_ZERO) throw new SourceFenceQuarantineError('first witness advance priorHeadDigest is not genesis — quarantine');
  }
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

// ── C2/H1: compiled full-catalog attestation + MANDATORY readiness capability ──

const SCHEMA_RE = /^[a-z_][a-z0-9_]{0,62}$/;

/** Pin the schema for THIS tx (pg_temp LAST so a temp table cannot shadow the authority tables;
 *  pg_catalog is implicitly first so system funcs/catalogs cannot be shadowed) + assert SERIALIZABLE. */
async function enterSourceTx(exec: PgExecutor, schema: string): Promise<void> {
  if (!SCHEMA_RE.test(schema)) throw new ContractValidationError(`invalid schema identifier: ${schema}`);
  const iso = String((await exec.query('SHOW transaction_isolation')).rows[0]?.transaction_isolation ?? '').toLowerCase();
  if (iso !== 'serializable') throw new ContractValidationError(`source fence attestation requires SERIALIZABLE; got '${iso}'`);
  await exec.query('SELECT pg_catalog.set_config($1, $2, true)', ['search_path', `${schema}, pg_temp`]);
  const cur = (await exec.query('SELECT pg_catalog.current_schema() AS s')).rows[0]?.s;
  if (cur !== schema) throw new ContractValidationError(`schema context mismatch: current_schema=${String(cur)} pinned=${schema}`);
}

/** Canonical full-catalog manifest of a source-fence table group (columns + constraints + indexes),
 *  pg_catalog-qualified. Attested against a COMPILED pinned digest — never trust-on-first-use. The
 *  lease group (on A) and the witness group (on control) are attested SEPARATELY: each attestation is
 *  co-located with the transactor that actually owns those tables in its own DB. */
async function sourceFenceManifest(exec: PgExecutor, tables: readonly string[], ver: string): Promise<string> {
  const t = tables as string[];
  // NB: do NOT rely on SQL `ORDER BY <text>` — the default collation differs across builds (glibc on
  // Debian vs musl on Alpine sort punctuation differently), so the same catalog would hash to different
  // digests. Fetch unordered and sort the emitted lines byte-canonically in application code instead.
  // (H3) attest the FULL catalog like the hardened control manifest: exact table presence (relkind /
  // persistence / RLS enable+force), columns, constraints, indexes, triggers (+enabled), and policies —
  // so an UNLOGGED flip, an added trigger, an RLS toggle, or a new policy cannot drift past the pin.
  const rel = (await exec.query(
    `SELECT rel.relname AS t, rel.relkind, rel.relpersistence, rel.relrowsecurity, rel.relforcerowsecurity
     FROM pg_catalog.pg_class rel JOIN pg_catalog.pg_namespace ns ON ns.oid = rel.relnamespace
     WHERE ns.nspname = pg_catalog.current_schema() AND rel.relname = ANY($1)`, [t])).rows;
  const cols = (await exec.query(
    `SELECT table_name, ordinal_position, column_name, data_type, is_nullable, COALESCE(column_default,'') AS d
     FROM information_schema.columns WHERE table_schema = pg_catalog.current_schema() AND table_name = ANY($1)`, [t])).rows;
  const cons = (await exec.query(
    `SELECT rel.relname AS t, c.contype, pg_catalog.pg_get_constraintdef(c.oid) AS def
     FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class rel ON rel.oid = c.conrelid
     JOIN pg_catalog.pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = pg_catalog.current_schema() AND rel.relname = ANY($1) AND c.contype IN ('p','c','u','f')`, [t])).rows;
  const idx = (await exec.query(
    `SELECT tablename AS t, indexname AS n, indexdef AS def FROM pg_catalog.pg_indexes
     WHERE schemaname = pg_catalog.current_schema() AND tablename = ANY($1)`, [t])).rows;
  const trg = (await exec.query(
    `SELECT rel.relname AS t, tg.tgname AS n, pg_catalog.pg_get_triggerdef(tg.oid) AS def, tg.tgenabled
     FROM pg_catalog.pg_trigger tg JOIN pg_catalog.pg_class rel ON rel.oid = tg.tgrelid
     JOIN pg_catalog.pg_namespace ns ON ns.oid = rel.relnamespace
     WHERE ns.nspname = pg_catalog.current_schema() AND rel.relname = ANY($1) AND NOT tg.tgisinternal`, [t])).rows;
  const pol = (await exec.query(
    `SELECT tablename AS t, policyname AS n, permissive, roles::text AS roles, cmd, COALESCE(qual,'') AS qual, COALESCE(with_check,'') AS wc
     FROM pg_catalog.pg_policies WHERE schemaname = pg_catalog.current_schema() AND tablename = ANY($1)`, [t])).rows;
  // exact table-presence assertion: the manifest carries the SORTED set of tables actually present, so
  // a missing OR extra governed table changes the digest (and a fully-absent table set fails closed).
  const present = rel.map((r) => String(r.t)).sort();
  const lines = [
    `PRESENT|${present.join(',')}|n=${present.length}`,
    ...rel.map((r) => `R|${r.t}|${r.relkind}|${r.relpersistence}|${r.relrowsecurity}|${r.relforcerowsecurity}`),
    ...cols.map((r) => `C|${r.table_name}|${r.ordinal_position}|${r.column_name}|${r.data_type}|${r.is_nullable}|${r.d}`),
    ...cons.map((r) => `K|${r.t}|${r.contype}|${r.def}`),
    ...idx.map((r) => `I|${r.t}|${r.n}|${r.def}`),
    ...trg.map((r) => `T|${r.t}|${r.n}|${r.tgenabled}|${r.def}`),
    ...pol.map((r) => `P|${r.t}|${r.n}|${r.permissive}|${r.roles}|${r.cmd}|${r.qual}|${r.wc}`),
  ];
  lines.sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))); // collation-independent
  return [ver, ...lines].join('\n');
}

/** COMPILED expected catalog digests (pinned in source; computed on PG16). Re-pin only via an offline
 *  code-reviewed step; there is deliberately NO runtime override (R5-H1). The lease digest gates the
 *  outbox (on A); the witness digest gates witness advances (on control). */
export const SOURCE_LEASE_MANIFEST_DIGEST = '548ad3d75a8d9dc612afe2f6e3734d5660fb79ce768a011d5a2de3cfca4c04f3';
export const SOURCE_WITNESS_MANIFEST_DIGEST = 'ec71067986cb82d06fc8fa3e4e9f934b4a961b0759a92199789de33c19ce0a82';

async function attestSourceLease(exec: PgExecutor): Promise<void> {
  const digest = sha256hex(Buffer.from(await sourceFenceManifest(exec, TSK_SOURCE_LEASE_TABLES, 'Vsource_lease/1'), 'utf8'));
  if (digest !== SOURCE_LEASE_MANIFEST_DIGEST) throw new ContractValidationError(`source lease attestation failed: live catalog digest ${digest} != pinned ${SOURCE_LEASE_MANIFEST_DIGEST}`);
}
/** Attest the witness table group on the control transactor before mutating/reading it (H1). */
export async function attestSourceWitness(exec: PgExecutor): Promise<void> {
  const digest = sha256hex(Buffer.from(await sourceFenceManifest(exec, TSK_SOURCE_WITNESS_TABLES, 'Vsource_witness/1'), 'utf8'));
  if (digest !== SOURCE_WITNESS_MANIFEST_DIGEST) throw new ContractValidationError(`source witness attestation failed: live catalog digest ${digest} != pinned ${SOURCE_WITNESS_MANIFEST_DIGEST}`);
}

const READY_BRAND: unique symbol = Symbol('tsk_source_fence_ready');
export interface SourceFenceReadyToken { readonly [READY_BRAND]: true }
interface FenceBinding { db: PgTransactor; schema: string; streamId: string; holderNodeId: string; leaseId: string; grantDigest: string; }
const READY_STATE = new WeakMap<object, FenceBinding>();
function mintReady(b: FenceBinding): SourceFenceReadyToken {
  const token = Object.freeze({ [READY_BRAND]: true as const });
  READY_STATE.set(token, b);
  return token as SourceFenceReadyToken;
}
// NO test-only / unsafe mint export: a token is obtainable ONLY via assertSourceFenceReady (real attest).

/** Validate an unforgeable source-fence capability + that it is bound to this db/schema/stream. */
export function requireSourceFenceReady(token: SourceFenceReadyToken, ctx: { db: PgTransactor; schema: string; streamId: string }): FenceBinding {
  const st = READY_STATE.get(token as unknown as object);
  if (!st) throw new ContractValidationError('invalid source-fence capability (forged or foreign token)');
  if (st.db !== ctx.db) throw new ContractValidationError('source-fence capability bound to a different transactor');
  if (st.schema !== ctx.schema || st.streamId !== ctx.streamId) throw new ContractValidationError('source-fence capability bound to a different schema/stream');
  return st;
}

/** Attest the compiled source-fence catalog in the pinned schema (via the source transactor), FULL-
 *  CHAIN-VERIFY the live lease, assert its verified head EXACTLY equals the authorized identity, then
 *  mint an unforgeable capability bound to db+schema+stream+holder+leaseId+grantDigest. Because the
 *  full contiguous signed chain is verified HERE and the token pins the exact grantDigest, the token is
 *  a VERIFIED-CHAIN HIGH-WATER: the per-append gate then does only a bounded O(1) head/token match (M1).
 *  A lease renewal changes the head grantDigest, so a fresh token must be minted (re-verifying the chain). */
export async function assertSourceFenceReady(db: PgTransactor, schema: string, resolver: SourceVerifyKeyResolver, binding: { streamId: string; holderNodeId: string; leaseId: string; grantDigest: string }): Promise<SourceFenceReadyToken> {
  const streamId = vId(binding.streamId, STREAM_ID_RE, 'streamId');
  const holderNodeId = vId(binding.holderNodeId, ID_RE, 'holderNodeId');
  const leaseId = vId(binding.leaseId, ID_RE, 'leaseId');
  if (!DIGEST_RE.test(binding.grantDigest)) throw new ContractValidationError('invalid grantDigest');
  await db.transaction(async (exec) => {
    await enterSourceTx(exec, schema);
    await attestSourceLease(exec);
    const head = await readSourceLease(exec, resolver, streamId); // (M1) full contiguous signed chain from genesis
    if (!head) throw new SourceFenceQuarantineError('cannot mint readiness: no source lease for the stream');
    if (head.holderNodeId !== holderNodeId || head.leaseId !== leaseId || head.grantDigest !== binding.grantDigest) {
      throw new SourceFenceQuarantineError('cannot mint readiness: the verified lease head is not the authorized holder/leaseId/grant');
    }
  });
  return mintReady({ db, schema, streamId, holderNodeId, leaseId, grantDigest: binding.grantDigest });
}

// ── (H3) control-side witness readiness + owned serializable advance; (H5) atomic checkpoint issuer ──

const WITNESS_READY_BRAND: unique symbol = Symbol('tsk_source_witness_ready');
export interface SourceWitnessReadyToken { readonly [WITNESS_READY_BRAND]: true }
interface WitnessBinding { db: PgTransactor; schema: string; }
const WITNESS_READY_STATE = new WeakMap<object, WitnessBinding>();
function mintWitnessReady(b: WitnessBinding): SourceWitnessReadyToken {
  const token = Object.freeze({ [WITNESS_READY_BRAND]: true as const });
  WITNESS_READY_STATE.set(token, b);
  return token as SourceWitnessReadyToken;
}
/** Validate an unforgeable witness capability + that it is bound to this control transactor. */
export function requireSourceWitnessReady(token: SourceWitnessReadyToken, ctx: { db: PgTransactor }): WitnessBinding {
  const st = WITNESS_READY_STATE.get(token as unknown as object);
  if (!st) throw new ContractValidationError('invalid source-witness capability (forged or foreign token)');
  if (st.db !== ctx.db) throw new ContractValidationError('source-witness capability bound to a different transactor');
  return st;
}
/** Attest the compiled witness catalog in the pinned schema (control transactor) + mint a db/schema-
 *  bound witness capability. The owned-tx `advanceSourceWitness` REQUIRES this token. */
export async function assertSourceWitnessReady(db: PgTransactor, schema: string): Promise<SourceWitnessReadyToken> {
  await db.transaction(async (exec) => { await enterSourceTx(exec, schema); await attestSourceWitness(exec); });
  return mintWitnessReady({ db, schema });
}
/** (H3) Owned, SERIALIZABLE, schema-pinned witness advance (production path): validate the db/schema-
 *  bound capability, open the control tx, pin the schema, then run the in-tx primitive (attest + full
 *  chain + continuity + guard-signed CAS). Never takes a raw caller exec/current_schema. */
export async function advanceSourceWitness(db: PgTransactor, ready: SourceWitnessReadyToken, resolver: SourceVerifyKeyResolver, guardKeyId: string, guardPrivateKey: KeyObject | string, receipt: SourceCheckpointReceipt): Promise<WitnessState> {
  const { schema } = requireSourceWitnessReady(ready, { db });
  return db.transaction(async (exec) => {
    await enterSourceTx(exec, schema);
    return advanceSourceWitnessInTx(exec, resolver, guardKeyId, guardPrivateKey, receipt);
  });
}

/** (H5) The ONLY runtime path that produces a checkpoint receipt: a source-transactor-owned,
 *  SERIALIZABLE, schema-pinned derivation. Attests the lease catalog, LOCKS the source lease +
 *  checkpoint FOR SHARE, DERIVES the committed (system_identifier, grantSeq, head@N, head@N-1)
 *  straight from the ledger, then source-signs. The low-level `signSourceCheckpointReceipt` accepts
 *  arbitrary caller state and MUST NOT attest live source state on the runtime path — use this. */
const OUTBOX_ROW_COLS = 'sequence, source_epoch, fence_token, op_digest, head_prev, head_digest, head_key_id, head_alg, head_sig';

/** (H2) Verify ONE signed committed outbox row: reconstruct the header + SignedStreamHead from the
 *  stored fields, RECOMPUTE the canonical head-digest binding via the contract's `assertStreamHeadBinds`
 *  (pins streamId + sequence + opDigest + prev + keyId + alg — so a signed head/digest cannot be
 *  replayed from another row or stream), then verify the ed25519 signature. Returns {headDigest, headPrev}. */
function verifyOneOutboxRow(headResolver: SourceVerifyKeyResolver, streamId: string, epoch: string, expectSeq: number, row: Record<string, unknown>): { headDigest: string; headPrev: string } {
  const seq = vInt(row.sequence, 'outbox row sequence', 1, MAX_SEQ);
  if (seq !== expectSeq) throw new SourceFenceQuarantineError(`outbox row seq ${seq} != expected ${expectSeq} — ledger gap/fork; quarantine`);
  if (String(row.source_epoch) !== epoch) throw new SourceFenceQuarantineError(`outbox row @${seq} source_epoch ${String(row.source_epoch)} != ${epoch} — cross-epoch; quarantine`);
  const headDigest = vHeadDigest(row.head_digest, `outbox head@${seq}`);
  const headPrev = vHeadDigest(row.head_prev, `outbox head_prev@${seq}`);
  const opDigest = vHeadDigest(row.op_digest, `outbox op_digest@${seq}`);
  const keyId = String(row.head_key_id), alg = String(row.head_alg) as StreamHeadAlg, sig = String(row.head_sig);
  const header: OutboxRecordHeader = { contractVersion: '1', streamId, sourceEpoch: epoch, sequence: seq, fenceToken: String(row.fence_token), opDigest };
  const head: SignedStreamHead = { streamId, sequence: seq, prevHeadDigest: headPrev, opDigest, keyId, alg, headDigest, signature: sig };
  assertStreamHeadBinds(header, head); // (H2) recompute canonical digest + binding — no replay from another row/stream
  if (alg !== 'ed25519') throw new ContractValidationError(`unsupported outbox head alg '${alg}' for checkpoint/freeze`);
  if (!B64U_CANON.test(sig)) throw new ContractValidationError('invalid outbox head signature encoding');
  const pub = headResolver.resolve(keyId);
  if (pub === null) throw new ContractValidationError('unknown or revoked outbox head keyId');
  if (!edVerify(null, Buffer.from(headDigest, 'utf8'), toPublicKey(pub), Buffer.from(sig, 'base64url'))) {
    throw new SourceFenceQuarantineError(`outbox head signature invalid at seq ${seq} — ledger tamper; quarantine`);
  }
  return { headDigest, headPrev };
}

/** (H1) Verify the ENTIRE signed outbox ledger range (fromSeq, toSeq] for the EXACT source epoch:
 *  every row present + contiguous, canonical-binding + signature verified, and the prev-digest chain
 *  linked from `fromHeadDigest` (head@fromSeq, or genesis when fromSeq===0). A missing/broken/copied
 *  middle row → quarantine. Returns head@toSeq. */
async function verifyOutboxLedgerRange(exec: PgExecutor, headResolver: SourceVerifyKeyResolver, streamId: string, epoch: string, fromSeq: number, fromHeadDigest: string, toSeq: number): Promise<string> {
  if (toSeq < fromSeq) throw new SourceFenceQuarantineError(`ledger range toSeq ${toSeq} < fromSeq ${fromSeq} — quarantine`);
  if (toSeq === fromSeq) return fromHeadDigest;
  const rows = (await exec.query(`SELECT ${OUTBOX_ROW_COLS} FROM tsk_outbox_rows WHERE stream_id=$1 AND source_epoch=$2 AND sequence > $3 AND sequence <= $4 ORDER BY sequence ASC`, [streamId, epoch, fromSeq, toSeq])).rows;
  if (rows.length !== toSeq - fromSeq) throw new SourceFenceQuarantineError(`ledger range (${fromSeq},${toSeq}] expected ${toSeq - fromSeq} rows, got ${rows.length} — gap; quarantine`);
  let prev = fromHeadDigest;
  for (let i = 0; i < rows.length; i++) {
    const { headDigest, headPrev } = verifyOneOutboxRow(headResolver, streamId, epoch, fromSeq + 1 + i, rows[i] as Record<string, unknown>);
    if (headPrev !== prev) throw new SourceFenceQuarantineError(`row ${fromSeq + 1 + i} head_prev does not chain — ledger fork; quarantine`);
    prev = headDigest;
  }
  return prev;
}

/** Read the committed source checkpoint (mutable pointer) + verify it agrees with the SIGNED ledger:
 *  full-verify the range (0, N] and assert the checkpoint's (sequence, head) equal N + head@N. Returns
 *  { epoch, n, headN }. Never trusts the mutable checkpoint row alone. */
async function deriveSignedLedgerHead(exec: PgExecutor, headResolver: SourceVerifyKeyResolver, streamId: string): Promise<{ epoch: string; n: number; headN: string }> {
  const cp = (await exec.query('SELECT source_epoch, sequence, head_digest FROM tsk_outbox_source_checkpoint WHERE stream_id=$1 FOR SHARE', [streamId])).rows[0];
  if (!cp) throw new SourceFenceQuarantineError('no source checkpoint — stream not provisioned');
  const epoch = String(cp.source_epoch);
  const n = vInt(cp.sequence, 'cp sequence', 0, MAX_SEQ);
  if (n < 1) throw new SourceFenceQuarantineError('source checkpoint at genesis (N=0) — nothing to derive');
  const headN = await verifyOutboxLedgerRange(exec, headResolver, streamId, epoch, 0, GENESIS_HEAD_ZERO, n);
  if (vHeadDigest(cp.head_digest, 'cp head') !== headN) throw new SourceFenceQuarantineError('checkpoint pointer diverges from the signed ledger head at N — quarantine');
  return { epoch, n, headN };
}

/** Options for the atomic checkpoint issuer. `leaseResolver` holds the guard PUBLIC key (verify the
 *  lease chain); `headResolver` holds the outbox head-signer PUBLIC key (verify the signed ledger
 *  heads); `priorWitnessSeq` is the CURRENT witnessed height W (0 = genesis) — the issuer anchors the
 *  receipt's continuity proof at W, derives head@W, and verifies the FULL range (W, N] from the signed
 *  ledger, so a witness that lags the source by more than 1 (W=3, N=10) advances in one proven step. */
export interface CheckpointIssueOptions {
  sourceKeyId: string; sourcePrivateKey: KeyObject | string;
  leaseResolver: SourceVerifyKeyResolver; headResolver: SourceVerifyKeyResolver; priorWitnessSeq: number;
}
export async function issueSourceCheckpointReceipt(db: PgTransactor, schema: string, streamId: string, opts: CheckpointIssueOptions): Promise<SourceCheckpointReceipt> {
  const s = vId(streamId, STREAM_ID_RE, 'streamId');
  const priorW = vInt(opts.priorWitnessSeq, 'priorWitnessSeq', 0, MAX_SEQ);
  return db.transaction(async (exec) => {
    await enterSourceTx(exec, schema);
    await attestSourceLease(exec);
    const sysId = String((await exec.query('SELECT system_identifier::text AS s FROM pg_catalog.pg_control_system()')).rows[0]?.s);
    // (H4) full-chain verify the EXACT live lease under FOR SHARE (never trust the mutable head row alone)
    await exec.query('SELECT 1 FROM tsk_source_lease WHERE stream_id=$1 FOR SHARE', [s]);
    const lease = await readSourceLease(exec, opts.leaseResolver, s); // chain-verified head
    if (!lease) throw new SourceFenceQuarantineError('no source lease — cannot issue for an unleased stream');
    // (H4) derive N + head@N from the SIGNED append-only ledger (checkpoint pointer must agree)
    const { epoch, n, headN } = await deriveSignedLedgerHead(exec, opts.headResolver, s);
    if (priorW > n) throw new SourceFenceQuarantineError(`witnessed height ${priorW} exceeds source N ${n} — restore/rollback; quarantine`);
    // (H1/H5) anchor at the witnessed height W (head@W derived from the signed ledger) and verify the FULL range (W, N]
    let priorHeadDigest = GENESIS_HEAD_ZERO;
    if (priorW >= 1) {
      const wRow = (await exec.query(`SELECT ${OUTBOX_ROW_COLS} FROM tsk_outbox_rows WHERE stream_id=$1 AND source_epoch=$2 AND sequence=$3`, [s, epoch, priorW])).rows[0];
      if (!wRow) throw new SourceFenceQuarantineError(`missing committed row at witnessed height ${priorW} — quarantine`);
      priorHeadDigest = verifyOneOutboxRow(opts.headResolver, s, epoch, priorW, wRow as Record<string, unknown>).headDigest;
    }
    const headAtN = await verifyOutboxLedgerRange(exec, opts.headResolver, s, epoch, priorW, priorHeadDigest, n);
    if (headAtN !== headN) throw new SourceFenceQuarantineError('range head@N != checkpoint head@N — quarantine');
    return signSourceCheckpointReceipt(opts.sourceKeyId, opts.sourcePrivateKey, { streamId: s, sourceSystemId: sysId, sourceSeq: n, sourceHeadDigest: headN, grantSeq: lease.leaseGrantSeq, priorSeq: priorW, priorHeadDigest });
  });
}
