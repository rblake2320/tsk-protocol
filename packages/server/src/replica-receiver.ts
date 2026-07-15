/** Authenticated, ordered receiver for a TSK replication stream. */
import { timingSafeEqual } from 'node:crypto';
import { TSK_MAX_HOTP_COUNTER, type TumblerMap } from '@tsk/core';
import type { TumblerMapStore } from './store.js';
import {
  MIN_REPLICATION_TOKEN_BYTES,
  REPLICATION_GENESIS_HASH,
  computeReplicationHash,
  verifyReplicaEnvelopeSignature,
  type ReplicationCheckpoint,
  type TumblerReplicaMutation,
  type TumblerReplicaOp,
} from './replicating-tumbler-store.js';

const MAX_CLIENT_ID_LEN = 128;
const MAX_SEGMENT_ID_LEN = 128;
const MAX_SEGMENTS = 32;
const MAX_SEALED_SECRET_CHARS = 8192;
const MAX_ENVELOPE_BYTES = 256 * 1024;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface TumblerApplyResult {
  ok: boolean;
  error?: string;
}

export interface ReplicaReceiverOptions {
  streamId: string;
  epoch: number;
  initialCheckpoint?: ReplicationCheckpoint;
  maxClockSkewMs?: number;
  now?: () => number;
  /** Required for a replica that may be promoted to validate TSK credentials. */
  secretUnsealer?: (clientId: string, sealedSecret: string) => Promise<string> | string;
  /**
   * Confirms the applied mutation and receiver checkpoint are durably and
   * atomically recoverable. Omit to make promotion fail closed.
   */
  promotionDurability?: (checkpoint: ReplicationCheckpoint) => boolean;
}

/** Retained for callers that separately authenticate legacy control endpoints. */
export function authorizeReplica(
  headers: Record<string, string | string[] | undefined>,
  expectedToken: string,
): boolean {
  const raw = headers['x-replica-token'];
  const presented = Array.isArray(raw) ? raw[0] : raw;
  if (!presented || Buffer.byteLength(expectedToken, 'utf8') < MIN_REPLICATION_TOKEN_BYTES) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(expectedToken);
  return a.length === b.length && timingSafeEqual(a, b);
}

function isValidId(value: unknown, max = MAX_CLIENT_ID_LEN): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isValidHOTPStoredCounter(value: unknown): value is number {
  return isSafeNonNegativeInteger(value) && value <= TSK_MAX_HOTP_COUNTER;
}

function validateMap(map: unknown, clientId: string, secretSealed: boolean): map is TumblerMap {
  if (!map || typeof map !== 'object') return false;
  const candidate = map as TumblerMap;
  if (candidate.clientId !== clientId || candidate.version !== '1') return false;
  if (!Number.isSafeInteger(candidate.keyLength) || candidate.keyLength < 20 || candidate.keyLength > 512) return false;
  if (!Number.isSafeInteger(candidate.createdAt) || candidate.createdAt < 0) return false;
  if (!Array.isArray(candidate.segments) || candidate.segments.length < 2 || candidate.segments.length > MAX_SEGMENTS) return false;
  if (!candidate.checksum || !Array.isArray(candidate.checksum.position) || candidate.checksum.position.length !== 2) return false;
  if (secretSealed) {
    if (typeof candidate.sharedSecret !== 'string' || candidate.sharedSecret.length < 1 || candidate.sharedSecret.length > MAX_SEALED_SECRET_CHARS) return false;
  } else if (candidate.sharedSecret !== '') {
    // The default replication profile is metadata-only. Raw signing material is
    // never accepted under a false `secretSealed` marker.
    return false;
  }

  const ids = new Set<string>();
  let cursor = 0;
  let hasHotp = false;
  let hasExhaustedHotp = false;
  for (const segment of candidate.segments) {
    if (!segment || !isValidId(segment.segmentId, MAX_SEGMENT_ID_LEN) || ids.has(segment.segmentId)) return false;
    ids.add(segment.segmentId);
    if (!Array.isArray(segment.position) || segment.position.length !== 2) return false;
    const [start, end] = segment.position;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start !== cursor || end <= start || end > candidate.keyLength) return false;
    if (segment.type !== 'static' && segment.type !== 'totp' && segment.type !== 'hotp') return false;
    if (segment.type === 'hotp') {
      if (!isValidHOTPStoredCounter(segment.counter ?? 0)) return false;
      if ((segment.counter ?? 0) === TSK_MAX_HOTP_COUNTER) hasExhaustedHotp = true;
      hasHotp = true;
    }
    if (segment.type === 'totp' && (!Number.isSafeInteger(segment.windowSec) || (segment.windowSec ?? 0) < 1)) return false;
    cursor = end;
  }
  const [checksumStart, checksumEnd] = candidate.checksum.position;
  if (!Number.isSafeInteger(checksumStart) || !Number.isSafeInteger(checksumEnd) || checksumStart !== cursor || checksumEnd !== candidate.keyLength) return false;
  if (!hasHotp) return false;
  if (candidate.requestCount !== undefined && !isSafeNonNegativeInteger(candidate.requestCount)) return false;
  if (candidate.maxRequests !== undefined && (!Number.isSafeInteger(candidate.maxRequests) || candidate.maxRequests < 1)) return false;
  if (candidate.hotpRotationWarningCounters !== undefined &&
      (!Number.isSafeInteger(candidate.hotpRotationWarningCounters) ||
       candidate.hotpRotationWarningCounters < 1 ||
       candidate.hotpRotationWarningCounters > TSK_MAX_HOTP_COUNTER)) return false;
  if (candidate.expiresAt !== undefined && (!Number.isSafeInteger(candidate.expiresAt) || candidate.expiresAt < 0)) return false;
  if (candidate.status !== undefined && !['active', 'expiring', 'revoked', 'expired'].includes(candidate.status)) return false;
  if (hasExhaustedHotp && candidate.status !== 'expired' && candidate.status !== 'revoked') return false;
  return true;
}

function validateMutation(value: unknown): { ok: true; mutation: TumblerReplicaMutation } | { ok: false; error: string } {
  if (!value || typeof value !== 'object') return { ok: false, error: 'invalid_mutation' };
  const op = (value as { op?: unknown }).op;
  switch (op) {
    case 'set': {
      const { clientId, map, secretSealed } = value as { clientId?: unknown; map?: unknown; secretSealed?: unknown };
      if (!isValidId(clientId)) return { ok: false, error: 'invalid_set_clientId' };
      if (typeof secretSealed !== 'boolean' || !validateMap(map, clientId, secretSealed)) {
        return { ok: false, error: 'invalid_set_map' };
      }
      return { ok: true, mutation: { op: 'set', clientId, map, secretSealed } };
    }
    case 'delete': {
      const clientId = (value as { clientId?: unknown }).clientId;
      if (!isValidId(clientId)) return { ok: false, error: 'invalid_delete' };
      return { ok: true, mutation: { op: 'delete', clientId } };
    }
    case 'updateCounters': {
      const { clientId, updates } = value as { clientId?: unknown; updates?: unknown };
      if (!isValidId(clientId)) return { ok: false, error: 'invalid_update_clientId' };
      if (!Array.isArray(updates) || updates.length > MAX_SEGMENTS || !updates.every(entry =>
        Array.isArray(entry) && entry.length === 2 && isValidId(entry[0], MAX_SEGMENT_ID_LEN) && isValidHOTPStoredCounter(entry[1]))) {
        return { ok: false, error: 'invalid_update_entries' };
      }
      return { ok: true, mutation: { op: 'updateCounters', clientId, updates: updates as Array<[string, number]> } };
    }
    case 'consumeCounter': {
      const { clientId, segmentId, matchedCounter } = value as Record<string, unknown>;
      if (!isValidId(clientId) || !isValidId(segmentId, MAX_SEGMENT_ID_LEN) ||
          !isValidHOTPStoredCounter(matchedCounter) || matchedCounter >= TSK_MAX_HOTP_COUNTER) {
        return { ok: false, error: 'invalid_consume' };
      }
      return { ok: true, mutation: { op: 'consumeCounter', clientId, segmentId, matchedCounter } };
    }
    default:
      return { ok: false, error: 'unknown_op' };
  }
}

/** Validate the complete authenticated envelope before touching the store. */
export function validateTumblerOp(
  body: unknown,
): { ok: true; op: TumblerReplicaOp } | { ok: false; error: string } {
  let encoded: string;
  try { encoded = JSON.stringify(body); } catch { return { ok: false, error: 'invalid_body' }; }
  if (Buffer.byteLength(encoded, 'utf8') > MAX_ENVELOPE_BYTES) return { ok: false, error: 'envelope_too_large' };
  if (!body || typeof body !== 'object') return { ok: false, error: 'invalid_body' };
  const candidate = body as Partial<TumblerReplicaOp>;
  if (!isValidId(candidate.streamId, 128)) return { ok: false, error: 'invalid_stream' };
  if (!Number.isSafeInteger(candidate.epoch) || (candidate.epoch ?? 0) < 1) return { ok: false, error: 'invalid_epoch' };
  if (!Number.isSafeInteger(candidate.sequence) || (candidate.sequence ?? 0) < 1) return { ok: false, error: 'invalid_sequence' };
  if (!Number.isSafeInteger(candidate.sentAt) || (candidate.sentAt ?? -1) < 0) return { ok: false, error: 'invalid_sentAt' };
  if (typeof candidate.previousHash !== 'string' || !HASH_PATTERN.test(candidate.previousHash)) return { ok: false, error: 'invalid_previous_hash' };
  if (typeof candidate.headHash !== 'string' || !HASH_PATTERN.test(candidate.headHash)) return { ok: false, error: 'invalid_head_hash' };
  if (typeof candidate.signature !== 'string' || !SIGNATURE_PATTERN.test(candidate.signature)) return { ok: false, error: 'invalid_signature' };
  const mutation = validateMutation(candidate.mutation);
  if (!mutation.ok) return mutation;
  return { ok: true, op: { ...candidate, mutation: mutation.mutation } as TumblerReplicaOp };
}

function isTerminal(status: TumblerMap['status']): boolean {
  return status === 'revoked' || status === 'expired';
}

/** Apply a validated mutation while rejecting lifecycle/counter rollback. */
export async function applyTumblerOp(store: TumblerMapStore, mutation: TumblerReplicaMutation): Promise<TumblerApplyResult> {
  try {
    switch (mutation.op) {
      case 'set': {
        const current = await store.get(mutation.clientId);
        if (current) {
          if (isTerminal(current.status) && !isTerminal(mutation.map.status)) return { ok: false, error: 'lifecycle_rollback' };
          if ((mutation.map.requestCount ?? 0) < (current.requestCount ?? 0)) return { ok: false, error: 'usage_rollback' };
          const nextSegments = new Map(mutation.map.segments.map(segment => [segment.segmentId, segment]));
          for (const segment of current.segments) {
            if (segment.type !== 'hotp') continue;
            const next = nextSegments.get(segment.segmentId);
            if (!next || next.type !== 'hotp' || (next.counter ?? 0) < (segment.counter ?? 0)) {
              return { ok: false, error: 'counter_rollback' };
            }
          }
        }
        await store.set(mutation.clientId, mutation.map);
        return { ok: true };
      }
      case 'delete':
        await store.delete(mutation.clientId);
        return { ok: true };
      case 'updateCounters': {
        const current = await store.get(mutation.clientId);
        if (!current) return { ok: false, error: 'client_not_found' };
        const segments = new Map(current.segments.map(segment => [segment.segmentId, segment]));
        for (const [segmentId, nextCounter] of mutation.updates) {
          const segment = segments.get(segmentId);
          if (!segment || segment.type !== 'hotp' || nextCounter < (segment.counter ?? 0)) {
            return { ok: false, error: 'counter_rollback' };
          }
        }
        await store.updateCounters(mutation.clientId, new Map(mutation.updates));
        return { ok: true };
      }
      case 'consumeCounter': {
        if (!store.consumeCounter) return { ok: false, error: 'consume_unsupported' };
        const consumed = await store.consumeCounter(mutation.clientId, mutation.segmentId, mutation.matchedCounter);
        return consumed ? { ok: true } : { ok: false, error: 'counter_replay_or_gap' };
      }
    }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'apply_failed' };
  }
}

export class TumblerReplicaReceiver {
  private readonly now: () => number;
  private readonly maxClockSkewMs: number;
  private checkpoint: ReplicationCheckpoint;
  private integrityLost = false;
  private validationReady = true;

  constructor(
    private readonly store: TumblerMapStore,
    private readonly expectedToken: string,
    private readonly options: ReplicaReceiverOptions,
  ) {
    if (Buffer.byteLength(expectedToken, 'utf8') < MIN_REPLICATION_TOKEN_BYTES) throw new Error('replica token is too short');
    if (!isValidId(options.streamId, 128)) throw new Error('invalid receiver streamId');
    if (!Number.isSafeInteger(options.epoch) || options.epoch < 1) throw new Error('invalid receiver epoch');
    this.now = options.now ?? Date.now;
    this.maxClockSkewMs = options.maxClockSkewMs ?? 60_000;
    this.checkpoint = options.initialCheckpoint
      ? { ...options.initialCheckpoint }
      : { streamId: options.streamId, epoch: options.epoch, sequence: 0, headHash: REPLICATION_GENESIS_HASH };
    if (this.checkpoint.streamId !== options.streamId || this.checkpoint.epoch !== options.epoch) {
      throw new Error('initial checkpoint does not match configured stream');
    }
  }

  getCheckpoint(): ReplicationCheckpoint {
    return { ...this.checkpoint };
  }

  /** Null means promotion must fail closed. */
  promotionCheckpoint(): ReplicationCheckpoint | null {
    if (this.integrityLost || !this.validationReady || this.checkpoint.sequence < 1) return null;
    const checkpoint = this.getCheckpoint();
    try {
      if (!this.options.promotionDurability?.(checkpoint)) return null;
    } catch {
      return null;
    }
    return checkpoint;
  }

  async ingest(body: unknown): Promise<{ status: number; result: TumblerApplyResult }> {
    const validated = validateTumblerOp(body);
    if (!validated.ok) return { status: 400, result: { ok: false, error: validated.error } };
    const op = validated.op;
    if (!verifyReplicaEnvelopeSignature(op, this.expectedToken)) {
      return { status: 401, result: { ok: false, error: 'signature_invalid' } };
    }
    if (Math.abs(this.now() - op.sentAt) > this.maxClockSkewMs) {
      return { status: 401, result: { ok: false, error: 'envelope_stale' } };
    }
    if (op.streamId !== this.options.streamId || op.epoch !== this.options.epoch) {
      return { status: 409, result: { ok: false, error: 'stream_or_epoch_mismatch' } };
    }
    const expectedSequence = this.checkpoint.sequence + 1;
    if (op.sequence !== expectedSequence) {
      if (op.sequence > expectedSequence) this.integrityLost = true;
      return { status: 409, result: { ok: false, error: op.sequence < expectedSequence ? 'envelope_replay' : 'sequence_gap' } };
    }
    if (op.previousHash !== this.checkpoint.headHash) {
      this.integrityLost = true;
      return { status: 409, result: { ok: false, error: 'hash_chain_mismatch' } };
    }
    const expectedHash = computeReplicationHash({
      streamId: op.streamId,
      epoch: op.epoch,
      sequence: op.sequence,
      previousHash: op.previousHash,
      mutation: op.mutation,
    });
    if (op.headHash !== expectedHash) {
      this.integrityLost = true;
      return { status: 409, result: { ok: false, error: 'operation_hash_mismatch' } };
    }
    let mutation = op.mutation;
    if (mutation.op === 'set') {
      if (!mutation.secretSealed) {
        // Metadata-only state can support observation/recovery workflows but
        // cannot authenticate clients after promotion.
        this.validationReady = false;
      } else {
        if (!this.options.secretUnsealer) {
          this.validationReady = false;
        } else {
          try {
            const rawSecret = await this.options.secretUnsealer(mutation.clientId, mutation.map.sharedSecret);
            if (!/^[a-f0-9]{64}$/.test(rawSecret)) {
              this.integrityLost = true;
              return { status: 409, result: { ok: false, error: 'unsealed_secret_invalid' } };
            }
            mutation = { ...mutation, map: { ...mutation.map, sharedSecret: rawSecret }, secretSealed: false };
          } catch {
            this.integrityLost = true;
            return { status: 409, result: { ok: false, error: 'secret_unseal_failed' } };
          }
        }
      }
    }
    const result = await applyTumblerOp(this.store, mutation);
    if (!result.ok) {
      this.integrityLost = true;
      return { status: 409, result };
    }
    this.checkpoint = { streamId: op.streamId, epoch: op.epoch, sequence: op.sequence, headHash: op.headHash };
    return { status: 200, result };
  }
}

/** Framework adapter: all authorization and ordering live in the receiver. */
export function handleTumblerIngest(
  receiver: TumblerReplicaReceiver,
  body: unknown,
): Promise<{ status: number; result: TumblerApplyResult }> {
  return receiver.ingest(body);
}
