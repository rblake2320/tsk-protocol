/**
 * Ordered, authenticated write mirroring for a TSK primary.
 *
 * The replication stream is hash-linked and monotonically sequenced. Queue loss
 * permanently disqualifies the stream from promotion until an operator performs
 * an explicit full resynchronization with a new stream/epoch.
 */
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type { TumblerMap } from '@tsk/core';
import type {
  TumblerMapStore,
  ValidationCommitInput,
  ValidationCommitResult,
} from './store.js';

export const REPLICATION_GENESIS_HASH = '0'.repeat(64);
export const MIN_REPLICATION_TOKEN_BYTES = 32;

export interface ReplicationCheckpoint {
  streamId: string;
  epoch: number;
  sequence: number;
  headHash: string;
}

export type TumblerReplicaMutation =
  | { op: 'set'; clientId: string; map: TumblerMap; secretSealed: boolean }
  | { op: 'delete'; clientId: string }
  | { op: 'updateCounters'; clientId: string; updates: Array<[string, number]> }
  | { op: 'consumeCounter'; clientId: string; segmentId: string; matchedCounter: number };

/** Wire envelope. `signature` authenticates every field except itself. */
export interface TumblerReplicaOp extends ReplicationCheckpoint {
  previousHash: string;
  sentAt: number;
  mutation: TumblerReplicaMutation;
  signature: string;
}

interface PendingReplicaOp {
  checkpoint: ReplicationCheckpoint;
  previousHash: string;
  mutation: TumblerReplicaMutation;
}

/** Seal a shared secret before it leaves the primary. */
export type SecretSealer = (clientId: string, sharedSecretHex: string) => Promise<string> | string;

export interface ReplicaTarget {
  url: string;
  /** At least 32 bytes; used for request authentication and envelope signing. */
  token: string;
  timeoutMs?: number;
}

export interface ReplicatingTumblerOptions {
  secretPolicy?: 'strip' | SecretSealer;
  maxQueue?: number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  onDrop?: (op: TumblerReplicaMutation, queueDepth: number) => void;
  onPush?: (ok: boolean, op: TumblerReplicaMutation, attempt: number) => void;
  fetchImpl?: typeof fetch;
  /** Persist these values with the primary. A changed stream requires full resync. */
  streamId?: string;
  epoch?: number;
  initialCheckpoint?: ReplicationCheckpoint;
  now?: () => number;
  /**
   * Confirms that the primary mutation, pending operation, and source
   * checkpoint are durably recoverable as one deployment transaction.
   * Omit to make promotion fail closed.
   */
  promotionDurability?: (checkpoint: ReplicationCheckpoint) => boolean;
}

const DEFAULTS = {
  maxQueue: 5000,
  backoffBaseMs: 1000,
  backoffMaxMs: 30_000,
  timeoutMs: 5000,
};

function assertStrongSecret(secret: string, name: string): void {
  if (Buffer.byteLength(secret, 'utf8') < MIN_REPLICATION_TOKEN_BYTES) {
    throw new Error(`${name} must contain at least ${MIN_REPLICATION_TOKEN_BYTES} bytes`);
  }
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(item => canonical(item === undefined ? null : item)).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).filter(key => record[key] !== undefined).sort()
    .map(key => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
}

export function computeReplicationHash(input: {
  streamId: string;
  epoch: number;
  sequence: number;
  previousHash: string;
  mutation: TumblerReplicaMutation;
}): string {
  return createHash('sha256').update(canonical(input), 'utf8').digest('hex');
}

function unsignedEnvelope(op: TumblerReplicaOp): Omit<TumblerReplicaOp, 'signature'> {
  const { signature: _signature, ...unsigned } = op;
  return unsigned;
}

export function signReplicaEnvelope(
  input: Omit<TumblerReplicaOp, 'signature'>,
  token: string,
): TumblerReplicaOp {
  assertStrongSecret(token, 'replica token');
  const signature = createHmac('sha256', token).update(canonical(input), 'utf8').digest('base64url');
  return { ...input, signature };
}

export function verifyReplicaEnvelopeSignature(op: TumblerReplicaOp, token: string): boolean {
  try {
    assertStrongSecret(token, 'replica token');
    const expected = createHmac('sha256', token)
      .update(canonical(unsignedEnvelope(op)), 'utf8')
      .digest();
    const presented = Buffer.from(op.signature, 'base64url');
    return presented.toString('base64url') === op.signature &&
      presented.length === expected.length && timingSafeEqual(presented, expected);
  } catch {
    return false;
  }
}

export class ReplicatingTumblerStore implements TumblerMapStore {
  private readonly queue: PendingReplicaOp[] = [];
  private draining = false;
  private attempt = 0;
  private integrityLost = false;
  private readonly secretPolicy: 'strip' | SecretSealer;
  private readonly maxQueue: number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly onDrop?: (op: TumblerReplicaMutation, queueDepth: number) => void;
  private readonly onPush?: (ok: boolean, op: TumblerReplicaMutation, attempt: number) => void;
  private readonly fetchImpl?: typeof fetch;
  private readonly now: () => number;
  private readonly promotionDurability?: (checkpoint: ReplicationCheckpoint) => boolean;
  private checkpoint: ReplicationCheckpoint;

  constructor(
    private readonly primary: TumblerMapStore,
    private readonly replica: ReplicaTarget,
    options: ReplicatingTumblerOptions = {},
  ) {
    assertStrongSecret(replica.token, 'replica token');
    if (!Number.isInteger(options.maxQueue ?? DEFAULTS.maxQueue) || (options.maxQueue ?? DEFAULTS.maxQueue) < 1) {
      throw new Error('maxQueue must be a positive integer');
    }
    this.secretPolicy = options.secretPolicy ?? 'strip';
    this.maxQueue = options.maxQueue ?? DEFAULTS.maxQueue;
    this.backoffBaseMs = options.backoffBaseMs ?? DEFAULTS.backoffBaseMs;
    this.backoffMaxMs = options.backoffMaxMs ?? DEFAULTS.backoffMaxMs;
    this.onDrop = options.onDrop;
    this.onPush = options.onPush;
    this.fetchImpl = options.fetchImpl;
    this.now = options.now ?? Date.now;
    this.promotionDurability = options.promotionDurability;

    if (options.initialCheckpoint) {
      this.checkpoint = { ...options.initialCheckpoint };
    } else {
      const epoch = options.epoch ?? 1;
      if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error('replication epoch must be a positive safe integer');
      this.checkpoint = {
        streamId: options.streamId ?? randomUUID(),
        epoch,
        sequence: 0,
        headHash: REPLICATION_GENESIS_HASH,
      };
    }
  }

  get(clientId: string) { return this.primary.get(clientId); }
  list() { return this.primary.list(); }

  async set(clientId: string, map: TumblerMap): Promise<void> {
    await this.primary.set(clientId, map);
    const { map: wireMap, secretSealed } = await this.sealMap(map);
    this.enqueueMutation({ op: 'set', clientId, map: wireMap, secretSealed });
  }

  async delete(clientId: string): Promise<void> {
    await this.primary.delete(clientId);
    this.enqueueMutation({ op: 'delete', clientId });
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    await this.primary.updateCounters(clientId, updates);
    this.enqueueMutation({ op: 'updateCounters', clientId, updates: [...updates] });
  }

  async consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    if (!this.primary.consumeCounter) return false;
    const ok = await this.primary.consumeCounter(clientId, segmentId, matchedCounter);
    if (ok) this.enqueueMutation({ op: 'consumeCounter', clientId, segmentId, matchedCounter });
    return ok;
  }

  async commitValidation(clientId: string, input: ValidationCommitInput): Promise<ValidationCommitResult> {
    const result = await this.primary.commitValidation(clientId, input);
    const current = await this.primary.get(clientId);
    if (current) {
      const { map, secretSealed } = await this.sealMap(current);
      this.enqueueMutation({ op: 'set', clientId, map, secretSealed });
    }
    return result;
  }

  async replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean> {
    const replaced = await this.primary.replaceCredential(oldClientId, replacement);
    if (!replaced) return false;
    for (const clientId of [oldClientId, replacement.clientId]) {
      const current = await this.primary.get(clientId);
      if (current) {
        const { map, secretSealed } = await this.sealMap(current);
        this.enqueueMutation({ op: 'set', clientId, map, secretSealed });
      }
    }
    return true;
  }

  private async sealMap(map: TumblerMap): Promise<{ map: TumblerMap; secretSealed: boolean }> {
    if (this.secretPolicy === 'strip') {
      return { map: { ...map, sharedSecret: '' }, secretSealed: false };
    }
    const sealed = await this.secretPolicy(map.clientId, map.sharedSecret);
    return { map: { ...map, sharedSecret: sealed }, secretSealed: true };
  }

  get queueDepth(): number { return this.queue.length; }
  get replicationIntegrityLost(): boolean { return this.integrityLost; }

  /**
   * Source checkpoint eligible for a signed promotion grant. A missing result is
   * a hard stop: the replica may not be promoted.
   */
  promotionCheckpoint(): ReplicationCheckpoint | null {
    if (this.integrityLost || this.draining || this.queue.length !== 0) return null;
    const checkpoint = { ...this.checkpoint };
    try {
      if (!this.promotionDurability?.(checkpoint)) return null;
    } catch {
      return null;
    }
    return checkpoint;
  }

  private enqueueMutation(mutation: TumblerReplicaMutation): void {
    const previousHash = this.checkpoint.headHash;
    const sequence = this.checkpoint.sequence + 1;
    const base = {
      streamId: this.checkpoint.streamId,
      epoch: this.checkpoint.epoch,
      sequence,
      previousHash,
      mutation,
    };
    const headHash = computeReplicationHash(base);
    const pending: PendingReplicaOp = {
      checkpoint: { streamId: base.streamId, epoch: base.epoch, sequence, headHash },
      previousHash,
      mutation,
    };
    this.checkpoint = { ...pending.checkpoint };

    if (this.queue.length >= this.maxQueue) {
      // Never remove index 0 while it may be in flight. Drop the incoming op,
      // retain its hash in the source chain, and permanently mark the stream as
      // non-promotable. The receiver will reject the resulting sequence gap.
      this.integrityLost = true;
      this.onDrop?.(mutation, this.queue.length);
      return;
    }
    this.queue.push(pending);
    void this.drain();
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.queue.length > 0) {
        const pending = this.queue[0];
        const ok = await this.push(pending);
        if (ok) {
          // Remove only the exact operation that completed. A queue mutation may
          // never acknowledge a different operation.
          if (this.queue[0] !== pending) {
            this.integrityLost = true;
            return;
          }
          this.queue.shift();
          this.attempt = 0;
        } else {
          this.attempt++;
          await this.sleep(this.backoff());
        }
      }
    } finally {
      this.draining = false;
    }
  }

  private backoff(): number {
    const ms = this.backoffBaseMs * 2 ** Math.min(this.attempt - 1, 10);
    return Math.min(ms, this.backoffMaxMs);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, Math.max(0, ms)));
  }

  private async push(pending: PendingReplicaOp): Promise<boolean> {
    const doFetch = this.fetchImpl ?? fetch;
    const unsigned: Omit<TumblerReplicaOp, 'signature'> = {
      ...pending.checkpoint,
      previousHash: pending.previousHash,
      sentAt: this.now(),
      mutation: pending.mutation,
    };
    const envelope = signReplicaEnvelope(unsigned, this.replica.token);
    try {
      const response = await doFetch(`${this.replica.url}/tumbler`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(envelope),
        signal: AbortSignal.timeout(this.replica.timeoutMs ?? DEFAULTS.timeoutMs),
      });
      const ok = response.ok;
      this.onPush?.(ok, pending.mutation, this.attempt);
      return ok;
    } catch {
      this.onPush?.(false, pending.mutation, this.attempt);
      return false;
    }
  }

  async flush(timeoutMs = 10_000): Promise<boolean> {
    const start = this.now();
    while (this.draining || this.queue.length > 0) {
      if (this.now() - start > timeoutMs) return false;
      await this.sleep(25);
    }
    return !this.integrityLost;
  }
}
