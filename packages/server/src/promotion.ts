/**
 * Lease and fencing-epoch gate for authoritative TSK writes.
 *
 * Every writer, including the normal primary, needs a fresh guard-signed lease.
 * A shared FencingStore atomically accepts only increasing epochs, so activation
 * of a replica invalidates the old primary's lease on its next write check.
 */
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type { TumblerMap } from '@tsk/core';
import type { ReplicationCheckpoint } from './replicating-tumbler-store.js';
import type {
  TumblerMapStore,
  ValidationCommitInput,
  ValidationCommitResult,
} from './store.js';

export type NodeRole = 'primary' | 'replica';
export type GuardCommandType = 'activate' | 'promote' | 'demote';

export interface GuardCommand {
  command: GuardCommandType;
  commandId: string;
  nodeId: string;
  fenceEpoch: number;
  issuedAt: number;
  expiresAt: number;
  by: string;
  reason?: string;
  /** Required for replica promotion; bound into the guard signature. */
  requiredCheckpoint?: ReplicationCheckpoint;
  signature: string;
}

export interface FenceRecord {
  nodeId: string;
  fenceEpoch: number;
  expiresAt: number;
  commandId: string;
  active: boolean;
}

/** Must be implemented by one strongly consistent store shared by all writers. */
export interface FencingStore {
  current(): Promise<FenceRecord | null>;
  claim(record: Omit<FenceRecord, 'active'>): Promise<boolean>;
  release(nodeId: string, fenceEpoch: number, commandId: string): Promise<boolean>;
}

/** Single-process reference implementation used by the standalone suites. */
export class MemoryFencingStore implements FencingStore {
  private record: FenceRecord | null = null;

  current(): Promise<FenceRecord | null> {
    return Promise.resolve(this.record ? { ...this.record } : null);
  }

  claim(next: Omit<FenceRecord, 'active'>): Promise<boolean> {
    // Strictly increasing means a replayed grant can never renew or resurrect a
    // released lease, even for the same node.
    if (this.record && next.fenceEpoch <= this.record.fenceEpoch) return Promise.resolve(false);
    this.record = { ...next, active: true };
    return Promise.resolve(true);
  }

  release(nodeId: string, fenceEpoch: number, commandId: string): Promise<boolean> {
    if (!this.record || !this.record.active || this.record.nodeId !== nodeId ||
        this.record.fenceEpoch !== fenceEpoch || this.record.commandId !== commandId) {
      return Promise.resolve(false);
    }
    this.record = { ...this.record, active: false };
    return Promise.resolve(true);
  }
}

export interface PromotionControllerOptions {
  now?: () => number;
  maxCommandAgeMs?: number;
  maxLeaseMs?: number;
  /** Replica receiver checkpoint. Omit on a primary. */
  replicaCheckpoint?: () => ReplicationCheckpoint | null;
}

export interface PromotionSnapshot {
  role: NodeRole;
  nodeId: string;
  writable: boolean;
  fenceEpoch: number | null;
  leaseExpiresAt: number | null;
  activatedBy: string | null;
  reason: string | null;
}

const MIN_GUARD_SECRET_BYTES = 32;
const DEFAULT_MAX_COMMAND_AGE_MS = 60_000;
const DEFAULT_MAX_LEASE_MS = 5 * 60_000;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(item => canonical(item === undefined ? null : item)).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).filter(key => record[key] !== undefined).sort()
    .map(key => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
}

function unsigned(command: GuardCommand): Omit<GuardCommand, 'signature'> {
  const { signature: _signature, ...rest } = command;
  return rest;
}

function validSecret(secret: string): boolean {
  return Buffer.byteLength(secret, 'utf8') >= MIN_GUARD_SECRET_BYTES;
}

export function signGuardCommand(
  command: Omit<GuardCommand, 'signature' | 'commandId'> & { commandId?: string },
  guardSecret: string,
): GuardCommand {
  if (!validSecret(guardSecret)) throw new Error(`guard secret must contain at least ${MIN_GUARD_SECRET_BYTES} bytes`);
  const withId = { ...command, commandId: command.commandId ?? randomUUID() };
  const signature = createHmac('sha256', guardSecret).update(canonical(withId), 'utf8').digest('base64url');
  return { ...withId, signature };
}

export function verifyGuardCommandSignature(command: GuardCommand, guardSecret: string): boolean {
  if (!validSecret(guardSecret) || !SIGNATURE_PATTERN.test(command.signature)) return false;
  const expected = createHmac('sha256', guardSecret).update(canonical(unsigned(command)), 'utf8').digest();
  const presented = Buffer.from(command.signature, 'base64url');
  return presented.toString('base64url') === command.signature &&
    presented.length === expected.length && timingSafeEqual(presented, expected);
}

function sameCheckpoint(left: ReplicationCheckpoint, right: ReplicationCheckpoint): boolean {
  return left.streamId === right.streamId && left.epoch === right.epoch &&
    left.sequence === right.sequence && left.headHash === right.headHash;
}

export class PromotionController {
  private readonly now: () => number;
  private readonly maxCommandAgeMs: number;
  private readonly maxLeaseMs: number;
  private readonly replicaCheckpoint?: () => ReplicationCheckpoint | null;
  private lease: GuardCommand | null = null;

  constructor(
    public readonly role: NodeRole,
    public readonly nodeId: string,
    private readonly fenceStore: FencingStore,
    options: PromotionControllerOptions = {},
  ) {
    if (!nodeId) throw new Error('nodeId is required');
    this.now = options.now ?? Date.now;
    this.maxCommandAgeMs = options.maxCommandAgeMs ?? DEFAULT_MAX_COMMAND_AGE_MS;
    this.maxLeaseMs = options.maxLeaseMs ?? DEFAULT_MAX_LEASE_MS;
    this.replicaCheckpoint = options.replicaCheckpoint;
  }

  /** Called only after signature/shape validation by handlePromotionCommand. */
  async activate(command: GuardCommand): Promise<{ ok: true } | { ok: false; error: string }> {
    if (command.nodeId !== this.nodeId) return { ok: false, error: 'wrong_node' };
    if (this.role === 'primary' && command.command !== 'activate') return { ok: false, error: 'wrong_command_for_primary' };
    if (this.role === 'replica' && command.command !== 'promote') return { ok: false, error: 'wrong_command_for_replica' };

    if (this.role === 'replica') {
      const local = this.replicaCheckpoint?.();
      const required = command.requiredCheckpoint;
      if (!local || !required || local.sequence < 1 || !sameCheckpoint(local, required)) {
        return { ok: false, error: 'replica_not_converged' };
      }
    }

    const claimed = await this.fenceStore.claim({
      nodeId: this.nodeId,
      fenceEpoch: command.fenceEpoch,
      expiresAt: command.expiresAt,
      commandId: command.commandId,
    });
    if (!claimed) return { ok: false, error: 'fence_epoch_not_monotonic' };
    this.lease = command;
    return { ok: true };
  }

  async demote(command: GuardCommand): Promise<{ ok: true } | { ok: false; error: string }> {
    if (command.command !== 'demote' || command.nodeId !== this.nodeId) return { ok: false, error: 'invalid_demotion' };
    const currentLease = this.lease;
    if (!currentLease || currentLease.fenceEpoch !== command.fenceEpoch) return { ok: false, error: 'lease_mismatch' };
    const released = await this.fenceStore.release(this.nodeId, currentLease.fenceEpoch, currentLease.commandId);
    if (!released) return { ok: false, error: 'fence_release_failed' };
    this.lease = null;
    return { ok: true };
  }

  async isWritable(): Promise<boolean> {
    try {
      if (!this.lease || this.lease.expiresAt <= this.now()) return false;
      const current = await this.fenceStore.current();
      return Boolean(current?.active && current.nodeId === this.nodeId &&
        current.fenceEpoch === this.lease.fenceEpoch && current.commandId === this.lease.commandId &&
        current.expiresAt === this.lease.expiresAt && current.expiresAt > this.now());
    } catch {
      // An unavailable fencing authority is a write outage, never permission.
      return false;
    }
  }

  async snapshot(): Promise<PromotionSnapshot> {
    return {
      role: this.role,
      nodeId: this.nodeId,
      writable: await this.isWritable(),
      fenceEpoch: this.lease?.fenceEpoch ?? null,
      leaseExpiresAt: this.lease?.expiresAt ?? null,
      activatedBy: this.lease?.by ?? null,
      reason: this.lease?.reason ?? null,
    };
  }

  validateFreshness(command: GuardCommand): string | null {
    const now = this.now();
    if (!Number.isSafeInteger(command.fenceEpoch) || command.fenceEpoch < 1) return 'invalid_fence_epoch';
    if (!Number.isSafeInteger(command.issuedAt) || !Number.isSafeInteger(command.expiresAt)) return 'invalid_time';
    if (command.issuedAt > now || now - command.issuedAt > this.maxCommandAgeMs) return 'command_stale';
    if (command.expiresAt <= now || command.expiresAt - command.issuedAt > this.maxLeaseMs) return 'invalid_lease_window';
    if (!command.commandId || !command.by || !command.nodeId) return 'invalid_identity';
    return null;
  }
}

/** Gate every client-facing authoritative mutation. */
export async function assertWritable(
  controller: PromotionController,
): Promise<{ ok: true; fenceEpoch: number } | { ok: false; status: number; error: string }> {
  const snapshot = await controller.snapshot();
  if (snapshot.writable && snapshot.fenceEpoch !== null) return { ok: true, fenceEpoch: snapshot.fenceEpoch };
  return { ok: false, status: 503, error: 'writer_lease_missing_stale_or_fenced' };
}

/** Raised when an authoritative store mutation is attempted without a lease. */
export class WriterFencedError extends Error {
  readonly code = 'TSK_WRITER_FENCED';

  constructor() {
    super('TSK authoritative mutation denied: writer lease is missing, stale, or fenced');
    this.name = 'WriterFencedError';
  }
}

/**
 * Non-optional mutation boundary for an authoritative TSK store.
 *
 * Deployments using promotion/failover must expose this wrapper, not the inner
 * store, to provisioners, validators, revocation handlers, or replication
 * receivers. Reads pass through; every interface-defined mutation rechecks the
 * shared fence immediately before delegating.
 */
export class FencedTumblerStore implements TumblerMapStore {
  constructor(
    private readonly inner: TumblerMapStore,
    private readonly controller: PromotionController,
  ) {}

  get(clientId: string): Promise<TumblerMap | null> { return this.inner.get(clientId); }
  list(): Promise<string[]> { return this.inner.list(); }

  async set(clientId: string, map: TumblerMap): Promise<void> {
    await this.requireWritable();
    await this.inner.set(clientId, map);
  }

  async delete(clientId: string): Promise<void> {
    await this.requireWritable();
    await this.inner.delete(clientId);
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    await this.requireWritable();
    await this.inner.updateCounters(clientId, updates);
  }

  async consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    await this.requireWritable();
    if (!this.inner.consumeCounter) return false;
    return this.inner.consumeCounter(clientId, segmentId, matchedCounter);
  }

  async commitValidation(
    clientId: string,
    input: ValidationCommitInput,
  ): Promise<ValidationCommitResult> {
    await this.requireWritable();
    return this.inner.commitValidation(clientId, input);
  }

  async replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean> {
    await this.requireWritable();
    return this.inner.replaceCredential(oldClientId, replacement);
  }

  private async requireWritable(): Promise<void> {
    if (!(await assertWritable(this.controller)).ok) throw new WriterFencedError();
  }
}

function isGuardCommand(value: unknown): value is GuardCommand {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<GuardCommand>;
  return ['activate', 'promote', 'demote'].includes(candidate.command ?? '') &&
    typeof candidate.commandId === 'string' && typeof candidate.nodeId === 'string' &&
    typeof candidate.by === 'string' && typeof candidate.signature === 'string' &&
    typeof candidate.fenceEpoch === 'number' && typeof candidate.issuedAt === 'number' &&
    typeof candidate.expiresAt === 'number';
}

/** Verify a signed, fresh guard command and apply it to the shared fence. */
export async function handlePromotionCommand(
  controller: PromotionController,
  body: unknown,
  guardSecret: string,
): Promise<{ status: number; result: unknown }> {
  if (!isGuardCommand(body)) return { status: 400, result: { ok: false, error: 'invalid_body' } };
  if (!verifyGuardCommandSignature(body, guardSecret)) {
    return { status: 401, result: { ok: false, error: 'signature_invalid' } };
  }
  const freshnessError = controller.validateFreshness(body);
  if (freshnessError) return { status: 401, result: { ok: false, error: freshnessError } };
  const result = body.command === 'demote'
    ? await controller.demote(body)
    : await controller.activate(body);
  if (!result.ok) return { status: 409, result };
  return { status: 200, result: { ok: true, snapshot: await controller.snapshot() } };
}
