/**
 * ReplicatingTumblerStore — async write-mirroring decorator for HA TSK.
 *
 * Wraps ANY primary TumblerMapStore and mirrors every mutation to a remote
 * replica over HTTPS. Mirrors the BPC ReplicatingPairStore HA pattern, but the
 * mutation surface and wire format follow TumblerMapStore — NOT the BPC pair
 * shape. The decisive divergence is secret handling (HA-03'), below.
 *
 *  HA-01 Local-first authority:
 *    The primary mutation completes and its result is returned to the caller
 *    BEFORE the replica is touched. A slow/down/unreachable replica NEVER blocks
 *    or fails a primary operation. consumeCounter() — the replay-critical atomic
 *    CAS — is decided entirely by the primary; only a SUCCESSFUL consume is then
 *    mirrored, so the replica's counter stays monotonic and replay-safe too.
 *
 *  HA-02 Bounded retry queue (no memory exhaustion):
 *    Failed pushes retry with exponential backoff. The queue is capped and sheds
 *    OLDEST entries when full, surfacing the loss via onDrop. A long replica
 *    outage cannot exhaust primary memory.
 *
 *  HA-03' Secret never leaks by default (TSK-specific):
 *    Unlike BPC (asymmetric — the replica only ever held a verifier), TSK is a
 *    SHARED-SECRET protocol: TumblerMap.sharedSecret is live signing material
 *    that the type contract says is "NEVER transmitted after provisioning".
 *    Therefore the DEFAULT policy ('strip') ensures sharedSecret NEVER crosses
 *    the wire — the replica receives a metadata-only map (sharedSecret = '') and
 *    can serve revocation / expiry / counter state, but cannot independently
 *    validate keys. Full-failover validation is an EXPLICIT opt-in: pass a
 *    SecretSealer that envelope-encrypts the secret so a passive replica
 *    compromise (DB dump) still leaks nothing. The dangerous path is never
 *    accidental.
 *
 * NIST SP 800-53 Rev 5: CP-9, CP-10, SC-5, SC-28 (protection of information at
 * rest), AU-9.
 */
import type { TumblerMapStore } from './store.js';
import type { TumblerMap } from '@tsk/core';

/**
 * Seals a per-client sharedSecret before it crosses the wire. Return value
 * replaces TumblerMap.sharedSecret on the replicated copy. Implement with
 * envelope encryption under a key the replica controls; NEVER return the raw
 * secret. Only used when secretPolicy is set to a sealer (opt-in).
 */
export type SecretSealer = (clientId: string, sharedSecretHex: string) => Promise<string> | string;

export type TumblerReplicaOp =
  | { op: 'set'; clientId: string; map: TumblerMap; secretSealed: boolean }
  | { op: 'delete'; clientId: string }
  | { op: 'updateCounters'; clientId: string; updates: Array<[string, number]> }
  | { op: 'consumeCounter'; clientId: string; segmentId: string; matchedCounter: number };

export interface ReplicaTarget {
  /** Base URL of the replica ingest endpoint, e.g. https://srv1740069.hstgr.cloud/replica */
  url: string;
  /** Shared replication auth token (sent as x-replica-token). NOT a TSK secret. */
  token: string;
  /** Per-request timeout. Default 5000ms. */
  timeoutMs?: number;
}

export interface ReplicatingTumblerOptions {
  /**
   * sharedSecret handling before transmission.
   * - 'strip' (DEFAULT, SECURE): sharedSecret is NEVER replicated. Replica holds
   *   metadata only and cannot independently validate keys.
   * - SecretSealer: envelope-encrypt for full-failover validation, accepting
   *   sealed key material on the replica. Use only with a replica held to the
   *   same standard as the primary.
   */
  secretPolicy?: 'strip' | SecretSealer;
  /** Max queued ops before oldest are shed. Default 5000. */
  maxQueue?: number;
  /** Base backoff in ms for retries. Default 1000. */
  backoffBaseMs?: number;
  /** Max backoff in ms. Default 30_000. */
  backoffMaxMs?: number;
  /** Called when an op is shed because the queue is full (replication lag alarm). */
  onDrop?: (op: TumblerReplicaOp, queueDepth: number) => void;
  /** Called on each push outcome — wire to metrics/health. */
  onPush?: (ok: boolean, op: TumblerReplicaOp, attempt: number) => void;
  /** Injectable fetch for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

const DEFAULTS = {
  maxQueue: 5000,
  backoffBaseMs: 1000,
  backoffMaxMs: 30_000,
  timeoutMs: 5000,
};

export class ReplicatingTumblerStore implements TumblerMapStore {
  private readonly queue: TumblerReplicaOp[] = [];
  private draining = false;
  private attempt = 0;

  private readonly secretPolicy: 'strip' | SecretSealer;
  private readonly maxQueue: number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly onDrop?: (op: TumblerReplicaOp, queueDepth: number) => void;
  private readonly onPush?: (ok: boolean, op: TumblerReplicaOp, attempt: number) => void;
  private readonly fetchImpl?: typeof fetch;

  constructor(
    private readonly primary: TumblerMapStore,
    private readonly replica: ReplicaTarget,
    options: ReplicatingTumblerOptions = {},
  ) {
    this.secretPolicy = options.secretPolicy ?? 'strip';
    this.maxQueue = options.maxQueue ?? DEFAULTS.maxQueue;
    this.backoffBaseMs = options.backoffBaseMs ?? DEFAULTS.backoffBaseMs;
    this.backoffMaxMs = options.backoffMaxMs ?? DEFAULTS.backoffMaxMs;
    this.onDrop = options.onDrop;
    this.onPush = options.onPush;
    this.fetchImpl = options.fetchImpl;
  }

  // ── Reads always hit the authoritative primary ──────────────────────────────
  get(clientId: string) { return this.primary.get(clientId); }
  list() { return this.primary.list(); }

  // ── Writes: primary first (authoritative), then async mirror ────────────────
  async set(clientId: string, map: TumblerMap): Promise<void> {
    await this.primary.set(clientId, map);
    const { map: wireMap, secretSealed } = await this.sealMap(map);
    this.enqueue({ op: 'set', clientId, map: wireMap, secretSealed });
  }

  async delete(clientId: string): Promise<void> {
    await this.primary.delete(clientId);
    this.enqueue({ op: 'delete', clientId });
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    await this.primary.updateCounters(clientId, updates);
    // HA: a JS Map does NOT survive JSON.stringify — serialize to entries.
    this.enqueue({ op: 'updateCounters', clientId, updates: [...updates] });
  }

  async consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    // HA-01: the primary is authoritative for the replay decision.
    if (!this.primary.consumeCounter) {
      // Underlying store has no atomic CAS — nothing to mirror, nothing to claim.
      return false;
    }
    const ok = await this.primary.consumeCounter(clientId, segmentId, matchedCounter);
    // Only mirror a SUCCESSFUL consume so the replica advances identically and
    // a rejected replay is never propagated.
    if (ok) this.enqueue({ op: 'consumeCounter', clientId, segmentId, matchedCounter });
    return ok;
  }

  // ── Secret sealing (HA-03') ─────────────────────────────────────────────────

  private async sealMap(map: TumblerMap): Promise<{ map: TumblerMap; secretSealed: boolean }> {
    if (this.secretPolicy === 'strip') {
      // Metadata-only: sharedSecret NEVER crosses the wire.
      return { map: { ...map, sharedSecret: '' }, secretSealed: false };
    }
    const sealed = await this.secretPolicy(map.clientId, map.sharedSecret);
    return { map: { ...map, sharedSecret: sealed }, secretSealed: true };
  }

  // ── Replication queue ───────────────────────────────────────────────────────

  /** Current number of unreplicated ops — wire to a "replication lag" gauge. */
  get queueDepth(): number { return this.queue.length; }

  private enqueue(op: TumblerReplicaOp): void {
    if (this.queue.length >= this.maxQueue) {
      const dropped = this.queue.shift();
      if (dropped) this.onDrop?.(dropped, this.queue.length);
    }
    this.queue.push(op);
    void this.drain();
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.queue.length > 0) {
        const op = this.queue[0];
        const ok = await this.push(op);
        if (ok) {
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
    const ms = this.backoffBaseMs * 2 ** Math.min(this.attempt, 10);
    return Math.min(ms, this.backoffMaxMs);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }

  private async push(op: TumblerReplicaOp): Promise<boolean> {
    const doFetch = this.fetchImpl ?? fetch;
    try {
      const res = await doFetch(`${this.replica.url}/tumbler`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-replica-token': this.replica.token,
        },
        body: JSON.stringify({ ...op, ts: Date.now() }),
        signal: AbortSignal.timeout(this.replica.timeoutMs ?? DEFAULTS.timeoutMs),
      });
      const ok = res.ok;
      this.onPush?.(ok, op, this.attempt);
      return ok;
    } catch {
      this.onPush?.(false, op, this.attempt);
      return false;
    }
  }

  /** Test/operational hook: wait until the queue is fully replicated or timeout. */
  async flush(timeoutMs = 10_000): Promise<boolean> {
    const start = Date.now();
    while (this.queue.length > 0) {
      if (Date.now() - start > timeoutMs) return false;
      await this.sleep(25);
    }
    return true;
  }
}
