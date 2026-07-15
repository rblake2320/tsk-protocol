/**
 * TSK Protocol — Abstract Store Interfaces
 *
 * Key security fixes in this version:
 * 1. BOUNDED MEMORY: MemoryTumblerStore rejects new entries at its configured
 *    cap instead of silently evicting an active credential.
 * 2. TTL EVICTION: entries older than maxAgeSec are automatically expired on
 *    access, preventing unbounded growth of stale maps.
 * 3. ATOMIC COMMIT: bundled stores commit all counters and lifecycle usage in
 *    one single-process transaction. Distributed stores must provide equivalent
 *    database or script-level atomicity.
 * 4. MONITORING: trackedClients getter for observability.
 */
import type { TumblerMap } from '@tsk/core';

export interface ValidationCommitInput {
  counterMatches: Array<{ segmentId: string; matchedCounter: number }>;
  usedAt: number;
}

export interface ValidationCommitResult {
  ok: boolean;
  error?: 'TSK_KEY_REVOKED' | 'TSK_KEY_EXPIRED' | 'TSK_KEY_USAGE_CAP_EXCEEDED' | 'TSK_HOTP_REPLAY_DETECTED';
  requestCount?: number;
  requestsRemaining?: number;
  rotationRequired?: boolean;
}

// ─── Abstract Interface ───────────────────────────────────────────────────────

/**
 * Abstract storage for tumbler maps.
 * Implementations: MemoryTumblerStore (dev), PgTumblerStore, RedisTumblerStore
 */
export interface TumblerMapStore {
  /** Store a tumbler map for a client */
  set(clientId: string, map: TumblerMap): Promise<void>;
  /** Retrieve a tumbler map */
  get(clientId: string): Promise<TumblerMap | null>;
  /** Delete a tumbler map (revocation) */
  delete(clientId: string): Promise<void>;
  /** List all client IDs */
  list(): Promise<string[]>;
  /** Update HOTP counter values after successful validation */
  updateCounters(clientId: string, updates: Map<string, number>): Promise<void>;
  /**
   * Atomic compare-and-swap for HOTP counter — prevents replay under concurrency.
   *
   * Returns true if counter was at expectedCounter and has been atomically advanced.
   * Returns false if counter has already moved (concurrent duplicate = replay).
   *
   * PRODUCTION REQUIREMENT: implement this on all stores used in multi-server or
   * high-concurrency deployments. Without it, the middleware falls back to the
   * non-atomic updateCounters(), which has a validate→update race window.
   *
   * Implementation notes:
   * - MemoryTumblerStore: synchronous Map mutation (atomic within single process)
   * - PgTumblerStore: use UPDATE ... WHERE counter = expectedCounter RETURNING id
   * - RedisTumblerStore: use a Lua script: if GET == expected then SET expected+1
   */
  consumeCounter?(clientId: string, segmentId: string, expectedCounter: number): Promise<boolean>;
  /**
   * Atomically commit every replay-sensitive counter and the lifecycle usage
   * count for one successful validation. Implementations must perform all
   * checks before mutating any field.
   */
  commitValidation(clientId: string, input: ValidationCommitInput): Promise<ValidationCommitResult>;
  /** Atomically add the replacement and mark the prior credential revoked. */
  replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean>;
}

/** Mutate one already-exclusive map only after every commit precondition passes. */
export function commitValidationToMap(
  map: TumblerMap,
  input: ValidationCommitInput,
): ValidationCommitResult {
  if (map.status === 'revoked') return { ok: false, error: 'TSK_KEY_REVOKED' };
  if (map.status === 'expired') return { ok: false, error: 'TSK_KEY_EXPIRED' };
  if (map.expiresAt !== undefined && input.usedAt > map.expiresAt) {
    map.status = 'expired';
    return { ok: false, error: 'TSK_KEY_EXPIRED' };
  }

  const currentCount = map.requestCount ?? 0;
  if (map.maxRequests !== undefined && map.maxRequests > 0 && currentCount >= map.maxRequests) {
    map.status = 'expired';
    return { ok: false, error: 'TSK_KEY_USAGE_CAP_EXCEEDED' };
  }

  const segments = new Map(map.segments.map(segment => [segment.segmentId, segment]));
  for (const update of input.counterMatches) {
    const segment = segments.get(update.segmentId);
    if (!segment || segment.type !== 'hotp' || (segment.counter ?? 0) > update.matchedCounter) {
      return { ok: false, error: 'TSK_HOTP_REPLAY_DETECTED' };
    }
  }

  for (const update of input.counterMatches) {
    segments.get(update.segmentId)!.counter = update.matchedCounter + 1;
  }

  const requestCount = currentCount + 1;
  map.requestCount = requestCount;
  map.lastUsedAt = input.usedAt;

  if (map.maxRequests === undefined || map.maxRequests <= 0) {
    return { ok: true, requestCount, rotationRequired: false };
  }

  const requestsRemaining = Math.max(0, map.maxRequests - requestCount);
  const configuredWindow = map.rotationWarningRequests
    ?? Math.max(1, Math.ceil(map.maxRequests * 0.1));
  const warningWindow = Math.min(map.maxRequests, Math.max(1, configuredWindow));
  const rotationRequired = requestsRemaining <= warningWindow;
  if (rotationRequired) map.status = 'expiring';

  return { ok: true, requestCount, requestsRemaining, rotationRequired };
}

// ─── Memory Store Config ──────────────────────────────────────────────────────

export interface MemoryStoreConfig {
  /**
   * Maximum number of tumbler maps to store. New clients fail at the limit;
   * active credentials are never silently evicted. Default: 100,000.
   */
  maxEntries?: number;
  /**
   * Maximum age of a tumbler map in seconds before it is considered expired.
   * Expired maps are deleted on access. Default: 90 days (7,776,000 seconds).
   * Set to 0 to disable TTL.
   */
  maxAgeSec?: number;
}

// ─── In-Memory Store ──────────────────────────────────────────────────────────

/**
 * In-memory tumbler map store.
 *
 * SECURITY: Bounded with fail-on-capacity behavior and TTL for stale maps.
 * For production multi-server deployments, replace with PgTumblerStore or
 * RedisTumblerStore to share state across instances.
 */
export class MemoryTumblerStore implements TumblerMapStore {
  private maps = new Map<string, TumblerMap>();
  private accessOrder: string[] = []; // LRU tracking (most recent at end)

  private readonly maxEntries: number;
  private readonly maxAgeMs: number;

  constructor(config: MemoryStoreConfig = {}) {
    this.maxEntries = config.maxEntries ?? 100_000;
    this.maxAgeMs = (config.maxAgeSec ?? 90 * 24 * 3600) * 1000;
  }

  async set(clientId: string, map: TumblerMap): Promise<void> {
    // Never silently evict an active credential. Capacity is a hard failure.
    if (!this.maps.has(clientId) && this.maps.size >= this.maxEntries) {
      throw new Error('TSK_STORE_CAPACITY_REACHED');
    }

    this.maps.set(clientId, structuredClone(map));
    this.touchLRU(clientId);
  }

  async get(clientId: string): Promise<TumblerMap | null> {
    const map = this.maps.get(clientId);
    if (!map) return null;

    // TTL check: expire maps older than maxAgeMs
    if (this.maxAgeMs > 0 && Date.now() - map.createdAt > this.maxAgeMs) {
      this.maps.delete(clientId);
      this.removeLRU(clientId);
      return null;
    }

    this.touchLRU(clientId);
    return structuredClone(map);
  }

  async delete(clientId: string): Promise<void> {
    this.maps.delete(clientId);
    this.removeLRU(clientId);
  }

  async list(): Promise<string[]> {
    return Array.from(this.maps.keys());
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    const map = this.maps.get(clientId);
    if (!map) return;
    for (const seg of map.segments) {
      const newCounter = updates.get(seg.segmentId);
      if (newCounter !== undefined && seg.type === 'hotp') {
        seg.counter = newCounter;
      }
    }
  }

  /**
   * Atomic compare-and-swap for HOTP counter.
   *
   * SECURITY: This is synchronous and therefore truly atomic within a single
   * Node.js process (no await between read and write). For multi-process or
   * multi-server deployments, use a Redis Lua script or PostgreSQL
   * UPDATE ... WHERE counter = expectedCounter.
   */
  consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    const map = this.maps.get(clientId);
    if (!map) return Promise.resolve(false);

    const seg = map.segments.find(s => s.segmentId === segmentId);
    if (!seg || seg.type !== 'hotp') return Promise.resolve(false);

    const storedCounter = seg.counter ?? 0;
    // Atomic CAS for HOTP with lookahead:
    // matchedCounter is the counter value that was matched during validation
    // (may be storedCounter + lookahead, e.g., stored=0, matched=3).
    // Accept if storedCounter <= matchedCounter (not yet consumed).
    // A concurrent duplicate would find storedCounter > matchedCounter after
    // the first request advances it, correctly rejecting the replay.
    if (storedCounter > matchedCounter) {
      // Counter already advanced past this point — concurrent replay detected
      return Promise.resolve(false);
    }
    // Advance stored counter to matchedCounter + 1
    seg.counter = matchedCounter + 1;
    return Promise.resolve(true);
  }

  commitValidation(clientId: string, input: ValidationCommitInput): Promise<ValidationCommitResult> {
    const map = this.maps.get(clientId);
    if (!map) return Promise.resolve({ ok: false, error: 'TSK_KEY_EXPIRED' });
    return Promise.resolve(commitValidationToMap(map, input));
  }

  async replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean> {
    const current = this.maps.get(oldClientId);
    if (!current || (current.status !== undefined && current.status !== 'active' && current.status !== 'expiring')) {
      return false;
    }
    if (this.maps.has(replacement.clientId)) return false;
    current.status = 'revoked';
    if (this.maps.size >= this.maxEntries) {
      // Preserve the hard capacity bound. Removing the old credential still
      // makes every old-key request fail closed.
      this.maps.delete(oldClientId);
      this.removeLRU(oldClientId);
    }
    await this.set(replacement.clientId, replacement);
    return true;
  }

  /** Return current number of tracked clients (for monitoring). */
  get trackedClients(): number {
    return this.maps.size;
  }

  // ── LRU helpers ────────────────────────────────────────────────────────────

  private touchLRU(clientId: string): void {
    const idx = this.accessOrder.indexOf(clientId);
    if (idx !== -1) this.accessOrder.splice(idx, 1);
    this.accessOrder.push(clientId);
  }

  private removeLRU(clientId: string): void {
    const idx = this.accessOrder.indexOf(clientId);
    if (idx !== -1) this.accessOrder.splice(idx, 1);
  }
}
