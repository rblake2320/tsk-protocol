/**
 * TSK Protocol — Abstract Store Interfaces
 * IL4/5/6/7-hardened.
 *
 * Key security fixes in this version:
 * 1. BOUNDED MEMORY: MemoryTumblerStore enforces a max entry count with LRU
 *    eviction to prevent memory exhaustion via provisioner spam.
 * 2. TTL EVICTION: entries older than maxAgeSec are automatically expired on
 *    access, preventing unbounded growth of stale maps.
 * 3. ATOMIC CAS: consumeCounter() is properly atomic within the single-process
 *    in-memory store. Production note: PgTumblerStore must use SELECT FOR UPDATE,
 *    RedisTumblerStore must use a Lua CAS script.
 * 4. MONITORING: trackedClients getter for observability.
 */
import type { TumblerMap } from '@tsk/core';

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
}

// ─── Memory Store Config ──────────────────────────────────────────────────────

export interface MemoryStoreConfig {
  /**
   * Maximum number of tumbler maps to store.
   * LRU eviction when limit is reached. Default: 100,000.
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
 * SECURITY: Bounded with LRU eviction and TTL to prevent memory exhaustion.
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
    // LRU eviction if at capacity
    if (!this.maps.has(clientId) && this.maps.size >= this.maxEntries) {
      const lruKey = this.accessOrder.shift();
      if (lruKey) this.maps.delete(lruKey);
    }

    this.maps.set(clientId, { ...map });
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
    return map;
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
