/**
 * TSK Protocol — Abstract Store Interfaces
 * Following the same pattern as BPC's store interfaces for consistency.
 */

import type { TumblerMap } from '@tsk/core';

/**
 * Abstract storage for tumbler maps.
 * Implementations: MemoryTumblerStore, PgTumblerStore, RedisTumblerStore
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
   * Returns true if counter was at expectedCounter and has been atomically advanced.
   * Returns false if counter has already moved (concurrent duplicate request = replay).
   *
   * PRODUCTION REQUIREMENT: implement this on all stores used in multi-server or
   * high-concurrency deployments. Without it, the middleware falls back to the
   * non-atomic updateCounters(), which has a validate→update race window.
   * MemoryTumblerStore implements it. PgTumblerStore should use SELECT FOR UPDATE.
   * RedisTumblerStore should use a Lua CAS script.
   */
  consumeCounter?(clientId: string, segmentId: string, expectedCounter: number): Promise<boolean>;
}

/**
 * In-memory tumbler map store (for testing and single-server dev).
 */
export class MemoryTumblerStore implements TumblerMapStore {
  private maps = new Map<string, TumblerMap>();

  async set(clientId: string, map: TumblerMap): Promise<void> {
    this.maps.set(clientId, { ...map });
  }

  async get(clientId: string): Promise<TumblerMap | null> {
    return this.maps.get(clientId) ?? null;
  }

  async delete(clientId: string): Promise<void> {
    this.maps.delete(clientId);
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

  async consumeCounter(clientId: string, segmentId: string, expectedCounter: number): Promise<boolean> {
    const map = this.maps.get(clientId);
    if (!map) return false;
    const seg = map.segments.find(s => s.segmentId === segmentId);
    if (!seg || seg.counter !== expectedCounter) return false;
    seg.counter = expectedCounter + 1;
    return true;
  }
}
