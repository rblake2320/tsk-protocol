/**
 * FileTumblerStore — JSON-file-backed tumbler map persistence for TSK.
 *
 * Survives server restarts. Suitable for single-node deployments,
 * local dev with persistence, and terminal identity management in PKA.
 *
 * Preserves all IL4/5/6/7 hardening: atomic HOTP CAS (single-process),
 * TTL expiry, bounded entry count. For multi-node: use PgTumblerStore.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { TumblerMap } from '@tsk/core';
import type { TumblerMapStore } from './store.js';

interface FileTumblerData {
  maps: Record<string, TumblerMap>;
  lastAccess: Record<string, number>; // LRU tracking — ms timestamps
}

export class FileTumblerStore implements TumblerMapStore {
  private data: FileTumblerData = { maps: {}, lastAccess: {} };

  private readonly maxEntries: number;
  private readonly maxAgeMs: number;

  constructor(
    private readonly filePath: string,
    config: { maxEntries?: number; maxAgeSec?: number } = {},
  ) {
    this.maxEntries = config.maxEntries ?? 100_000;
    this.maxAgeMs   = (config.maxAgeSec ?? 90 * 24 * 3600) * 1000;
    this.load();
  }

  private load(): void {
    try {
      if (existsSync(this.filePath)) {
        const raw = readFileSync(this.filePath, 'utf8');
        this.data = JSON.parse(raw) as FileTumblerData;
        this.data.maps       ??= {};
        this.data.lastAccess ??= {};
        // Prune TTL-expired entries immediately
        if (this.maxAgeMs > 0) {
          const now = Date.now();
          for (const [id, map] of Object.entries(this.data.maps)) {
            if (now - map.createdAt > this.maxAgeMs) {
              delete this.data.maps[id];
              delete this.data.lastAccess[id];
            }
          }
        }
      }
    } catch {
      this.data = { maps: {}, lastAccess: {} };
    }
  }

  private flush(): void {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf8');
  }

  private evictLRU(): void {
    const entries = Object.entries(this.data.lastAccess).sort((a, b) => a[1] - b[1]);
    const lruId = entries[0]?.[0];
    if (lruId) {
      delete this.data.maps[lruId];
      delete this.data.lastAccess[lruId];
    }
  }

  async set(clientId: string, map: TumblerMap): Promise<void> {
    if (!this.data.maps[clientId] && Object.keys(this.data.maps).length >= this.maxEntries) {
      this.evictLRU();
    }
    this.data.maps[clientId] = { ...map };
    this.data.lastAccess[clientId] = Date.now();
    this.flush();
  }

  async get(clientId: string): Promise<TumblerMap | null> {
    const map = this.data.maps[clientId];
    if (!map) return null;
    if (this.maxAgeMs > 0 && Date.now() - map.createdAt > this.maxAgeMs) {
      delete this.data.maps[clientId];
      delete this.data.lastAccess[clientId];
      this.flush();
      return null;
    }
    this.data.lastAccess[clientId] = Date.now();
    return map;
  }

  async delete(clientId: string): Promise<void> {
    delete this.data.maps[clientId];
    delete this.data.lastAccess[clientId];
    this.flush();
  }

  async list(): Promise<string[]> {
    return Object.keys(this.data.maps);
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    const map = this.data.maps[clientId];
    if (!map) return;
    for (const seg of map.segments) {
      const newCounter = updates.get(seg.segmentId);
      if (newCounter !== undefined && seg.type === 'hotp') {
        seg.counter = newCounter;
      }
    }
    this.flush();
  }

  /**
   * Atomic CAS for HOTP counter — single-process atomic within Node.js event loop.
   * For multi-process deployments, replace with a Lua Redis script or PG row lock.
   */
  consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    const map = this.data.maps[clientId];
    if (!map) return Promise.resolve(false);
    const seg = map.segments.find(s => s.segmentId === segmentId);
    if (!seg || seg.type !== 'hotp') return Promise.resolve(false);
    const stored = seg.counter ?? 0;
    if (stored > matchedCounter) return Promise.resolve(false); // already consumed
    seg.counter = matchedCounter + 1;
    this.flush();
    return Promise.resolve(true);
  }

  get trackedClients(): number {
    return Object.keys(this.data.maps).length;
  }
}
