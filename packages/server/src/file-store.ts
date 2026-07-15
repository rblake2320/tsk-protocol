/**
 * FileTumblerStore — JSON-file-backed tumbler map persistence for TSK.
 *
 * Survives server restarts. Suitable for single-node deployments,
 * local dev with persistence, and terminal identity management in PKA.
 *
 * Provides single-process atomic counter/lifecycle commits, TTL expiry, and a
 * bounded entry count. It is not a multi-process or multi-node store.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  TSK_MAX_HOTP_COUNTER,
  assertValidHOTPStoredCounter,
  isUsableHOTPDerivationCounter,
  minimumHOTPUsesRemaining,
  type TumblerMap,
} from '@tsk/core';
import {
  assertTumblerMapCounterState,
  commitValidationToMap,
  reconcileTumblerMapCounterStatus,
  type TumblerMapStore,
  type ValidationCommitInput,
  type ValidationCommitResult,
} from './store.js';

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
        for (const map of Object.values(this.data.maps)) {
          assertTumblerMapCounterState(map);
        }
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
    } catch (error) {
      throw new Error(
        `TSK_FILE_STORE_CORRUPT: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  private flush(): void {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const temporary = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
    writeFileSync(temporary, JSON.stringify(this.data, null, 2), { encoding: 'utf8', mode: 0o600 });
    renameSync(temporary, this.filePath);
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
      throw new Error('TSK_STORE_CAPACITY_REACHED');
    }
    assertTumblerMapCounterState(map);
    this.data.maps[clientId] = structuredClone(map);
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
    return structuredClone(map);
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
    for (const [segmentId, newCounter] of updates) {
      const segment = map.segments.find(candidate => candidate.segmentId === segmentId);
      if (!segment || segment.type !== 'hotp') throw new Error('TSK_HOTP_COUNTER_INVALID');
      assertValidHOTPStoredCounter(newCounter, `HOTP counter for ${segmentId}`);
      if (newCounter < (segment.counter ?? 0)) throw new Error('TSK_HOTP_COUNTER_ROLLBACK');
    }
    for (const seg of map.segments) {
      const newCounter = updates.get(seg.segmentId);
      if (newCounter !== undefined && seg.type === 'hotp') {
        seg.counter = newCounter;
      }
    }
    const remaining = minimumHOTPUsesRemaining(map.segments);
    if (remaining !== undefined) reconcileTumblerMapCounterStatus(map, remaining);
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
    if (!isUsableHOTPDerivationCounter(stored) ||
        !isUsableHOTPDerivationCounter(matchedCounter)) {
      if (stored === TSK_MAX_HOTP_COUNTER) map.status = 'expired';
      this.flush();
      return Promise.resolve(false);
    }
    if (stored > matchedCounter) return Promise.resolve(false); // already consumed
    seg.counter = matchedCounter + 1;
    const remaining = minimumHOTPUsesRemaining(map.segments);
    if (remaining !== undefined) reconcileTumblerMapCounterStatus(map, remaining);
    this.flush();
    return Promise.resolve(true);
  }

  commitValidation(clientId: string, input: ValidationCommitInput): Promise<ValidationCommitResult> {
    const map = this.data.maps[clientId];
    if (!map) return Promise.resolve({ ok: false, error: 'TSK_KEY_EXPIRED' });
    const result = commitValidationToMap(map, input);
    this.flush();
    return Promise.resolve(result);
  }

  replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean> {
    assertTumblerMapCounterState(replacement);
    const current = this.data.maps[oldClientId];
    if (!current || (current.status !== undefined && current.status !== 'active' && current.status !== 'expiring')) {
      return Promise.resolve(false);
    }
    if (this.data.maps[replacement.clientId]) return Promise.resolve(false);
    current.status = 'revoked';
    if (Object.keys(this.data.maps).length >= this.maxEntries) {
      delete this.data.maps[oldClientId];
      delete this.data.lastAccess[oldClientId];
    }
    this.data.maps[replacement.clientId] = structuredClone(replacement);
    this.data.lastAccess[oldClientId] = Date.now();
    this.data.lastAccess[replacement.clientId] = Date.now();
    this.flush();
    return Promise.resolve(true);
  }

  get trackedClients(): number {
    return Object.keys(this.data.maps).length;
  }
}
