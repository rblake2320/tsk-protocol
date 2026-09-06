/**
 * FileTumblerStore — JSON-file-backed tumbler map persistence for TSK.
 *
 * Survives server restarts. Suitable for single-node deployments,
 * local dev with persistence, and terminal identity management in PKA.
 *
 * Provides single-process atomic counter/lifecycle commits, TTL expiry, and a
 * bounded entry count. It is not a multi-process or multi-node store.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, openSync, fsyncSync, closeSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname } from 'node:path';
import type { TumblerMap } from '@tsk/core';
import {
  commitValidationToMap,
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

  /** Publish authority only after the complete candidate has reached the file. */
  private flush(candidate: FileTumblerData): void {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const temporary = `${this.filePath}.${process.pid}.${randomUUID()}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(temporary, 'wx', 0o600);
      writeFileSync(fd, JSON.stringify(candidate, null, 2), { encoding: 'utf8' });
      fsyncSync(fd);
      closeSync(fd); fd = undefined;
      renameSync(temporary, this.filePath);
      this.data = candidate;
    } catch (error) {
      const cleanupErrors: unknown[] = [];
      if (fd !== undefined) { try { closeSync(fd); } catch (cleanup) { cleanupErrors.push(cleanup); } }
      if (existsSync(temporary)) { try { unlinkSync(temporary); } catch (cleanup) { cleanupErrors.push(cleanup); } }
      if (cleanupErrors.length) throw new AggregateError([error, ...cleanupErrors], `TSK_FILE_STORE_WRITE_FAILED: ${this.filePath}`);
      throw error;
    }
  }

  async set(clientId: string, map: TumblerMap): Promise<void> {
    const candidate = structuredClone(this.data);
    if (!candidate.maps[clientId] && Object.keys(candidate.maps).length >= this.maxEntries) {
      throw new Error('TSK_STORE_CAPACITY_REACHED');
    }
    candidate.maps[clientId] = structuredClone(map);
    candidate.lastAccess[clientId] = Date.now();
    this.flush(candidate);
  }

  async get(clientId: string): Promise<TumblerMap | null> {
    const map = this.data.maps[clientId];
    if (!map) return null;
    if (this.maxAgeMs > 0 && Date.now() - map.createdAt > this.maxAgeMs) {
      const candidate = structuredClone(this.data);
      delete candidate.maps[clientId];
      delete candidate.lastAccess[clientId];
      this.flush(candidate);
      return null;
    }
    this.data.lastAccess[clientId] = Date.now();
    return structuredClone(map);
  }

  async delete(clientId: string): Promise<void> {
    const candidate = structuredClone(this.data);
    delete candidate.maps[clientId];
    delete candidate.lastAccess[clientId];
    this.flush(candidate);
  }

  async list(): Promise<string[]> {
    return Object.keys(this.data.maps);
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    const candidate = structuredClone(this.data);
    const map = candidate.maps[clientId];
    if (!map) return;
    for (const seg of map.segments) {
      const newCounter = updates.get(seg.segmentId);
      if (newCounter !== undefined && seg.type === 'hotp') {
        seg.counter = newCounter;
      }
    }
    this.flush(candidate);
  }

  /**
   * Atomic CAS for HOTP counter — single-process atomic within Node.js event loop.
   * For multi-process deployments, replace with a Lua Redis script or PG row lock.
   */
  consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    const candidate = structuredClone(this.data);
    const map = candidate.maps[clientId];
    if (!map) return Promise.resolve(false);
    const seg = map.segments.find(s => s.segmentId === segmentId);
    if (!seg || seg.type !== 'hotp') return Promise.resolve(false);
    const stored = seg.counter ?? 0;
    if (stored > matchedCounter) return Promise.resolve(false); // already consumed
    seg.counter = matchedCounter + 1;
    this.flush(candidate);
    return Promise.resolve(true);
  }

  commitValidation(clientId: string, input: ValidationCommitInput): Promise<ValidationCommitResult> {
    const candidate = structuredClone(this.data);
    const map = candidate.maps[clientId];
    if (!map) return Promise.resolve({ ok: false, error: 'TSK_KEY_EXPIRED' });
    const result = commitValidationToMap(map, input);
    this.flush(candidate);
    return Promise.resolve(result);
  }

  replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean> {
    const candidate = structuredClone(this.data);
    const current = candidate.maps[oldClientId];
    if (!current || (current.status !== undefined && current.status !== 'active' && current.status !== 'expiring')) {
      return Promise.resolve(false);
    }
    if (candidate.maps[replacement.clientId]) return Promise.resolve(false);
    current.status = 'revoked';
    if (Object.keys(candidate.maps).length >= this.maxEntries) {
      delete candidate.maps[oldClientId];
      delete candidate.lastAccess[oldClientId];
    }
    candidate.maps[replacement.clientId] = structuredClone(replacement);
    candidate.lastAccess[oldClientId] = Date.now();
    candidate.lastAccess[replacement.clientId] = Date.now();
    this.flush(candidate);
    return Promise.resolve(true);
  }

  get trackedClients(): number {
    return Object.keys(this.data.maps).length;
  }
}
