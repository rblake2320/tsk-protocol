/**
 * FileTumblerStore — JSON-file-backed tumbler map persistence for TSK.
 *
 * Survives server restarts. Suitable for single-node deployments,
 * local dev with persistence, and terminal identity management in PKA.
 *
 * Uses exclusive per-file transactions, fresh disk reads and bounded entries.
 * Lock contention or abandoned locks fail closed; no automatic write retries.
 * This is a local-filesystem store, not a distributed or network-filesystem store.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, openSync, fsyncSync, closeSync, unlinkSync, realpathSync, lstatSync, fstatSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, basename, resolve, join } from 'node:path';
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

function record(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validClientId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 &&
    !['__proto__', 'constructor', 'prototype'].includes(value);
}

function requireClientId(value: unknown): asserts value is string {
  if (!validClientId(value)) throw new Error('TSK_FILE_STORE_CLIENT_ID_INVALID');
}

function natural(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** Persisted JSON is untrusted runtime input, never a TypeScript assertion. */
function validateFileData(value: unknown): asserts value is FileTumblerData {
  if (!record(value) || !record(value.maps) || !record(value.lastAccess)) throw new Error('invalid store envelope');
  for (const [id, map] of Object.entries(value.maps)) {
    if (!validClientId(id) || !record(map) || map.clientId !== id ||
        map.version !== '1' || typeof map.sharedSecret !== 'string' || !/^[0-9a-fA-F]{64}$/.test(map.sharedSecret) ||
        !natural(map.createdAt) || !natural(map.keyLength) || map.keyLength < 20 || map.keyLength > 512 ||
        !Array.isArray(map.segments) || !map.segments.length || !record(map.checksum)) throw new Error('invalid map');
    let cursor = 0;
    const ids = new Set<string>();
    for (const segment of map.segments) {
      if (!record(segment) || typeof segment.segmentId !== 'string' || !segment.segmentId || ids.has(segment.segmentId) ||
          !Array.isArray(segment.position) || segment.position.length !== 2 ||
          !natural(segment.position[0]) || !natural(segment.position[1]) || segment.position[0] !== cursor ||
          segment.position[1] <= cursor || segment.position[1] > map.keyLength ||
          !['hotp', 'totp', 'static'].includes(segment.type)) throw new Error('invalid segment');
      if (segment.type === 'hotp' && !natural(segment.counter)) throw new Error('invalid counter');
      if (segment.type === 'totp' && (!natural(segment.windowSec) || segment.windowSec === 0)) throw new Error('invalid window');
      ids.add(segment.segmentId); cursor = segment.position[1];
    }
    const position = map.checksum.position;
    if (!Array.isArray(position) || position.length !== 2 || position[0] !== cursor ||
        position[1] !== map.keyLength || cursor >= map.keyLength) throw new Error('invalid checksum');
    for (const key of ['expiresAt', 'requestCount', 'maxRequests', 'rotationWarningRequests']) {
      if (map[key] !== undefined && !natural(map[key])) throw new Error('invalid lifecycle number');
    }
    if (map.lastUsedAt !== undefined && map.lastUsedAt !== null && !natural(map.lastUsedAt)) throw new Error('invalid last use');
    if (map.status !== undefined && !['active', 'expiring', 'revoked', 'expired'].includes(map.status)) throw new Error('invalid status');
    if (!natural(value.lastAccess[id])) throw new Error('invalid access time');
  }
  for (const [id, time] of Object.entries(value.lastAccess)) {
    if (!Object.hasOwn(value.maps, id) || !natural(time)) throw new Error('invalid access entry');
  }
}

export class FileTumblerStore implements TumblerMapStore {
  private data: FileTumblerData = { maps: {}, lastAccess: {} };

  private readonly maxEntries: number;
  private readonly maxAgeMs: number;

  private expired(map: TumblerMap): boolean {
    return this.maxAgeMs > 0 && Date.now() - map.createdAt > this.maxAgeMs;
  }

  constructor(
    private readonly filePath: string,
    config: { maxEntries?: number; maxAgeSec?: number } = {},
  ) {
    this.maxEntries = config.maxEntries ?? 100_000;
    const maxAgeSec = config.maxAgeSec ?? 90 * 24 * 3600;
    if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries < 1 ||
        !Number.isFinite(maxAgeSec) || maxAgeSec < 0 || !Number.isSafeInteger(maxAgeSec * 1000)) {
      throw new Error(`TSK_FILE_STORE_CONFIG_INVALID: ${filePath}`);
    }
    const absolute = resolve(filePath);
    mkdirSync(dirname(absolute), {recursive: true});
    this.filePath = join(realpathSync(dirname(absolute)), basename(absolute));
    this.maxAgeMs = maxAgeSec * 1000;
    this.load();
  }

  private load(): void {
    if (!existsSync(this.filePath)) {
      this.data = { maps: {}, lastAccess: {} };
      return;
    }
    try {
      const stat = lstatSync(this.filePath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error('unsafe backing file');
      const candidate: unknown = JSON.parse(readFileSync(this.filePath, 'utf8'));
      validateFileData(candidate);
      this.data = candidate;
    } catch {
      throw new Error(`TSK_FILE_STORE_CORRUPT: ${this.filePath}`);
    }
  }

  /** Exclusive transaction across instances/processes; abandoned locks fail closed.
   * Never age out a lock: a suspended writer is not a dead writer. An operator
   * must resolve an abandoned lock with the owning process stopped before reuse.
   */
  private transaction<T>(operation: () => T): T {
    const lock = this.filePath + '.lock';
    let fd: number;
    try { fd = openSync(lock, 'wx', 0o600); }
    catch { throw new Error(`TSK_FILE_STORE_LOCK_UNAVAILABLE: ${lock}; do not retry writes until ownership is resolved`); }
    const identity = fstatSync(fd, {bigint: true});
    try {
      writeFileSync(fd, JSON.stringify({pid: process.pid, owner: randomUUID(), createdAt: Date.now()}));
      fsyncSync(fd);
      this.load();
      return operation();
    } finally {
      closeSync(fd);
      const current = lstatSync(lock, {bigint: true});
      if (current.dev !== identity.dev || current.ino !== identity.ino)
        throw new Error(`TSK_FILE_STORE_LOCK_CHANGED: ${lock}; operation outcome may be unknown`);
      unlinkSync(lock);
    }
  }

  /** Publish authority only after the complete candidate has reached the file. */
  private flush(candidate: FileTumblerData): void {
    validateFileData(candidate);
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
    requireClientId(clientId);
    return this.transaction(() => {
      const candidate = structuredClone(this.data);
      if (!Object.hasOwn(candidate.maps, clientId) && Object.keys(candidate.maps).length >= this.maxEntries) {
        throw new Error('TSK_STORE_CAPACITY_REACHED');
      }
      candidate.maps[clientId] = structuredClone(map);
      candidate.lastAccess[clientId] = Date.now();
      this.flush(candidate);

    });
  }

  async get(clientId: string): Promise<TumblerMap | null> {
    requireClientId(clientId);
    return this.transaction(() => {
      const map = Object.hasOwn(this.data.maps, clientId) ? this.data.maps[clientId] : undefined;
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

    });
  }

  async delete(clientId: string): Promise<void> {
    requireClientId(clientId);
    return this.transaction(() => {
      const candidate = structuredClone(this.data);
      delete candidate.maps[clientId];
      delete candidate.lastAccess[clientId];
      this.flush(candidate);

    });
  }

  async list(): Promise<string[]> {
    return this.transaction(() => {
      return Object.entries(this.data.maps).filter(([, map]) => !this.expired(map)).map(([id]) => id);

    });
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    requireClientId(clientId);
    return this.transaction(() => {
      const candidate = structuredClone(this.data);
      const map = Object.hasOwn(candidate.maps, clientId) ? candidate.maps[clientId] : undefined;
      if (!map) throw new Error(`TSK_FILE_STORE_CLIENT_MISSING: ${clientId}`);
      if (this.expired(map)) throw new Error(`TSK_FILE_STORE_CLIENT_EXPIRED: ${clientId}`);
      for (const seg of map.segments) {
        const newCounter = updates.get(seg.segmentId);
        if (newCounter !== undefined && seg.type === 'hotp') {
          seg.counter = newCounter;
        }
      }
      this.flush(candidate);

    });
  }

  /**
   * Atomic CAS for HOTP counter — single-process atomic within Node.js event loop.
   * For multi-process deployments, replace with a Lua Redis script or PG row lock.
   */
  consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    requireClientId(clientId);
    return Promise.resolve(this.transaction(() => {
      const candidate = structuredClone(this.data);
      const map = Object.hasOwn(candidate.maps, clientId) ? candidate.maps[clientId] : undefined;
      if (!map || this.expired(map)) return false;
      const seg = map.segments.find(s => s.segmentId === segmentId);
      if (!seg || seg.type !== 'hotp') return false;
      const stored = seg.counter ?? 0;
      if (stored > matchedCounter) return false; // already consumed
      seg.counter = matchedCounter + 1;
      this.flush(candidate);
      return true;

    }));
  }

  commitValidation(clientId: string, input: ValidationCommitInput): Promise<ValidationCommitResult> {
    requireClientId(clientId);
    return Promise.resolve(this.transaction(() => {
      const candidate = structuredClone(this.data);
      const map = Object.hasOwn(candidate.maps, clientId) ? candidate.maps[clientId] : undefined;
      if (!map || this.expired(map)) return { ok: false, error: 'TSK_KEY_EXPIRED' } as ValidationCommitResult;
      const result = commitValidationToMap(map, input);
      this.flush(candidate);
      return result;

    }));
  }

  replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean> {
    requireClientId(oldClientId);
    requireClientId(replacement?.clientId);
    return Promise.resolve(this.transaction(() => {
      const candidate = structuredClone(this.data);
      const current = Object.hasOwn(candidate.maps, oldClientId) ? candidate.maps[oldClientId] : undefined;
      if (!current || this.expired(current) || (current.status !== undefined && current.status !== 'active' && current.status !== 'expiring')) {
        return false;
      }
      if (Object.hasOwn(candidate.maps, replacement.clientId)) return false;
      current.status = 'revoked';
      if (Object.keys(candidate.maps).length >= this.maxEntries) {
        delete candidate.maps[oldClientId];
        delete candidate.lastAccess[oldClientId];
      }
      candidate.maps[replacement.clientId] = structuredClone(replacement);
      if (Object.hasOwn(candidate.maps, oldClientId)) candidate.lastAccess[oldClientId] = Date.now();
      candidate.lastAccess[replacement.clientId] = Date.now();
      this.flush(candidate);
      return true;

    }));
  }

  get trackedClients(): number {
    return this.transaction(() => {
      return Object.keys(this.data.maps).length;

    });
  }
}
