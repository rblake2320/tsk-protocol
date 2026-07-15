/**
 * TSK Client SDK — Provision Payload Storage
 *
 * Stores the client-side provision payload received at provisioning time.
 * The ordered segment lengths reveal cumulative boundaries. The shared secret
 * is provided separately and is not written by this storage abstraction.
 */

import type { TSKProvisionPayload } from '@tsk/core';

export interface TSKClientStorage {
  save(payload: TSKProvisionPayload): Promise<void>;
  load(clientId: string): Promise<TSKProvisionPayload | null>;
  delete(clientId: string): Promise<void>;
  /**
   * Persist an HOTP counter value to survive process restarts.
   * Optional — if not implemented, counters reset to initialCounter on restart
   * (which causes desync if the server has advanced beyond that point).
   * STRONGLY RECOMMENDED for production deployments.
   */
  saveCounter?(clientId: string, segmentId: string, counter: number): Promise<void>;
  /** Atomically persist the full counter vector for one accepted request. */
  saveCounters(clientId: string, counters: ReadonlyMap<string, number>): Promise<void>;
  /**
   * Load a persisted HOTP counter value.
   * Returns undefined if no counter has been persisted yet.
   */
  loadCounter(clientId: string, segmentId: string): Promise<number | undefined>;
}

/**
 * In-memory storage (for testing and server-side Node.js clients).
 * Includes counter persistence to prevent HOTP desync on process restart.
 */
export class MemoryClientStorage implements TSKClientStorage {
  private store = new Map<string, TSKProvisionPayload>();
  private counters = new Map<string, number>(); // key: `${clientId}:${segmentId}`

  async save(payload: TSKProvisionPayload): Promise<void> {
    this.store.set(payload.clientId, payload);
  }

  async load(clientId: string): Promise<TSKProvisionPayload | null> {
    return this.store.get(clientId) ?? null;
  }

  async delete(clientId: string): Promise<void> {
    this.store.delete(clientId);
    // Clean up persisted counters for this client
    for (const key of this.counters.keys()) {
      if (key.startsWith(`${clientId}:`)) this.counters.delete(key);
    }
  }

  async saveCounter(clientId: string, segmentId: string, counter: number): Promise<void> {
    this.counters.set(`${clientId}:${segmentId}`, counter);
  }

  async saveCounters(clientId: string, counters: ReadonlyMap<string, number>): Promise<void> {
    for (const [segmentId, counter] of counters) {
      this.counters.set(`${clientId}:${segmentId}`, counter);
    }
  }

  async loadCounter(clientId: string, segmentId: string): Promise<number | undefined> {
    return this.counters.get(`${clientId}:${segmentId}`);
  }
}

/**
 * Node.js file-backed storage (for persistent CLI/server clients).
 * Writes to a local JSON file — recommend OS-level file encryption or Vault integration.
 */
export class FileClientStorage implements TSKClientStorage {
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(private filePath: string) {}

  private async readData(): Promise<{
    version: 1;
    payloads: Record<string, TSKProvisionPayload>;
    counters: Record<string, number>;
  }> {
    const { readFile } = await import('node:fs/promises');
    try {
      const parsed = JSON.parse(await readFile(this.filePath, 'utf-8')) as Record<string, unknown>;
      if (parsed['version'] === 1 && parsed['payloads'] && parsed['counters']) {
        return parsed as unknown as {
          version: 1;
          payloads: Record<string, TSKProvisionPayload>;
          counters: Record<string, number>;
        };
      }
      // Backward-compatible read of the original payload-only object.
      return { version: 1, payloads: parsed as Record<string, TSKProvisionPayload>, counters: {} };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { version: 1, payloads: {}, counters: {} };
      }
      throw new Error(
        `TSK_CLIENT_STORE_CORRUPT: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  private async writeData(data: {
    version: 1;
    payloads: Record<string, TSKProvisionPayload>;
    counters: Record<string, number>;
  }): Promise<void> {
    const { mkdir, rename, writeFile } = await import('node:fs/promises');
    const { dirname } = await import('node:path');
    const dir = dirname(this.filePath);
    await mkdir(dir, { recursive: true });
    const temporary = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(temporary, JSON.stringify(data, null, 2), { encoding: 'utf-8', mode: 0o600 });
    await rename(temporary, this.filePath);
  }

  private async mutate(
    change: (data: { version: 1; payloads: Record<string, TSKProvisionPayload>; counters: Record<string, number> }) => void,
  ): Promise<void> {
    const operation = this.mutationQueue.then(async () => {
      const data = await this.readData();
      change(data);
      await this.writeData(data);
    });
    this.mutationQueue = operation.catch(() => undefined);
    return operation;
  }

  async save(payload: TSKProvisionPayload): Promise<void> {
    await this.mutate(data => { data.payloads[payload.clientId] = payload; });
  }

  async load(clientId: string): Promise<TSKProvisionPayload | null> {
    return (await this.readData()).payloads[clientId] ?? null;
  }

  async delete(clientId: string): Promise<void> {
    await this.mutate(data => {
      delete data.payloads[clientId];
      for (const key of Object.keys(data.counters)) {
        if (key.startsWith(`${clientId}:`)) delete data.counters[key];
      }
    });
  }

  async saveCounter(clientId: string, segmentId: string, counter: number): Promise<void> {
    await this.mutate(data => { data.counters[`${clientId}:${segmentId}`] = counter; });
  }

  async saveCounters(clientId: string, counters: ReadonlyMap<string, number>): Promise<void> {
    await this.mutate(data => {
      for (const [segmentId, counter] of counters) {
        data.counters[`${clientId}:${segmentId}`] = counter;
      }
    });
  }

  async loadCounter(clientId: string, segmentId: string): Promise<number | undefined> {
    return (await this.readData()).counters[`${clientId}:${segmentId}`];
  }
}
