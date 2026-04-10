/**
 * TSK Client SDK — Provision Payload Storage
 *
 * Stores the client-side provision payload received at provisioning time.
 * NOTE: The stored payload contains segment types/timing but NOT positions —
 * positions are the server's secret. The shared secret IS stored client-side
 * (needed for key generation), secured in hardware storage when possible.
 */

import type { TSKProvisionPayload } from '@tsk/core';

export interface TSKClientStorage {
  save(payload: TSKProvisionPayload): Promise<void>;
  load(clientId: string): Promise<TSKProvisionPayload | null>;
  delete(clientId: string): Promise<void>;
}

/**
 * In-memory storage (for testing and server-side Node.js clients).
 */
export class MemoryClientStorage implements TSKClientStorage {
  private store = new Map<string, TSKProvisionPayload>();

  async save(payload: TSKProvisionPayload): Promise<void> {
    this.store.set(payload.clientId, payload);
  }

  async load(clientId: string): Promise<TSKProvisionPayload | null> {
    return this.store.get(clientId) ?? null;
  }

  async delete(clientId: string): Promise<void> {
    this.store.delete(clientId);
  }
}

/**
 * Node.js file-backed storage (for persistent CLI/server clients).
 * Writes to a local JSON file — recommend OS-level file encryption or Vault integration.
 */
export class FileClientStorage implements TSKClientStorage {
  constructor(private filePath: string) {}

  async save(payload: TSKProvisionPayload): Promise<void> {
    const { writeFile, readFile } = await import('node:fs/promises');
    let store: Record<string, TSKProvisionPayload> = {};
    try {
      const raw = await readFile(this.filePath, 'utf-8');
      store = JSON.parse(raw);
    } catch {
      // File doesn't exist yet — start fresh
    }
    store[payload.clientId] = payload;
    await writeFile(this.filePath, JSON.stringify(store, null, 2), 'utf-8');
  }

  async load(clientId: string): Promise<TSKProvisionPayload | null> {
    const { readFile } = await import('node:fs/promises');
    try {
      const raw = await readFile(this.filePath, 'utf-8');
      const store: Record<string, TSKProvisionPayload> = JSON.parse(raw);
      return store[clientId] ?? null;
    } catch {
      return null;
    }
  }

  async delete(clientId: string): Promise<void> {
    const { writeFile, readFile } = await import('node:fs/promises');
    try {
      const raw = await readFile(this.filePath, 'utf-8');
      const store: Record<string, TSKProvisionPayload> = JSON.parse(raw);
      delete store[clientId];
      await writeFile(this.filePath, JSON.stringify(store, null, 2), 'utf-8');
    } catch {
      // Nothing to delete
    }
  }
}
