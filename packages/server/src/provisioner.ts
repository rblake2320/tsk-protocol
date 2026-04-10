/**
 * TSK Protocol — Server-Side Provisioner
 *
 * Handles client provisioning: generating a new tumbler map, storing it,
 * and returning the client-facing provision payload (positions omitted).
 */

import {
  generateTumblerMap,
  toProvisionPayload,
  type TumblerMap,
  type TSKProvisionPayload,
  type TumblerMapOptions,
} from '@tsk/core';
import type { TumblerMapStore } from './store.js';

export interface ProvisionResult {
  ok: boolean;
  clientId?: string;
  /** Safe to send to client — positions are omitted */
  provisionPayload?: TSKProvisionPayload;
  /** Full map — NEVER send to client, store server-side only */
  tumblerMap?: TumblerMap;
  error?: string;
}

export class TSKProvisioner {
  constructor(private store: TumblerMapStore) {}

  /**
   * Provision a new client.
   * Returns the client-facing payload and the full map (for audit/logging if needed).
   */
  async provision(options: TumblerMapOptions = {}): Promise<ProvisionResult> {
    try {
      const map = generateTumblerMap(options);
      await this.store.set(map.clientId, map);

      return {
        ok: true,
        clientId: map.clientId,
        provisionPayload: toProvisionPayload(map),
        tumblerMap: map,
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : 'PROVISION_FAILED',
      };
    }
  }

  /**
   * Revoke a client's tumbler map.
   */
  async revoke(clientId: string): Promise<void> {
    await this.store.delete(clientId);
  }
}
