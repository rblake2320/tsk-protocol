/**
 * TSK Protocol — Client SDK
 *
 * TSKClient wraps HTTP fetch with automatic TSK key generation.
 * Uses the client-side provision payload to generate keys per-request.
 *
 * Usage:
 *   const client = new TSKClient({ clientId: 'tsk_abc', storage });
 *   await client.init(); // loads provision payload from storage
 *   const response = await client.fetch('https://api.example.com/data', { method: 'GET' });
 */

import {
  generateClientSegmentValues,
  hmac as hmacFn,
  type TSKProvisionPayload,
  type ClientSegmentConfig,
} from '@tsk/core';
import type { TSKClientStorage } from './storage.js';
import { TSK_HEADERS, TSK_PROTOCOL_VERSION } from './constants.js';

export interface TSKClientConfig {
  clientId: string;
  storage: TSKClientStorage;
  /** Optional: override the provisioned shared secret (usually loaded from storage) */
  sharedSecret?: string;
}

export class TSKClient {
  private payload: TSKProvisionPayload | null = null;
  private sharedSecret: string | null = null;
  private counters = new Map<string, number>();

  constructor(private config: TSKClientConfig) {}

  /**
   * Load the provision payload from storage.
   * Must call before making requests.
   */
  async init(): Promise<void> {
    this.payload = await this.config.storage.load(this.config.clientId);
    if (!this.payload) {
      throw new Error(`TSKClient: No provision payload found for clientId=${this.config.clientId}`);
    }
    if (this.config.sharedSecret) {
      this.sharedSecret = this.config.sharedSecret;
    } else {
      throw new Error('TSKClient: sharedSecret must be provided (loaded from secure storage)');
    }
    // Initialize HOTP counters
    for (const seg of this.payload.clientSegments) {
      if (seg.type === 'hotp') {
        this.counters.set(seg.segmentId, seg.initialCounter ?? 0);
      }
    }
  }

  /**
   * Generate the current TSK key and required headers.
   * The key is assembled from segment values + a checksum.
   * Positions are unknown to the client — the server maps them.
   *
   * CLIENT-SIDE KEY ASSEMBLY:
   * The client doesn't know positions, so it generates segment values and
   * sends them in a structured way. The server re-derives expected values
   * using its stored positions. We send one consolidated "key" that is a
   * concatenation of segment values in segmentId order (server knows this order).
   */
  generateHeaders(nowMs: number = Date.now()): Record<string, string> {
    if (!this.payload || !this.sharedSecret) {
      throw new Error('TSKClient: not initialized. Call init() first.');
    }

    // Generate segment values
    const values = generateClientSegmentValues(
      this.sharedSecret,
      this.payload.clientSegments,
      this.counters,
      nowMs,
    );

    // Advance HOTP counters
    for (const seg of this.payload.clientSegments) {
      if (seg.type === 'hotp') {
        const current = this.counters.get(seg.segmentId) ?? 0;
        this.counters.set(seg.segmentId, current + 1);
      }
    }

    // Build key: use segmentOrder for correct positional assembly (if available)
    const orderedSegmentIds = this.payload.segmentOrder ??
      this.payload.clientSegments.map(s => s.segmentId);
    const segmentParts = orderedSegmentIds.map(id => values.get(id) ?? '');
    const keyWithoutChecksum = segmentParts.join('');
    const checksum = hmacFn(this.sharedSecret, `checksum:${keyWithoutChecksum}`).slice(0, 8);
    const key = keyWithoutChecksum + checksum;

    return {
      [TSK_HEADERS.CLIENT_ID]: this.config.clientId,
      [TSK_HEADERS.KEY]: key,
      [TSK_HEADERS.VERSION]: TSK_PROTOCOL_VERSION,
    };
  }

  /**
   * Fetch wrapper that automatically adds TSK headers.
   */
  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    const tskHeaders = this.generateHeaders();
    const headers = new Headers(init.headers);
    for (const [k, v] of Object.entries(tskHeaders)) {
      headers.set(k, v);
    }
    return fetch(url, { ...init, headers });
  }
}
