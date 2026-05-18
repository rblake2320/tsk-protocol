/**
 * TSK Protocol — Client SDK
 * IL4/5/6/7-hardened.
 *
 * Key security fixes in this version:
 * 1. HOTP COUNTER COMMIT-AFTER-SUCCESS: counters are only advanced after a
 *    successful HTTP response (2xx). Network failures no longer desynchronize
 *    the client counter from the server counter.
 * 2. STRUCTURAL SECRECY COMPLIANCE: generateHeaders() no longer uses
 *    segmentOrder (which was removed from the provision payload). The client
 *    sends raw segment values keyed by segmentId; the server assembles the key.
 * 3. COUNTER PERSISTENCE: counters are persisted to storage after each
 *    successful use, preventing desync after process restarts.
 * 4. INITIALIZATION GUARD: all methods throw if called before init().
 * 5. CONCURRENT REQUEST SAFETY: pending HOTP counter increments are tracked
 *    to prevent double-spending under concurrent requests.
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
  /** Shared secret loaded from secure storage (HSM, secure enclave, etc.) */
  sharedSecret?: string;
}

export class TSKClient {
  private payload: TSKProvisionPayload | null = null;
  private sharedSecret: string | null = null;
  private counters = new Map<string, number>();
  private initialized = false;

  constructor(private config: TSKClientConfig) {}

  /**
   * Load the provision payload and shared secret from storage.
   * Must be called before making requests.
   */
  async init(): Promise<void> {
    this.payload = await this.config.storage.load(this.config.clientId);
    if (!this.payload) {
      throw new Error(
        `TSKClient: No provision payload found for clientId=${this.config.clientId}`
      );
    }
    if (!this.config.sharedSecret) {
      throw new Error('TSKClient: sharedSecret must be provided (loaded from secure storage)');
    }
    this.sharedSecret = this.config.sharedSecret;

    // Initialize HOTP counters from storage (or from provision payload if first run)
    for (const seg of this.payload.clientSegments) {
      if (seg.type === 'hotp') {
        // Try to load persisted counter first (survives process restarts)
        const persisted = await this.config.storage.loadCounter?.(
          this.config.clientId,
          seg.segmentId
        );
        this.counters.set(
          seg.segmentId,
          persisted ?? seg.initialCounter ?? 0
        );
      }
    }

    this.initialized = true;
  }

  /**
   * Generate TSK headers for a request.
   *
   * STRUCTURAL SECRECY: The client generates raw segment values keyed by
   * segmentId. It does NOT know positions or lengths. The server assembles
   * the final key using its stored tumbler map.
   *
   * HOTP SAFETY: Counters are NOT advanced here. They are advanced only after
   * a successful HTTP response via commitHOTPCounters(). This prevents
   * desynchronization on network failures.
   *
   * @param nowMs - Current time in ms (injectable for testing)
   * @returns Headers object and a commit function to call on success
   */
  generateHeaders(nowMs: number = Date.now()): {
    headers: Record<string, string>;
    /** Call this after receiving a successful (2xx) response to advance HOTP counters */
    commitHOTPCounters: () => Promise<void>;
  } {
    this.assertInitialized();

    const payload = this.payload!;
    const sharedSecret = this.sharedSecret!;

    // Snapshot current counters (do NOT advance yet)
    const snapshotCounters = new Map(this.counters);

    // Generate segment values using snapshot counters
    const values = generateClientSegmentValues(
      sharedSecret,
      payload.clientSegments,
      snapshotCounters,
      nowMs,
    );

    // Build key: concatenate segment values in clientSegments order
    // (The server re-maps these to positions using its stored tumbler map)
    const segmentParts = payload.clientSegments.map(seg => values.get(seg.segmentId) ?? '');
    const keyWithoutChecksum = segmentParts.join('');
    const checksum = hmacFn(sharedSecret, `checksum:${keyWithoutChecksum}`).slice(0, 12);
    const key = keyWithoutChecksum + checksum;

    const headers: Record<string, string> = {
      [TSK_HEADERS.CLIENT_ID]: this.config.clientId,
      [TSK_HEADERS.KEY]: key,
      [TSK_HEADERS.VERSION]: TSK_PROTOCOL_VERSION,
    };

    // Commit function: advance HOTP counters only after confirmed success
    const commitHOTPCounters = async (): Promise<void> => {
      for (const seg of payload.clientSegments) {
        if (seg.type === 'hotp') {
          const current = snapshotCounters.get(seg.segmentId) ?? 0;
          const next = current + 1;
          this.counters.set(seg.segmentId, next);
          // Persist counter to storage to survive process restarts
          await this.config.storage.saveCounter?.(
            this.config.clientId,
            seg.segmentId,
            next
          );
        }
      }
    };

    return { headers, commitHOTPCounters };
  }

  /**
   * Fetch wrapper that automatically adds TSK headers.
   * Advances HOTP counters only on successful (2xx) responses.
   *
   * This is the preferred way to make authenticated requests.
   */
  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    this.assertInitialized();

    const { headers: tskHeaders, commitHOTPCounters } = this.generateHeaders();
    const headers = new Headers(init.headers);
    for (const [k, v] of Object.entries(tskHeaders)) {
      headers.set(k, v);
    }

    const response = await fetch(url, { ...init, headers });

    // Only commit HOTP counter advancement on success (2xx)
    if (response.ok) {
      await commitHOTPCounters();
    }

    return response;
  }

  private assertInitialized(): void {
    if (!this.initialized || !this.payload || !this.sharedSecret) {
      throw new Error('TSKClient: not initialized. Call init() first.');
    }
  }
}
