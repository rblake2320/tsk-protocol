/**
 * TSK Protocol — Client SDK
 *
 * Key security properties in this version:
 * 1. CORRECT KEY ASSEMBLY: generateHeaders() uses generateKeyFromClientPayload()
 *    which truncates/pads each segment value to its provisioned segmentLength before
 *    concatenation. This produces a key byte-for-byte identical to the server's
 *    positional layout.
 * 2. HONEST LAYOUT MODEL: ordered lengths reveal cumulative boundaries;
 *    security does not depend on hiding them from the provisioned client.
 * 3. HOTP COUNTER COMMIT-AFTER-AUTH: counters advance only when the server
 *    returns X-TSK-Authenticated: 1, independent of application status.
 * 4. COUNTER PERSISTENCE: counters are persisted to storage after each
 *    successful use, preventing desync after process restarts.
 * 5. INITIALIZATION GUARD: all methods throw if called before init().
 */
import {
  assertUsableHOTPDerivationCounter,
  assertValidHOTPStoredCounter,
  generateKeyFromClientPayload,
  type TSKProvisionPayload,
} from '@tsk/core';
import type { TSKClientStorage } from './storage.js';
import { TSK_HEADERS, TSK_PROTOCOL_VERSION, TSK_RESPONSE_HEADERS } from './constants.js';

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
        const persisted = await this.config.storage.loadCounter(
          this.config.clientId,
          seg.segmentId
        );
        const counter = persisted ?? seg.initialCounter ?? 0;
        assertValidHOTPStoredCounter(counter, `HOTP counter for ${seg.segmentId}`);
        this.counters.set(seg.segmentId, counter);
      }
    }

    this.initialized = true;
  }

  /**
   * Generate TSK headers for a request.
   *
   * KEY ASSEMBLY: Uses generateKeyFromClientPayload() which:
   *   1. Derives HMAC values for each segment using the shared secret
   *   2. Truncates/pads each value to its provisioned segmentLength
   *   3. Concatenates in positional order (matching server layout)
   *   4. Appends checksumLength-char HMAC checksum
   *
   * HOTP SAFETY: Counters are NOT advanced here. They are advanced only after
   * an authenticated response via commitHOTPCounters().
   *
   * @param nowMs - Current time in ms (injectable for testing)
   * @returns Headers object and a commit function to call on success
   */
  generateHeaders(nowMs: number = Date.now()): {
    headers: Record<string, string>;
    /** Call only after the server explicitly confirms TSK authentication. */
    commitHOTPCounters: () => Promise<void>;
  } {
    this.assertInitialized();

    const payload = this.payload!;
    const sharedSecret = this.sharedSecret!;

    // Snapshot current counters (do NOT advance yet — commit-after-success pattern)
    const snapshotCounters = new Map(this.counters);
    for (const seg of payload.clientSegments) {
      if (seg.type !== 'hotp') continue;
      assertUsableHOTPDerivationCounter(
        snapshotCounters.get(seg.segmentId) ?? seg.initialCounter ?? 0,
        `HOTP counter for ${seg.segmentId}`,
      );
    }

    // Generate the full key using the client payload (with segmentLength per segment)
    const key = generateKeyFromClientPayload(
      sharedSecret,
      payload,
      snapshotCounters,
      nowMs,
    );

    const headers: Record<string, string> = {
      [TSK_HEADERS.CLIENT_ID]: this.config.clientId,
      [TSK_HEADERS.KEY]: key,
      [TSK_HEADERS.VERSION]: TSK_PROTOCOL_VERSION,
    };

    // Commit function: advance HOTP counters only after confirmed success
    const commitHOTPCounters = async (): Promise<void> => {
      const nextCounters = new Map<string, number>();
      for (const seg of payload.clientSegments) {
        if (seg.type === 'hotp') {
          const current = snapshotCounters.get(seg.segmentId) ?? 0;
          assertUsableHOTPDerivationCounter(current, `HOTP counter for ${seg.segmentId}`);
          const next = current + 1;
          assertValidHOTPStoredCounter(next, `next HOTP counter for ${seg.segmentId}`);
          nextCounters.set(seg.segmentId, next);
        }
      }
      await this.config.storage.saveCounters(this.config.clientId, nextCounters);
      for (const [segmentId, counter] of nextCounters) this.counters.set(segmentId, counter);
    };

    return { headers, commitHOTPCounters };
  }

  /**
   * Fetch wrapper that automatically adds TSK headers.
   * Advances HOTP counters only when the server explicitly confirms that TSK
   * authentication was accepted. HTTP adapters must add the headers returned
   * by buildTSKResponseHeaders() even when downstream application work fails.
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

    if (response.headers.get(TSK_RESPONSE_HEADERS.AUTHENTICATED) === '1') {
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
