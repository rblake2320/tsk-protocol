/**
 * TSK Protocol — Server Validation Middleware
 *
 * Validates an inbound TSK key from the X-TSK-Key header.
 * This is the primary server-side entry point.
 *
 * Header format:
 *   X-TSK-Client-ID: tsk_<clientId>
 *   X-TSK-Key: <assembled key string>
 *   X-TSK-Version: 1
 */

import { validateTSKKey, type TSKConfig } from '@tsk/core';
import type { TumblerMapStore } from './store.js';
import type { AnomalyEngine } from './anomaly.js';

export const TSK_HEADERS = {
  CLIENT_ID: 'x-tsk-client-id',
  KEY: 'x-tsk-key',
  VERSION: 'x-tsk-version',
} as const;

export const TSK_PROTOCOL_VERSION = '1';
export const TSK_MAX_KEY_HEADER_BYTES = 1024;
export const TSK_RESPONSE_HEADERS = {
  AUTHENTICATED: 'x-tsk-authenticated',
  ROTATION_REQUIRED: 'x-tsk-rotation-required',
  REQUESTS_REMAINING: 'x-tsk-requests-remaining',
  HOTP_COUNTERS_REMAINING: 'x-tsk-hotp-counters-remaining',
} as const;

export interface TSKRequestData {
  headers: Record<string, string | string[] | undefined>;
}

export interface TSKServerConfig {
  config?: TSKConfig;
  anomaly?: AnomalyEngine;
  ipAddress?: string;
}

export interface TSKVerifyResult {
  ok: boolean;
  clientId?: string;
  error?: string;
  /** True inside either the usage-cap or numeric-counter rotation window. */
  rotationRequired?: boolean;
  /** Successful validations remaining before the hard usage cap. */
  requestsRemaining?: number;
  /** Legal HOTP uses remaining for the segment closest to exhaustion. */
  hotpCountersRemaining?: number;
}

/** Response headers an HTTP adapter must add after successful verification. */
export function buildTSKResponseHeaders(result: TSKVerifyResult): Record<string, string> {
  if (!result.ok) return {};
  const headers: Record<string, string> = {
    [TSK_RESPONSE_HEADERS.AUTHENTICATED]: '1',
  };
  if (result.rotationRequired === true) {
    headers[TSK_RESPONSE_HEADERS.ROTATION_REQUIRED] = '1';
  }
  if (result.requestsRemaining !== undefined) {
    headers[TSK_RESPONSE_HEADERS.REQUESTS_REMAINING] = String(result.requestsRemaining);
  }
  if (result.hotpCountersRemaining !== undefined) {
    headers[TSK_RESPONSE_HEADERS.HOTP_COUNTERS_REMAINING] = String(result.hotpCountersRemaining);
  }
  return headers;
}

/**
 * Verify a TSK request.
 * The store atomically commits HOTP counters and lifecycle usage after validation.
 */
export async function verifyTSKRequest(
  req: TSKRequestData,
  store: TumblerMapStore,
  options: TSKServerConfig = {},
): Promise<TSKVerifyResult> {
  const { config, anomaly, ipAddress } = options;

  // 1. Check required headers
  const clientIdRaw = getHeader(req, TSK_HEADERS.CLIENT_ID);
  const keyRaw = getHeader(req, TSK_HEADERS.KEY);
  const versionRaw = getHeader(req, TSK_HEADERS.VERSION);

  if (!clientIdRaw || !keyRaw) {
    return { ok: false, error: 'TSK_HEADERS_MISSING' };
  }

  // 2. Protocol version (MED-07 FIX: Enforce version negotiation in wire format)
  if (!versionRaw) {
    return { ok: false, error: 'TSK_VERSION_MISSING' };
  }
  if (versionRaw !== TSK_PROTOCOL_VERSION) {
    return { ok: false, error: 'TSK_VERSION_UNSUPPORTED' };
  }

  // 3. Size guard (prevent oversized header DoS)
  if (keyRaw.length > TSK_MAX_KEY_HEADER_BYTES) {
    return { ok: false, error: 'TSK_KEY_TOO_LARGE' };
  }

  // 4. Look up tumbler map
  const map = await store.get(clientIdRaw);
  if (!map) {
    return { ok: false, error: 'TSK_CLIENT_NOT_FOUND' };
  }

  // 5. Lifecycle checks — before cryptographic validation to fail fast
  if (map.status === 'revoked') {
    return { ok: false, error: 'TSK_KEY_REVOKED', clientId: clientIdRaw };
  }
  if (map.status === 'expired') {
    return { ok: false, error: 'TSK_KEY_EXPIRED', clientId: clientIdRaw };
  }
  if (map.expiresAt !== undefined && Date.now() > map.expiresAt) {
    // Auto-transition to expired
    const updated = { ...map, status: 'expired' as const };
    await store.set(clientIdRaw, updated);
    return { ok: false, error: 'TSK_KEY_EXPIRED', clientId: clientIdRaw };
  }
  if (map.maxRequests && map.maxRequests > 0) {
    const count = map.requestCount ?? 0;
    if (count >= map.maxRequests) {
      // Auto-transition to expired
      const updated = { ...map, status: 'expired' as const };
      await store.set(clientIdRaw, updated);
      return { ok: false, error: 'TSK_KEY_USAGE_CAP_EXCEEDED', clientId: clientIdRaw };
    }
  }

  // 6. Validate key
  const result = validateTSKKey(keyRaw, { map, config });

  // 7. Record anomaly if failed
  if (!result.ok && anomaly) {
    anomaly.record({
      clientId: clientIdRaw,
      timestamp: Date.now(),
      segmentResults: result.segmentResults ?? [],
      failureKind: result.internalError === 'CHECKSUM_INVALID'
        ? 'checksum_invalid'
        : 'segment_validation_failed',
      ipAddress,
    });
  }

  if (!result.ok) {
    return { ok: false, error: result.error ?? 'TSK_VALIDATION_FAILED', clientId: clientIdRaw };
  }

  // 8. Atomically commit all counters and lifecycle usage. The commit repeats
  // lifecycle checks so concurrent requests cannot cross the hard cap.
  const committed = await store.commitValidation(clientIdRaw, {
    counterMatches: [...(result.counterUpdates ?? new Map())].map(
      ([segmentId, update]) => ({ segmentId, matchedCounter: update.matchedCounter }),
    ),
    usedAt: Date.now(),
  });
  if (!committed.ok) {
    return { ok: false, error: committed.error, clientId: clientIdRaw };
  }

  return {
    ok: true,
    clientId: result.clientId,
    rotationRequired: committed.rotationRequired,
    requestsRemaining: committed.requestsRemaining,
    hotpCountersRemaining: committed.hotpCountersRemaining,
  };
}

function getHeader(req: TSKRequestData, name: string): string | undefined {
  const val = req.headers[name];
  if (Array.isArray(val)) return val[0];
  return val;
}
