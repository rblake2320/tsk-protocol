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
}

/**
 * Verify a TSK request.
 * Pure function — no side effects except anomaly recording and HOTP counter updates.
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

  // 2. Protocol version
  if (versionRaw && versionRaw !== TSK_PROTOCOL_VERSION) {
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
  if (!result.ok && anomaly && result.segmentResults) {
    anomaly.record({
      clientId: clientIdRaw,
      timestamp: Date.now(),
      segmentResults: result.segmentResults,
      ipAddress,
    });
  }

  // 7. Advance HOTP counters on success — use CAS (consumeCounter) when available
  // to prevent replay under concurrent requests. Fall back to updateCounters.
  if (result.ok && result.counterUpdates && result.counterUpdates.size > 0) {
    if (store.consumeCounter) {
      for (const [segmentId, update] of result.counterUpdates) {
        // CAS: use matchedCounter as expectedCounter (the exact value that was matched
        // during validation). This correctly handles lookahead scenarios where the
        // matched counter may be > storedCounter (e.g., counter+3 matched with stored=0).
        const cas = await store.consumeCounter(clientIdRaw, segmentId, update.matchedCounter);
        if (!cas) {
          // Counter was already consumed by a concurrent request — treat as replay
          return { ok: false, error: 'TSK_HOTP_REPLAY_DETECTED', clientId: clientIdRaw };
        }
      }
    } else {
      // Fallback: build a plain Map<string, number> for updateCounters
      const plainUpdates = new Map<string, number>();
      for (const [segmentId, update] of result.counterUpdates) {
        plainUpdates.set(segmentId, update.newCounter);
      }
      await store.updateCounters(clientIdRaw, plainUpdates);
    }
  }

  if (!result.ok) {
    return { ok: false, error: result.error ?? 'TSK_VALIDATION_FAILED', clientId: clientIdRaw };
  }

  // 11. Update lifecycle tracking fields after successful validation
  const updatedMap = {
    ...map,
    requestCount: (map.requestCount ?? 0) + 1,
    lastUsedAt: Date.now(),
  };
  await store.set(clientIdRaw, updatedMap);

  return { ok: true, clientId: result.clientId };
}

function getHeader(req: TSKRequestData, name: string): string | undefined {
  const val = req.headers[name];
  if (Array.isArray(val)) return val[0];
  return val;
}
