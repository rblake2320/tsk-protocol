/**
 * TSK Protocol — Server-Side Key Validation
 *
 * Validates a submitted TSK key against the stored tumbler map.
 * Uses constant-time comparison throughout to prevent timing attacks.
 *
 * Security properties:
 * - TOTP segments: checked ±totpToleranceWindows (default ±1)
 * - HOTP segments: checked with lookahead (default +5), counter advanced on match
 * - Checksum: verified with constant-time compare
 * - Per-segment failure details exposed for anomaly engine (which segments failed
 *   tells the server whether this is clock drift vs. a stolen key being replayed)
 */

import type { TumblerMap, TSKValidationResult, TSKConfig } from './types.js';
import { DEFAULT_TSK_CONFIG } from './types.js';
import { constantTimeEqual } from './crypto.js';
import { deriveSegmentForWindow, deriveSegmentForCounter, deriveSegmentValue } from './segment.js';
import { computeChecksum } from './tumbler-map.js';

export interface ValidationContext {
  /** Full tumbler map (server-side only) */
  map: TumblerMap;
  /** Current server time in ms (injectable for testing) */
  nowMs?: number;
  config?: TSKConfig;
}

export interface ValidationResultWithCounterUpdates extends TSKValidationResult {
  /** HOTP counter updates to apply if validation succeeded */
  counterUpdates?: Map<string, number>;
}

/**
 * Validate a submitted TSK key string.
 */
export function validateTSKKey(
  providedKey: string,
  ctx: ValidationContext,
): ValidationResultWithCounterUpdates {
  const { map, nowMs = Date.now(), config = {} } = ctx;
  const cfg = { ...DEFAULT_TSK_CONFIG, ...config };

  // Guard: key length
  if (providedKey.length < cfg.minKeyLength || providedKey.length > cfg.maxKeyLength) {
    return { ok: false, error: 'KEY_LENGTH_MISMATCH' };
  }
  if (providedKey.length !== map.keyLength) {
    return { ok: false, error: 'KEY_LENGTH_MISMATCH' };
  }

  const segmentResults: { segmentId: string; valid: boolean }[] = [];
  const counterUpdates = new Map<string, number>();
  let allValid = true;

  // Validate each segment
  for (const seg of map.segments) {
    const [start, end] = seg.position;
    const providedSegValue = providedKey.slice(start, end);
    let segValid = false;

    if (seg.type === 'static') {
      const expected = deriveSegmentValue(map.sharedSecret, seg, nowMs);
      segValid = constantTimeEqual(providedSegValue, expected);

    } else if (seg.type === 'totp') {
      const windowSec = seg.windowSec ?? 60;
      const T = Math.floor(nowMs / 1000 / windowSec);
      // Check T-tolerance to T+tolerance
      for (let delta = -cfg.totpToleranceWindows; delta <= cfg.totpToleranceWindows; delta++) {
        const expected = deriveSegmentForWindow(map.sharedSecret, seg, T + delta);
        if (constantTimeEqual(providedSegValue, expected)) {
          segValid = true;
          break;
        }
      }

    } else {
      // hotp
      const storedCounter = seg.counter ?? 0;
      for (let lookahead = 0; lookahead <= cfg.hotpLookahead; lookahead++) {
        const expected = deriveSegmentForCounter(map.sharedSecret, seg, storedCounter + lookahead);
        if (constantTimeEqual(providedSegValue, expected)) {
          segValid = true;
          // Record counter advance (apply only if whole key validates)
          counterUpdates.set(seg.segmentId, storedCounter + lookahead + 1);
          break;
        }
      }
    }

    segmentResults.push({ segmentId: seg.segmentId, valid: segValid });
    if (!segValid) allValid = false;
  }

  // Validate checksum
  const [csStart, csEnd] = [map.checksum.position[0], map.checksum.position[1]];
  const providedChecksum = providedKey.slice(csStart, csEnd);
  const keyWithoutChecksum = providedKey.slice(0, csStart);
  const expectedChecksum = computeChecksum(map.sharedSecret, keyWithoutChecksum);
  const checksumValid = constantTimeEqual(providedChecksum, expectedChecksum);

  if (!checksumValid) {
    return {
      ok: false,
      error: 'CHECKSUM_INVALID',
      clientId: map.clientId,
      segmentResults,
    };
  }

  if (!allValid) {
    return {
      ok: false,
      error: 'VALIDATION_FAILED',
      clientId: map.clientId,
      segmentResults,
    };
  }

  return {
    ok: true,
    clientId: map.clientId,
    segmentResults,
    counterUpdates: counterUpdates.size > 0 ? counterUpdates : undefined,
  };
}
