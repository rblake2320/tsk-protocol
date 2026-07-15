/**
 * TSK Protocol — Key Validation
 *
 * Security properties:
 * - Checksum-first validation (DoS guard: rejects ~99.99% of invalid keys with 1 HMAC op)
 * - timingSafeEqual-backed comparison for equal-length segment candidates
 * - HOTP counter exhaustion detection
 * - Type-safe segment result reporting (for anomaly engine)
 * - counterUpdates stores {newCounter, matchedCounter} for correct CAS in middleware
 *
 * TSK-06 FIX — Error Oracle:
 * All external-facing failure modes now return the generic error code 'INVALID_KEY'.
 * Previously, 'CHECKSUM_INVALID' vs 'VALIDATION_FAILED' allowed an attacker to
 * determine exactly where the checksum boundary was in the key structure.
 * Internal error codes (CHECKSUM_INVALID, VALIDATION_FAILED, etc.) are preserved
 * in the internalError field for server-side anomaly engine use ONLY — they must
 * never be returned to the client.
 */
import { constantTimeEqual } from './crypto.js';
import { DEFAULT_TSK_CONFIG } from './types.js';
import type { TumblerMap, TSKValidationResult, TSKConfig, SegmentType } from './types.js';
import { deriveSegmentForWindow, deriveSegmentForCounter, deriveSegmentValue } from './segment.js';
import { computeChecksum, CHECKSUM_LENGTH } from './tumbler-map.js';
import {
  TSK_MAX_HOTP_COUNTER,
  isValidHOTPStoredCounter,
} from './hotp-counter.js';

export interface ValidationContext {
  /** Full tumbler map (server-side only) */
  map: TumblerMap;
  /** Current server time in ms (injectable for testing) */
  nowMs?: number;
  config?: TSKConfig;
}

/**
 * HOTP counter update entry.
 * Stores both the new counter value AND the matched (pre-advance) counter
 * so the middleware CAS can use the correct expectedCounter.
 */
export interface HOTPCounterUpdate {
  /** The counter value to advance TO (matchedCounter + 1) */
  newCounter: number;
  /** The counter value that was matched — used as expectedCounter in CAS */
  matchedCounter: number;
}

export interface ValidationResultWithCounterUpdates extends TSKValidationResult {
  /**
   * HOTP counter updates to apply if validation succeeded.
   * Map of segmentId → HOTPCounterUpdate.
   * matchedCounter is the value that was matched (for CAS).
   * newCounter is the value to advance to.
   */
  counterUpdates?: Map<string, HOTPCounterUpdate>;
}

/**
 * Validate a submitted TSK key string.
 *
 * Validation order (rejects malformed/random input before segment work):
 * 1. Key length check (O(1))
 * 2. Checksum verification (1 HMAC op — rejects ~99.99% of invalid keys here)
 * 3. Per-segment validation (only reached by keys with valid checksums)
 */
export function validateTSKKey(
  providedKey: string,
  ctx: ValidationContext,
): ValidationResultWithCounterUpdates {
  const { map, nowMs = Date.now(), config = {} } = ctx;
  const cfg = { ...DEFAULT_TSK_CONFIG, ...config };

  if (!Number.isSafeInteger(cfg.hotpLookahead) || cfg.hotpLookahead < 0) {
    return {
      ok: false,
      error: 'INVALID_KEY',
      internalError: 'INTERNAL_ERROR',
      clientId: map.clientId,
    };
  }

  // Time is an authentication input. Reject non-finite values before window
  // arithmetic can turn them into non-finite derivation strings.
  if (!Number.isFinite(nowMs)) {
    return {
      ok: false,
      error: 'INVALID_KEY',
      internalError: 'INTERNAL_ERROR',
      clientId: map.clientId,
    };
  }

  // ── Step 0: Map structural integrity guards ─────────────────────────────────
  // Reject degenerate maps that would allow trivial bypass:
  // - Empty segment array: any key with correct checksum would pass with no segment checks
  // - Zero-length segments: provide no authentication value and allow trivial matching
  if (!map.segments || map.segments.length === 0) {
    return { ok: false, error: 'MAP_INVALID_NO_SEGMENTS' };
  }
  if (!map.segments.some(segment => segment.type === 'hotp')) {
    return { ok: false, error: 'MAP_INVALID_NO_HOTP' };
  }
  for (const seg of map.segments) {
    const segLen = seg.position[1] - seg.position[0];
    if (segLen <= 0) {
      return { ok: false, error: 'MAP_INVALID_ZERO_LENGTH_SEGMENT' };
    }
  }

  // ── Step 1: Key length check (O(1), no crypto) ────────────────────────────
  if (providedKey.length < cfg.minKeyLength || providedKey.length > cfg.maxKeyLength) {
    return { ok: false, error: 'KEY_LENGTH_MISMATCH' };
  }
  if (providedKey.length !== map.keyLength) {
    return { ok: false, error: 'KEY_LENGTH_MISMATCH' };
  }

  // ── Step 2: Checksum-first validation (DoS guard) ─────────────────────────
  // Verify checksum BEFORE iterating segments. This rejects the vast majority
  // of invalid/brute-force keys with a single HMAC operation, preventing
  // attackers from forcing expensive per-segment validation on every request.
  const [csStart, csEnd] = [map.checksum.position[0], map.checksum.position[1]];
  const providedChecksum = providedKey.slice(csStart, csEnd);
  const keyWithoutChecksum = providedKey.slice(0, csStart);
  const expectedChecksum = computeChecksum(map.sharedSecret, keyWithoutChecksum);
  if (!constantTimeEqual(providedChecksum, expectedChecksum)) {
    // TSK-06 FIX: Return generic INVALID_KEY externally.
    // internalError is for server-side anomaly engine only — never send to client.
    return {
      ok: false,
      error: 'INVALID_KEY',
      internalError: 'CHECKSUM_INVALID',
      clientId: map.clientId,
    };
  }

  // ── Step 3: Per-segment validation ────────────────────────────────────────
  // Only reached by keys that passed the checksum. Segment results are included
  // for anomaly engine analysis (with type info for type-safe detection).
  const segmentResults: { segmentId: string; type: SegmentType; valid: boolean }[] = [];
  const counterUpdates = new Map<string, HOTPCounterUpdate>();
  let allValid = true;

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
      // Check T-tolerance to T+tolerance with equal-length timingSafeEqual calls.
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
      if (!isValidHOTPStoredCounter(storedCounter)) {
        return {
          ok: false,
          error: 'INVALID_KEY',
          internalError: 'HOTP_COUNTER_INVALID',
          clientId: map.clientId,
          segmentResults,
        };
      }
      // MAX is the persisted exhausted sentinel; it is never a derivation input.
      if (storedCounter >= TSK_MAX_HOTP_COUNTER) {
        // TSK-06 FIX: Generic external error; internal code for anomaly engine.
        return {
          ok: false,
          error: 'INVALID_KEY',
          internalError: 'HOTP_COUNTER_EXHAUSTED',
          clientId: map.clientId,
          segmentResults,
        };
      }
      const maximumLookahead = Math.min(
        cfg.hotpLookahead,
        TSK_MAX_HOTP_COUNTER - 1 - storedCounter,
      );
      for (let lookahead = 0; lookahead <= maximumLookahead; lookahead++) {
        const matchedCounter = storedCounter + lookahead;
        const expected = deriveSegmentForCounter(map.sharedSecret, seg, matchedCounter);
        if (constantTimeEqual(providedSegValue, expected)) {
          segValid = true;
          // Store both matchedCounter (for CAS expectedCounter) and newCounter (to advance to)
          counterUpdates.set(seg.segmentId, {
            matchedCounter,
            newCounter: matchedCounter + 1,
          });
          break;
        }
      }
    }

    segmentResults.push({ segmentId: seg.segmentId, type: seg.type, valid: segValid });
    if (!segValid) allValid = false;
  }

  if (!allValid) {
    // TSK-06 FIX: Generic external error; internal code for anomaly engine.
    return {
      ok: false,
      error: 'INVALID_KEY',
      internalError: 'VALIDATION_FAILED',
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
