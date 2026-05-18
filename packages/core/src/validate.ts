/**
 * TSK Protocol — Key Validation (IL4/5/6/7 Hardened)
 *
 * Security properties:
 * - Checksum-first validation (DoS guard: rejects ~99.99% of invalid keys with 1 HMAC op)
 * - Constant-time comparison for all segment values (timing oracle prevention)
 * - HOTP counter exhaustion detection
 * - Type-safe segment result reporting (for anomaly engine)
 * - counterUpdates stores {newCounter, matchedCounter} for correct CAS in middleware
 */
import { constantTimeEqual } from './crypto.js';
import { DEFAULT_TSK_CONFIG } from './types.js';
import type { TumblerMap, TSKValidationResult, TSKConfig, SegmentType } from './types.js';
import { deriveSegmentForWindow, deriveSegmentForCounter, deriveSegmentValue } from './segment.js';
import { computeChecksum, CHECKSUM_LENGTH } from './tumbler-map.js';

/** Maximum safe HOTP counter value (2^31 - 1). Counters beyond this are exhausted. */
const MAX_HOTP_COUNTER = 2_147_483_647;

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
 * Validation order (optimized for DoS resistance):
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

  // ── Step 0: Map structural integrity guards ─────────────────────────────────
  // Reject degenerate maps that would allow trivial bypass:
  // - Empty segment array: any key with correct checksum would pass with no segment checks
  // - Zero-length segments: provide no authentication value and allow trivial matching
  if (!map.segments || map.segments.length === 0) {
    return { ok: false, error: 'MAP_INVALID_NO_SEGMENTS' };
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
    return {
      ok: false,
      error: 'CHECKSUM_INVALID',
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
      // Check T-tolerance to T+tolerance (constant-time for each window)
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
      // Check for counter exhaustion before lookahead
      if (storedCounter > MAX_HOTP_COUNTER) {
        return {
          ok: false,
          error: 'HOTP_COUNTER_EXHAUSTED',
          clientId: map.clientId,
          segmentResults,
        };
      }
      for (let lookahead = 0; lookahead <= cfg.hotpLookahead; lookahead++) {
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
