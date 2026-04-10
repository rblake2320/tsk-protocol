/**
 * TSK Protocol — Segment Value Generation
 *
 * Each segment in the tumbler map derives its value from HMAC(sharedSecret, derivationInput).
 * The derivation input encodes the segment type and its temporal/counter factor.
 *
 * Static:  derivationInput = "static:<segmentId>"         (never changes)
 * TOTP:    derivationInput = "totp:<segmentId>:<T>"        (T = floor(unixMs/1000 / windowSec))
 * HOTP:    derivationInput = "hotp:<segmentId>:<counter>"  (counter increments per use)
 *
 * The segment value is a slice of the HMAC output, sized to fill the segment's position range.
 */

import { hmac } from './crypto.js';
import type { SegmentConfig } from './types.js';

/**
 * Derive the current segment value for a given config, at the given timestamp.
 * For TOTP segments, pass the current time in ms. For HOTP, counter is in the config.
 */
export function deriveSegmentValue(
  sharedSecret: string,
  seg: SegmentConfig,
  nowMs: number = Date.now(),
): string {
  const segLen = seg.position[1] - seg.position[0];
  let derivationInput: string;

  if (seg.type === 'static') {
    derivationInput = `static:${seg.segmentId}`;
  } else if (seg.type === 'totp') {
    const windowSec = seg.windowSec ?? 60;
    const T = Math.floor(nowMs / 1000 / windowSec);
    derivationInput = `totp:${seg.segmentId}:${T}`;
  } else {
    // hotp
    const counter = seg.counter ?? 0;
    derivationInput = `hotp:${seg.segmentId}:${counter}`;
  }

  const full = hmac(sharedSecret, derivationInput);
  // Wrap around if segment is longer than one HMAC output by hashing again
  return padOrTruncate(full, segLen);
}

/**
 * Derive TOTP segment value for a specific time window T (T = floor(unix/windowSec)).
 * Used by server to check ±tolerance windows.
 */
export function deriveSegmentForWindow(
  sharedSecret: string,
  seg: SegmentConfig,
  T: number,
): string {
  const segLen = seg.position[1] - seg.position[0];
  const derivationInput = `totp:${seg.segmentId}:${T}`;
  return padOrTruncate(hmac(sharedSecret, derivationInput), segLen);
}

/**
 * Derive HOTP segment value for a specific counter value.
 * Used by server lookahead check.
 */
export function deriveSegmentForCounter(
  sharedSecret: string,
  seg: SegmentConfig,
  counter: number,
): string {
  const segLen = seg.position[1] - seg.position[0];
  const derivationInput = `hotp:${seg.segmentId}:${counter}`;
  return padOrTruncate(hmac(sharedSecret, derivationInput), segLen);
}

/**
 * Pad or truncate a base64url string to exactly `length` characters.
 * base64url uses [A-Za-z0-9_-] — safe for key strings.
 */
function padOrTruncate(s: string, length: number): string {
  if (s.length >= length) return s.slice(0, length);
  // Need more chars: repeat hash
  let result = s;
  while (result.length < length) {
    result += hmac(s, result);
  }
  return result.slice(0, length);
}
