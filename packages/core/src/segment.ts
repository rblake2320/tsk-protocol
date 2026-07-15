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
 *
 * SECURITY FIX: padOrTruncate uses hmacRaw with the original secret Buffer
 * instead of calling hmac(hmacOutput, ...) which would fail secret validation (HMAC output
 * is base64url, not a valid 64-char hex secret). The original implementation had a latent
 * bug where the recursive padding call used the HMAC output as the key — now fixed to always
 * use the original sharedSecret for all HMAC operations.
 */
import { hmac, hmacRaw, validateHexSecret } from './crypto.js';
import type { SegmentConfig } from './types.js';
import { assertUsableHOTPDerivationCounter } from './hotp-counter.js';

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
    assertUsableHOTPDerivationCounter(counter, `HOTP counter for ${seg.segmentId}`);
    derivationInput = `hotp:${seg.segmentId}:${counter}`;
  }
  const secretBuf = toSecretBuf(sharedSecret);
  const full = hmacRaw(secretBuf, derivationInput);
  return padOrTruncate(secretBuf, full, segLen);
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
  const secretBuf = toSecretBuf(sharedSecret);
  return padOrTruncate(secretBuf, hmacRaw(secretBuf, derivationInput), segLen);
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
  assertUsableHOTPDerivationCounter(counter, `HOTP counter for ${seg.segmentId}`);
  const segLen = seg.position[1] - seg.position[0];
  const derivationInput = `hotp:${seg.segmentId}:${counter}`;
  const secretBuf = toSecretBuf(sharedSecret);
  return padOrTruncate(secretBuf, hmacRaw(secretBuf, derivationInput), segLen);
}

/**
 * Convert a validated hex secret string to a Buffer.
 * Validates the secret first to prevent silent key collapse.
 */
function toSecretBuf(sharedSecret: string): Buffer {
  validateHexSecret(sharedSecret);
  return Buffer.from(sharedSecret, 'hex');
}

/**
 * Pad or truncate a base64url string to exactly `length` characters.
 * base64url uses [A-Za-z0-9_-] — safe for key strings.
 *
 * SECURITY FIX: Uses the original sharedSecret Buffer for all HMAC operations
 * in the padding loop, NOT the HMAC output (which is not a valid hex secret).
 * This ensures consistent key material across all padding rounds.
 */
function padOrTruncate(secretBuf: Buffer, s: string, length: number): string {
  if (s.length >= length) return s.slice(0, length);
  // Need more chars: chain HMAC rounds using the original secret
  // Each round: hmacRaw(originalSecret, "pad:<round>:<previousOutput>")
  // This is deterministic, uses the original key, and produces high-entropy output.
  let result = s;
  let round = 0;
  while (result.length < length) {
    result += hmacRaw(secretBuf, `pad:${round}:${result}`);
    round++;
  }
  return result.slice(0, length);
}
