/**
 * TSK Protocol — Cryptographic Primitives
 * Uses Node.js built-in cryptographic providers (no external dependencies).
 *
 * Security properties:
 * - HMAC-SHA256 with validated 256-bit hex key
 * - Node timingSafeEqual for equal-length value comparison
 * - All randomness from crypto.randomBytes
 * - Hex secret validation prevents silent key collapse to empty buffer
 */
import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';

// ─── Secret Validation ────────────────────────────────────────────────────────

/**
 * Validate that a string is a valid 256-bit hex-encoded secret.
 * Throws if the secret is invalid.
 *
 * SECURITY: Buffer.from(secret, 'hex') silently drops non-hex characters,
 * which would cause all clients with invalid secrets to share the same
 * (empty) HMAC key — a catastrophic key collapse vulnerability.
 * This validation prevents that silent failure.
 */
export function validateHexSecret(secret: string): void {
  if (typeof secret !== 'string') {
    throw new TypeError('TSK: sharedSecret must be a string');
  }
  if (secret.length !== 64) {
    throw new RangeError(
      `TSK: sharedSecret must be 64 hex chars (256 bits), got ${secret.length}`
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(secret)) {
    throw new TypeError(
      'TSK: sharedSecret contains non-hex characters — key would silently collapse to empty buffer'
    );
  }
}

// ─── HMAC-SHA256 ──────────────────────────────────────────────────────────────

/**
 * HMAC-SHA256: core primitive for all segment value derivation.
 * Returns base64url-encoded output (43 chars) for URL-safe key characters.
 *
 * SECURITY: secret is validated before use to prevent silent key collapse.
 */
export function hmac(secret: string, data: string): string {
  validateHexSecret(secret);
  return createHmac('sha256', Buffer.from(secret, 'hex'))
    .update(data, 'utf8')
    .digest('base64url');
}

/**
 * HMAC-SHA256 with a pre-decoded Buffer key (hot-path variant).
 * Caller must have validated the secret via validateHexSecret before decoding.
 */
export function hmacRaw(secretBuf: Buffer, data: string): string {
  return createHmac('sha256', secretBuf)
    .update(data, 'utf8')
    .digest('base64url');
}

/**
 * Decode a validated hex secret to a Buffer once, for use in hmacRaw hot-path calls.
 */
export function hexSecretToBuffer(secret: string): Buffer {
  validateHexSecret(secret);
  return Buffer.from(secret, 'hex');
}

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

/**
 * SHA-256 hash of input string, returns hex.
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// ─── Constant-Time Comparison ─────────────────────────────────────────────────

/**
 * Compare equal-length string content with Node's timingSafeEqual.
 *
 * SECURITY HARDENING vs original:
 * - Original returned false immediately on length mismatch, leaking whether
 *   lengths matched via timing side-channel.
 * - A dummy timingSafeEqual call is made on length mismatch, but callers must
 *   not treat JavaScript/runtime timing as proof that input length is hidden.
 *
 * Returns true only if both strings are identical.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    // Avoid skipping the primitive entirely. This is not a guarantee that the
    // surrounding JavaScript path hides input length.
    const dummy = Buffer.alloc(bufA.length);
    timingSafeEqual(bufA, dummy);
    return false;
  }

  return timingSafeEqual(bufA, bufB);
}

// ─── Randomness ───────────────────────────────────────────────────────────────

/**
 * Generate a random 256-bit hex-encoded shared secret.
 * Uses the active Node.js runtime cryptographic provider via crypto.randomBytes.
 */
export function generateSharedSecret(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Generate a short random segment ID with a given prefix.
 */
export function generateSegmentId(prefix = 'seg'): string {
  return `${prefix}_${randomBytes(4).toString('hex')}`;
}

/**
 * Generate a random client ID.
 * Uses 8 random bytes = 64 bits of entropy.
 */
export function generateClientId(): string {
  return `tsk_${randomBytes(8).toString('hex')}`;
}

/**
 * Generate a cryptographically secure random integer in [0, max).
 * Uses rejection sampling to eliminate modulo bias.
 */
export function secureRandomInt(max: number): number {
  if (max <= 0) throw new RangeError('max must be > 0');
  if (max === 1) return 0;
  // Rejection sampling: discard values in the biased tail
  const limit = 0x100000000 - (0x100000000 % max);
  let val: number;
  do {
    val = randomBytes(4).readUInt32BE(0);
  } while (val >= limit);
  return val % max;
}
