/**
 * TSK Protocol — Cryptographic Primitives
 * Uses Node.js built-in crypto (no external dependencies)
 */

import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';

/**
 * HMAC-SHA256: core primitive for all segment value derivation.
 * Returns base64url-encoded output for URL-safe key characters.
 */
export function hmac(secret: string, data: string): string {
  return createHmac('sha256', Buffer.from(secret, 'hex'))
    .update(data)
    .digest('base64url');
}

/**
 * SHA-256 hash of input string, returns hex.
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Constant-time string comparison.
 * Returns true only if both strings are equal without leaking timing info.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return timingSafeEqual(bufA, bufB);
}

/**
 * Generate a random 256-bit hex-encoded shared secret.
 */
export function generateSharedSecret(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Generate a short random segment ID.
 */
export function generateSegmentId(prefix = 'seg'): string {
  return `${prefix}_${randomBytes(4).toString('hex')}`;
}

/**
 * Generate a random client ID.
 */
export function generateClientId(): string {
  return `tsk_${randomBytes(8).toString('hex')}`;
}
