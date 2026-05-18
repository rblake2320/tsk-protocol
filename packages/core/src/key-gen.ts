/**
 * TSK Protocol — Key Generation
 *
 * Assembles the full TSK key string from a tumbler map + current time/counters.
 * This runs on the CLIENT side (uses ClientSegmentConfig — no position info).
 * Also runs on the SERVER side during validation (uses full TumblerMap — with positions).
 *
 * CLIENT ASSEMBLY CONTRACT:
 * The client receives a TSKProvisionPayload with clientSegments sorted in positional order.
 * Each ClientSegmentConfig includes segmentLength (not position). The client:
 *   1. Derives an HMAC value for each segment (raw 43-char base64url output)
 *   2. Truncates/pads each value to exactly segmentLength characters
 *   3. Concatenates in clientSegments order (which matches server's positional order)
 *   4. Appends a checksumLength-char HMAC checksum of the concatenated body
 *
 * The resulting key is byte-for-byte identical to the server's expected positional layout.
 * The client knows segment lengths but NOT start offsets — it cannot reconstruct positions.
 */

import type { TumblerMap, ClientSegmentConfig, TSKProvisionPayload } from './types.js';
import { deriveSegmentValue } from './segment.js';
import { hmac, hmacRaw, validateHexSecret } from './crypto.js';

/**
 * Generate a TSK key using the FULL tumbler map (server-side / test path).
 * Uses absolute positions from the map — not available to clients in production.
 */
export function generateKeyFromMap(map: TumblerMap, nowMs: number = Date.now()): string {
  const keyBuffer = new Array<string>(map.keyLength).fill('\x00');

  for (const seg of map.segments) {
    const value = deriveSegmentValue(map.sharedSecret, seg, nowMs);
    const [start, end] = seg.position;
    for (let i = 0; i < end - start; i++) {
      keyBuffer[start + i] = value[i] ?? 'A';
    }
  }

  // Compute and write checksum
  const withoutChecksum = keyBuffer.slice(0, map.checksum.position[0]).join('');
  const checksum = computeChecksumChars(map.sharedSecret, withoutChecksum,
    map.checksum.position[1] - map.checksum.position[0]);
  for (let i = 0; i < checksum.length; i++) {
    keyBuffer[map.checksum.position[0] + i] = checksum[i];
  }

  return keyBuffer.join('');
}

/**
 * Generate a TSK key from the CLIENT-SIDE provision payload.
 *
 * This is the production client path. The client only knows segment lengths
 * (not positions). It derives segment values, truncates/pads to the correct
 * length, concatenates in provisioned order, and appends the checksum.
 *
 * The resulting key is byte-for-byte identical to what the server expects.
 *
 * @param sharedSecret - 64-char hex-encoded 256-bit secret (from secure storage)
 * @param payload - Provision payload received from server at provisioning time
 * @param counters - Current HOTP counter values (keyed by segmentId)
 * @param nowMs - Current time in ms (injectable for testing)
 */
export function generateKeyFromClientPayload(
  sharedSecret: string,
  payload: TSKProvisionPayload,
  counters: Map<string, number>,
  nowMs: number = Date.now(),
): string {
  validateHexSecret(sharedSecret);
  const secretBuf = Buffer.from(sharedSecret, 'hex');

  const parts: string[] = [];

  for (const seg of payload.clientSegments) {
    // Derive the raw HMAC value for this segment
    let derivationInput: string;
    if (seg.type === 'static') {
      derivationInput = `static:${seg.segmentId}`;
    } else if (seg.type === 'totp') {
      const windowSec = seg.windowSec ?? 60;
      const T = Math.floor(nowMs / 1000 / windowSec);
      derivationInput = `totp:${seg.segmentId}:${T}`;
    } else {
      // hotp
      const counter = counters.get(seg.segmentId) ?? seg.initialCounter ?? 0;
      derivationInput = `hotp:${seg.segmentId}:${counter}`;
    }

    // Get raw HMAC output and truncate/pad to exactly segmentLength chars
    const raw = hmacRaw(secretBuf, derivationInput);
    const value = padOrTruncateClient(secretBuf, raw, seg.segmentLength);
    parts.push(value);
  }

  // Assemble body (all segments concatenated in positional order)
  const body = parts.join('');

  // Append checksum
  const checksum = computeChecksumChars(sharedSecret, body, payload.checksumLength);
  return body + checksum;
}

/**
 * Generate client segment values (raw, before length adjustment).
 * Used internally and for testing.
 *
 * @deprecated Use generateKeyFromClientPayload for full key assembly.
 */
export function generateClientSegmentValues(
  sharedSecret: string,
  clientSegments: ClientSegmentConfig[],
  counters: Map<string, number>,
  nowMs: number = Date.now(),
): Map<string, string> {
  const values = new Map<string, string>();

  for (const seg of clientSegments) {
    let derivationInput: string;

    if (seg.type === 'static') {
      derivationInput = `static:${seg.segmentId}`;
    } else if (seg.type === 'totp') {
      const windowSec = seg.windowSec ?? 60;
      const T = Math.floor(nowMs / 1000 / windowSec);
      derivationInput = `totp:${seg.segmentId}:${T}`;
    } else {
      // hotp
      const counter = counters.get(seg.segmentId) ?? seg.initialCounter ?? 0;
      derivationInput = `hotp:${seg.segmentId}:${counter}`;
    }

    values.set(seg.segmentId, hmac(sharedSecret, derivationInput));
  }

  return values;
}

/**
 * Compute checksum bytes of exact `len` chars using HMAC.
 */
function computeChecksumChars(sharedSecret: string, data: string, len: number): string {
  const full = hmac(sharedSecret, `checksum:${data}`);
  return full.slice(0, len);
}

/**
 * Pad or truncate a base64url string to exactly `length` characters.
 * Uses the original secret buffer for all HMAC padding rounds (not the output).
 * Mirrors the server-side padOrTruncate in segment.ts.
 */
function padOrTruncateClient(secretBuf: Buffer, s: string, length: number): string {
  if (s.length >= length) return s.slice(0, length);
  let result = s;
  let round = 0;
  while (result.length < length) {
    result += hmacRaw(secretBuf, `pad:${round}:${result}`);
    round++;
  }
  return result.slice(0, length);
}
