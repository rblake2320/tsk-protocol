/**
 * TSK Protocol — Key Generation
 *
 * Assembles the full TSK key string from a tumbler map + current time/counters.
 * This runs on the CLIENT side (uses ClientSegmentConfig — no position info).
 * Also runs on the SERVER side during validation (uses full TumblerMap — with positions).
 */

import type { TumblerMap, ClientSegmentConfig } from './types.js';
import { deriveSegmentValue } from './segment.js';
import { hmac } from './crypto.js';

/**
 * Generate a TSK key using the FULL tumbler map (server-side validation path,
 * or client if they somehow have the full map — not normal production flow).
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
 * Generate a TSK key using only the CLIENT-SIDE provision payload.
 * The client does NOT know positions — it only knows segment types/timing.
 * The client generates segment values and sends them in a structured payload,
 * not a single string. The server assembles the final key using its stored positions.
 *
 * This function returns the client-side segment values, keyed by segmentId.
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
