/**
 * TSK Protocol — Tumbler Map Generation
 *
 * Creates a randomized per-client tumbler map at provisioning time.
 * The map is stored SERVER-SIDE ONLY. The client only receives the segment types
 * and timing parameters (not the positions), which is the "structural secrecy" property.
 */

import { randomInt } from 'node:crypto';
import type { TumblerMap, SegmentConfig, TSKProvisionPayload, ClientSegmentConfig } from './types.js';
import { generateSharedSecret, generateSegmentId, generateClientId } from './crypto.js';
import { hmac } from './crypto.js';

export interface TumblerMapOptions {
  /** Total key length in characters (default: 52) */
  keyLength?: number;
  /** Min number of rotating segments (default: 2) */
  minTumblers?: number;
  /** Max number of rotating segments (default: 5) */
  maxTumblers?: number;
  /** Allowed TOTP window sizes in seconds */
  allowedWindows?: number[];
}

/**
 * Generate a new randomized tumbler map for a client.
 * The positions of segments are randomized — this is the secret structural layer.
 */
export function generateTumblerMap(
  options: TumblerMapOptions = {},
): TumblerMap {
  const keyLength = options.keyLength ?? 52;
  const minTumblers = options.minTumblers ?? 2;
  const maxTumblers = options.maxTumblers ?? 5;
  const allowedWindows = options.allowedWindows ?? [30, 60, 120, 300];

  const clientId = generateClientId();
  const sharedSecret = generateSharedSecret();

  // Decide how many rotating segments (between min and max)
  const numTumblers = minTumblers + randomInt(0, maxTumblers - minTumblers + 1);

  // Reserve last 8 chars for checksum
  const checksumLen = 8;
  const checksumStart = keyLength - checksumLen;

  // Divide remaining space into segments (at least 1 static ID segment at start)
  const usableLength = checksumStart;
  const positions = randomNonOverlappingSegments(usableLength, numTumblers + 1); // +1 for static ID

  const segments: SegmentConfig[] = positions.map((pos, i) => {
    const segId = generateSegmentId(i === 0 ? 'id' : 'seg');
    if (i === 0) {
      // First segment is always static (client ID anchor)
      return {
        segmentId: segId,
        position: pos,
        type: 'static' as const,
      };
    }
    // Randomly assign TOTP or HOTP
    const isTotp = randomInt(0, 10) > 2; // 70% TOTP, 30% HOTP (values 3-9 = true)
    const windowSec = allowedWindows[randomInt(0, allowedWindows.length)];
    return {
      segmentId: segId,
      position: pos,
      type: isTotp ? 'totp' as const : 'hotp' as const,
      windowSec: isTotp ? windowSec : undefined,
      counter: isTotp ? undefined : 0,
    };
  });

  return {
    clientId,
    sharedSecret,
    keyLength,
    segments,
    checksum: { position: [checksumStart, keyLength] },
    createdAt: Date.now(),
    version: '1',
  };
}

/**
 * Extract the client-facing portion of a tumbler map (positions omitted).
 * This is what gets delivered to the client at provisioning.
 */
export function toProvisionPayload(map: TumblerMap): TSKProvisionPayload {
  // Sort segments by position to get correct assembly order
  const sortedSegments = [...map.segments].sort((a, b) => a.position[0] - b.position[0]);

  const clientSegments: ClientSegmentConfig[] = map.segments.map(seg => {
    const cs: ClientSegmentConfig = {
      segmentId: seg.segmentId,
      type: seg.type,
      length: seg.position[1] - seg.position[0],  // segment length in chars
    };
    if (seg.type === 'totp') cs.windowSec = seg.windowSec;
    if (seg.type === 'hotp') cs.initialCounter = seg.counter ?? 0;
    return cs;
  });

  return {
    clientId: map.clientId,
    clientSegments,
    keyLength: map.keyLength,
    segmentOrder: sortedSegments.map(s => s.segmentId),  // segmentIds in position order
    createdAt: map.createdAt,
    version: '1',
  };
}

/**
 * Compute the checksum for a partially-assembled key.
 * Returns a string of exactly `checksumLen` characters.
 */
export function computeChecksum(sharedSecret: string, keyWithoutChecksum: string): string {
  const full = hmac(sharedSecret, `checksum:${keyWithoutChecksum}`);
  const checksumLen = 8;
  return full.slice(0, checksumLen);
}

/**
 * Generate N non-overlapping segments that together cover [0, totalLength).
 * Each segment gets a roughly equal slice but with random boundaries.
 */
function randomNonOverlappingSegments(
  totalLength: number,
  count: number,
): Array<[number, number]> {
  if (count <= 0 || totalLength < count) {
    throw new Error(`Cannot create ${count} segments in ${totalLength} chars`);
  }

  // Start with equal division, then jitter boundaries
  const baseSize = Math.floor(totalLength / count);
  const boundaries: number[] = [0];

  for (let i = 1; i < count; i++) {
    const ideal = i * baseSize;
    // Jitter ±25% of base size but keep at least 2 chars per segment
    const maxJitter = Math.floor(baseSize * 0.25);
    const jitter = randomInt(0, maxJitter * 2 + 1) - maxJitter;
    const boundary = Math.max(boundaries[i - 1] + 2, Math.min(totalLength - (count - i) * 2, ideal + jitter));
    boundaries.push(boundary);
  }
  boundaries.push(totalLength);

  // Shuffle boundaries (except 0 and end) to randomize which segment gets which slot
  const midBoundaries = boundaries.slice(1, -1);
  for (let i = midBoundaries.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1);
    [midBoundaries[i], midBoundaries[j]] = [midBoundaries[j], midBoundaries[i]];
  }
  // Re-sort to maintain valid non-overlapping ranges
  midBoundaries.sort((a, b) => a - b);
  const finalBoundaries = [0, ...midBoundaries, totalLength];

  return finalBoundaries
    .slice(0, -1)
    .map((start, i) => [start, finalBoundaries[i + 1]] as [number, number]);
}
