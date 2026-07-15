/**
 * TSK Protocol — Tumbler Map Generation & Provision Payload
 *
 * Key security fixes in this version:
 * 1. CLIENT CONTRACT ACCURACY: ordered segment lengths reveal the cumulative
 *    boundaries and are not treated as a secret or authentication factor.
 *    The client sends raw segment values; the server assembles the key.
 * 2. CHECKSUM LENGTH: upgraded from 8 chars (48 bits) to 12 chars (72 bits).
 * 3. INPUT VALIDATION: keyLength, minTumblers, maxTumblers, windowSec all
 *    validated against safe bounds before map generation.
 * 4. SECURE RANDOMNESS: uses secureRandomInt() with rejection sampling.
 * 5. MINIMUM SEGMENT LENGTH: enforced at 8 chars (48 bits entropy per segment).
 */
import {
  hmac,
  generateClientId,
  generateSharedSecret,
  generateSegmentId,
  secureRandomInt,
} from './crypto.js';
import { emitKeyGenerationCapture } from './runtime-capture.js';
import type { KeyGenerationCaptureOptions } from './runtime-capture.js';
import type {
  TumblerMap,
  SegmentConfig,
  TSKProvisionPayload,
  ClientSegmentConfig,
} from './types.js';

// ─── Constants ────────────────────────────────────────────────────────────────

/** Checksum length in base64url chars. 12 chars carry 72 bits. */
export const CHECKSUM_LENGTH = 12;

/** Minimum segment length in chars. 8 chars = 48 bits of HMAC output per segment. */
export const MIN_SEGMENT_LENGTH = 8;

/** Minimum key length: at least 1 segment (8 chars) + checksum (12 chars) = 20 chars. */
export const MIN_KEY_LENGTH = 20;

/** Maximum key length: 512 chars (well within HTTP header limits). */
export const MAX_KEY_LENGTH = 512;

/** Minimum number of rotating (non-static) tumblers. */
export const MIN_TUMBLERS = 1;

/** Maximum number of rotating tumblers. */
export const MAX_TUMBLERS = 8;

/** Allowed TOTP window sizes (seconds). Matches RFC 6238 common values. */
export const ALLOWED_WINDOWS = [30, 60, 120, 300] as const;

/** Minimum TOTP window size (seconds). */
export const MIN_WINDOW_SEC = 30;

/** Maximum TOTP window size (seconds). */
export const MAX_WINDOW_SEC = 300;

// ─── Options ──────────────────────────────────────────────────────────────────

export interface TumblerMapOptions {
  /** Total key length in characters (default: 64, min: 20, max: 512) */
  keyLength?: number;
  /** Minimum number of rotating segments (default: 2, min: 1) */
  minTumblers?: number;
  /** Maximum number of rotating segments (default: 5, max: 8) */
  maxTumblers?: number;
  /** Allowed TOTP window sizes in seconds (default: [30, 60, 120, 300]) */
  allowedWindows?: number[];
}

// ─── Input Validation ─────────────────────────────────────────────────────────

function validateOptions(options: TumblerMapOptions): Required<TumblerMapOptions> {
  const keyLength = options.keyLength ?? 64;
  const minTumblers = options.minTumblers ?? 2;
  const maxTumblers = options.maxTumblers ?? 5;
  const allowedWindows = options.allowedWindows ?? [...ALLOWED_WINDOWS];

  if (!Number.isInteger(keyLength) || keyLength < MIN_KEY_LENGTH || keyLength > MAX_KEY_LENGTH) {
    throw new RangeError(
      `TSK: keyLength must be an integer in [${MIN_KEY_LENGTH}, ${MAX_KEY_LENGTH}], got ${keyLength}`
    );
  }
  if (!Number.isInteger(minTumblers) || minTumblers < MIN_TUMBLERS) {
    throw new RangeError(`TSK: minTumblers must be >= ${MIN_TUMBLERS}, got ${minTumblers}`);
  }
  if (!Number.isInteger(maxTumblers) || maxTumblers > MAX_TUMBLERS) {
    throw new RangeError(`TSK: maxTumblers must be <= ${MAX_TUMBLERS}, got ${maxTumblers}`);
  }
  if (minTumblers > maxTumblers) {
    throw new RangeError(
      `TSK: minTumblers (${minTumblers}) must be <= maxTumblers (${maxTumblers})`
    );
  }
  if (!Array.isArray(allowedWindows) || allowedWindows.length === 0) {
    throw new RangeError('TSK: allowedWindows must be a non-empty array');
  }
  for (const w of allowedWindows) {
    if (!Number.isInteger(w) || w < MIN_WINDOW_SEC || w > MAX_WINDOW_SEC) {
      throw new RangeError(
        `TSK: allowedWindows values must be integers in [${MIN_WINDOW_SEC}, ${MAX_WINDOW_SEC}], got ${w}`
      );
    }
  }

  // Verify enough space for all segments + checksum
  const numTotalSegments = maxTumblers + 1; // +1 for static anchor
  const minRequired = numTotalSegments * MIN_SEGMENT_LENGTH + CHECKSUM_LENGTH;
  if (keyLength < minRequired) {
    throw new RangeError(
      `TSK: keyLength ${keyLength} is too small for ${numTotalSegments} segments ` +
      `(min ${MIN_SEGMENT_LENGTH} chars each) + ${CHECKSUM_LENGTH}-char checksum. ` +
      `Need at least ${minRequired} chars.`
    );
  }

  return { keyLength, minTumblers, maxTumblers, allowedWindows };
}

// ─── Map Generation ───────────────────────────────────────────────────────────

/**
 * Generate a new randomized tumbler map for a client.
 *
 * Segment boundaries are randomized per client. Security does not depend on
 * hiding those boundaries from the provisioned client.
 */
export function generateTumblerMap(
  options: TumblerMapOptions = {},
  captureOptions: KeyGenerationCaptureOptions = {},
): TumblerMap {
  const { keyLength, minTumblers, maxTumblers, allowedWindows } = validateOptions(options);

  const clientId = generateClientId();
  const sharedSecret = generateSharedSecret();

  // Decide how many rotating segments (between min and max, inclusive)
  const numTumblers = minTumblers + secureRandomInt(maxTumblers - minTumblers + 1);
  const requiredHotpIndex = 1 + secureRandomInt(numTumblers);

  // Reserve last CHECKSUM_LENGTH chars for checksum
  const checksumStart = keyLength - CHECKSUM_LENGTH;

  // Divide remaining space into (numTumblers + 1) segments (+1 for static ID anchor)
  const numSegments = numTumblers + 1;
  const positions = randomNonOverlappingSegments(checksumStart, numSegments);

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

    // Guarantee at least one counter-based segment so a generated credential
    // cannot be replayed repeatedly inside a time window.
    const isTotp = i !== requiredHotpIndex && secureRandomInt(10) >= 3;
    const windowSec = allowedWindows[secureRandomInt(allowedWindows.length)];

    return {
      segmentId: segId,
      position: pos,
      type: isTotp ? 'totp' as const : 'hotp' as const,
      windowSec: isTotp ? windowSec : undefined,
      counter: isTotp ? undefined : 0,
    };
  });

  const map: TumblerMap = {
    clientId,
    sharedSecret,
    keyLength,
    segments,
    checksum: { position: [checksumStart, keyLength] },
    createdAt: Date.now(),
    version: '1',
  };
  emitKeyGenerationCapture({
    protocol: 'tsk',
    packageName: '@tsk/core',
    event: 'tsk.tumbler_map.generated',
    clientId,
    algorithm: 'HMAC-SHA-256',
    runtime: captureOptions.runtimeMetadata,
    details: {
      keyLength,
      segmentCount: segments.length,
      checksumLength: CHECKSUM_LENGTH,
      ...captureOptions.captureDetails,
    },
  });
  return map;
}

// ─── Provision Payload ────────────────────────────────────────────────────────

/**
 * Extract the client-facing portion of a tumbler map.
 *
 * CLIENT CONTRACT:
 * - Absolute offsets are omitted because they are redundant on the client.
 * - segmentLength is included so the client can truncate/pad its HMAC output.
 * - Segments are emitted in positional order (sorted by position[0]). The client
 *   concatenates in this order, producing a key that is byte-for-byte identical to the
 *   server's positional layout. Cumulative lengths reveal the boundaries.
 *
 * SECURITY ANALYSIS:
 * An attacker who intercepts the provision payload learns:
 *   - Segment count, types, and sizes (in positional order)
 *   - Total key length and checksum length
 * Provisioning necessarily transfers the shared secret through a protected
 * deployment channel. It must subsequently remain in approved secret storage.
 */
export function toProvisionPayload(map: TumblerMap): TSKProvisionPayload {
  // Sort segments by position[0] so client concatenation order matches server layout
  const sortedSegments = [...map.segments].sort((a, b) => a.position[0] - b.position[0]);

  const clientSegments: ClientSegmentConfig[] = sortedSegments.map(seg => {
    const segmentLength = seg.position[1] - seg.position[0];
    const cs: ClientSegmentConfig = {
      segmentId: seg.segmentId,
      type: seg.type,
      segmentLength,
      // Absolute offset is redundant because ordered lengths define boundaries.
    };
    if (seg.type === 'totp') cs.windowSec = seg.windowSec;
    if (seg.type === 'hotp') cs.initialCounter = seg.counter ?? 0;
    return cs;
  });

  return {
    clientId: map.clientId,
    clientSegments,
    keyLength: map.keyLength,
    checksumLength: CHECKSUM_LENGTH,
    createdAt: map.createdAt,
    version: '1',
  };
}

// ─── Checksum ─────────────────────────────────────────────────────────────────

/**
 * Compute the checksum for a partially-assembled key.
 * Returns exactly CHECKSUM_LENGTH (12) base64url characters = 72 bits.
 *
 * The checksum is a truncated integrity tag, not a digital signature.
 */
export function computeChecksum(sharedSecret: string, keyWithoutChecksum: string): string {
  const full = hmac(sharedSecret, `checksum:${keyWithoutChecksum}`);
  return full.slice(0, CHECKSUM_LENGTH);
}

// ─── Segment Position Generation ──────────────────────────────────────────────

/**
 * Generate N non-overlapping segments that together cover [0, totalLength).
 * Uses secure randomness and enforces minimum segment length.
 */
function randomNonOverlappingSegments(
  totalLength: number,
  count: number,
): Array<[number, number]> {
  if (count <= 0) {
    throw new RangeError(`Cannot create ${count} segments`);
  }
  if (totalLength < count * MIN_SEGMENT_LENGTH) {
    throw new RangeError(
      `Cannot create ${count} segments of min length ${MIN_SEGMENT_LENGTH} in ${totalLength} chars`
    );
  }

  // Distribute space: start with equal division, then jitter boundaries
  const baseSize = Math.floor(totalLength / count);
  const boundaries: number[] = [0];

  for (let i = 1; i < count; i++) {
    const ideal = i * baseSize;
    // Jitter +/-20% of base size, but keep at least MIN_SEGMENT_LENGTH per segment
    const maxJitter = Math.floor(baseSize * 0.20);
    const jitter = secureRandomInt(maxJitter * 2 + 1) - maxJitter;
    const minBoundary = boundaries[i - 1] + MIN_SEGMENT_LENGTH;
    const maxBoundary = totalLength - (count - i) * MIN_SEGMENT_LENGTH;
    const boundary = Math.max(minBoundary, Math.min(maxBoundary, ideal + jitter));
    boundaries.push(boundary);
  }
  boundaries.push(totalLength);

  // Jitter and shuffle the interior boundaries to diversify layouts per client.
  const midBoundaries = boundaries.slice(1, -1);
  for (let i = midBoundaries.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [midBoundaries[i], midBoundaries[j]] = [midBoundaries[j], midBoundaries[i]];
  }

  // Re-sort to maintain valid non-overlapping ranges after shuffle
  midBoundaries.sort((a, b) => a - b);
  const finalBoundaries = [0, ...midBoundaries, totalLength];

  return finalBoundaries
    .slice(0, -1)
    .map((start, i) => [start, finalBoundaries[i + 1]] as [number, number]);
}
