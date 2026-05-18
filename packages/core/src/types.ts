/**
 * TSK Protocol — Core Types
 * Tumbler-Style Rotating Segment Keys
 *
 * A TSKKey is a fixed-length string where individual character segments rotate
 * independently on TOTP/HOTP schedules. The map of WHICH positions rotate (and
 * at what rate) is a per-client secret stored only on the server — this "structural
 * secrecy" is the core novel security property.
 */

export type SegmentType = 'static' | 'totp' | 'hotp';

export interface SegmentConfig {
  /** Unique stable identifier for this segment */
  segmentId: string;
  /** [startIndex, endIndex) — exclusive end, zero-based position in key string */
  position: [number, number];
  /** Whether this segment is static, time-based (TOTP), or counter-based (HOTP) */
  type: SegmentType;
  /** TOTP only: rotation window in seconds (30, 60, 120, 300) */
  windowSec?: number;
  /** HOTP only: current counter value (server-side source of truth) */
  counter?: number;
}

export interface TumblerMap {
  /** Stable client identifier (also embedded in static segment for self-describing keys) */
  clientId: string;
  /** 256-bit random shared secret, hex-encoded. NEVER transmitted after provisioning. */
  sharedSecret: string;
  /** Total key length in characters */
  keyLength: number;
  /** All segment definitions, including static and rotating */
  segments: SegmentConfig[];
  /** Position of the checksum segment (last N chars) */
  checksum: { position: [number, number] };
  /** Unix timestamp (ms) when this map was provisioned */
  createdAt: number;
  /** Protocol version */
  version: '1';
}

export interface TSKProvisionPayload {
  /** Client identifier */
  clientId: string;
  /**
   * Segments the client needs to regenerate values (excludes positions and lengths).
   * STRUCTURAL SECRECY: The client only knows segment IDs, types, and timing.
   * It cannot reconstruct positions from this payload.
   */
  clientSegments: ClientSegmentConfig[];
  /**
   * Total key length — provided only for HTTP header size validation.
   * The client does NOT use this to infer segment positions or lengths.
   */
  keyLength: number;
  /**
   * segmentOrder is intentionally ABSENT.
   * Providing ordered segment IDs would allow position reconstruction.
   * The server assembles the key from raw client segment values.
   */
  /** Provisioned at timestamp */
  createdAt: number;
  /** Version */
  version: '1';
}

/**
 * What the client receives — positions and lengths OMITTED (structural secrecy).
 * The client can only derive segment values; it cannot reconstruct the key layout.
 */
export interface ClientSegmentConfig {
  segmentId: string;
  type: SegmentType;
  /** TOTP window in seconds */
  windowSec?: number;
  /** Initial HOTP counter (increments on each use) */
  initialCounter?: number;
  /**
   * length is intentionally ABSENT from this interface.
   * Providing segment lengths would allow clients to reconstruct positions
   * by computing cumulative sums — defeating structural secrecy.
   */
}

export interface TSKValidationResult {
  ok: boolean;
  clientId?: string;
  error?: TSKError;
  /**
   * Per-segment validation details (for anomaly detection).
   * Includes segment type so anomaly engine can use type-safe detection
   * instead of fragile name-prefix heuristics.
   */
  segmentResults?: { segmentId: string; type: SegmentType; valid: boolean }[];
}

export type TSKError =
  | 'CLIENT_NOT_FOUND'
  | 'KEY_LENGTH_MISMATCH'
  | 'SEGMENT_EXPIRED'
  | 'CHECKSUM_INVALID'
  | 'VALIDATION_FAILED'
  | 'HOTP_COUNTER_EXHAUSTED'
  | 'MAP_INVALID_NO_SEGMENTS'
  | 'MAP_INVALID_ZERO_LENGTH_SEGMENT'
  | 'INTERNAL_ERROR';

export interface TSKConfig {
  /** TOTP: accept ±N windows (default 1 — covers ±30s for 30s windows) */
  totpToleranceWindows?: number;
  /** HOTP: accept codes up to N counters ahead of stored (default 5) */
  hotpLookahead?: number;
  /** Max key length allowed (default 256) */
  maxKeyLength?: number;
  /** Min key length required (default 16) */
  minKeyLength?: number;
}

export const DEFAULT_TSK_CONFIG: Required<TSKConfig> = {
  totpToleranceWindows: 1,
  hotpLookahead: 5,
  maxKeyLength: 512,  // Updated to match MAX_KEY_LENGTH in tumbler-map.ts
  minKeyLength: 20,   // Updated to match MIN_KEY_LENGTH in tumbler-map.ts
};
