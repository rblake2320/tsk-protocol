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
  /** Encrypted/sealed tumbler map delivered to client at provisioning */
  clientId: string;
  /** Segments the client needs to regenerate keys (excludes position info — client only needs types + timing, server holds positions) */
  clientSegments: ClientSegmentConfig[];
  /** Total key length (client needs this to allocate the buffer) */
  keyLength: number;
  /** segmentIds in position order — for correct positional key assembly on the client */
  segmentOrder?: string[];
  /** Provisioned at timestamp */
  createdAt: number;
  /** Version */
  version: '1';
}

/** What the client receives — positions OMITTED (structural secrecy) */
export interface ClientSegmentConfig {
  segmentId: string;
  type: SegmentType;
  /** TOTP window in seconds */
  windowSec?: number;
  /** Initial HOTP counter (increments on each use) */
  initialCounter?: number;
  /** Segment length in characters */
  length?: number;
}

export interface TSKValidationResult {
  ok: boolean;
  clientId?: string;
  error?: TSKError;
  /** Per-segment validation details (for anomaly detection) */
  segmentResults?: { segmentId: string; valid: boolean }[];
}

export type TSKError =
  | 'CLIENT_NOT_FOUND'
  | 'KEY_LENGTH_MISMATCH'
  | 'SEGMENT_EXPIRED'
  | 'CHECKSUM_INVALID'
  | 'VALIDATION_FAILED'
  | 'HOTP_COUNTER_EXHAUSTED'
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
  maxKeyLength: 256,
  minKeyLength: 16,
};
