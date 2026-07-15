/**
 * TSK Protocol — Core Types
 * Tumbler-Style Rotating Segment Keys
 *
 * A TSKKey is a fixed-length string where individual character segments rotate
 * independently on time- and counter-based schedules. The server retains the
 * authoritative lifecycle and counter state used to validate each key.
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

  // ── Key Lifecycle Fields ─────────────────────────────────────────────────

  /** Human-readable label for this key (e.g. 'production-agent-1', 'ci-runner'). */
  label?: string;

  /**
   * Unix timestamp (ms) after which this key is considered expired and all
   * validation attempts will be denied with 'key_expired'.
   * Omit for a key that never expires.
   */
  expiresAt?: number;

  /**
   * Hard cap on the total number of successful validations this key may serve.
   * Once requestCount reaches maxRequests, the key transitions to 'expired'
   * and all further attempts are denied with 'key_usage_cap_exceeded'.
   * Omit (or 0) for unlimited usage.
   */
  maxRequests?: number;

  /**
   * Number of requests remaining at which the server starts returning a
   * rotation-required signal. Defaults to 10% of maxRequests (minimum 1).
   * This is a warning window, not a grace period: the hard cap still denies.
   */
  rotationWarningRequests?: number;

  /**
   * Number of usable HOTP counters remaining at which rotation is required.
   * Independent of maxRequests. Defaults to 1,000 for wire v1.
   */
  hotpRotationWarningCounters?: number;

  /**
   * Total number of successful validations served by this key.
   * Incremented by the server middleware after each successful verifyTSKRequest.
   */
  requestCount?: number;

  /**
   * Unix timestamp (ms) of the most recent successful validation.
   * Null if the key has never been used.
   */
  lastUsedAt?: number | null;

  /**
   * Key lifecycle status.
   * - 'active':    Key is valid and accepting requests.
   * - 'expiring':  Key is valid but inside its configured rotation warning window.
   * - 'revoked':   Key was explicitly revoked by an operator.
   * - 'expired':   Key has passed its expiresAt timestamp or hit its maxRequests cap.
   */
  status?: 'active' | 'expiring' | 'revoked' | 'expired';
}

export interface TSKProvisionPayload {
  /** Client identifier */
  clientId: string;
  /**
   * Ordered segment descriptions the client needs to regenerate values. The
   * ordering and lengths are sufficient to reconstruct segment boundaries;
   * they are not treated as a secret or authentication factor.
   */
  clientSegments: ClientSegmentConfig[];
  /**
   * Total key length — needed for HTTP header size validation and key assembly.
   */
  keyLength: number;
  /**
   * Checksum length in characters (always CHECKSUM_LENGTH = 12).
   * Included so the client knows how many chars to append as checksum.
   */
  checksumLength: number;
  /** Provisioned at timestamp */
  createdAt: number;
  /** Version */
  version: '1';
}

/**
 * What the client receives per segment.
 *
 * Absolute offsets are omitted, but the ordered lengths reveal the same
 * boundaries cumulatively. Security must not depend on hiding this layout.
 */
export interface ClientSegmentConfig {
  segmentId: string;
  type: SegmentType;
  /**
   * Number of characters this segment occupies in the assembled key.
   * The client uses this to truncate/pad its HMAC output before concatenation.
   * Ordered lengths allow the client to assemble the key deterministically.
   */
  segmentLength: number;
  /** TOTP window in seconds */
  windowSec?: number;
  /** Initial HOTP counter (increments on each use) */
  initialCounter?: number;
}

export interface TSKValidationResult {
  ok: boolean;
  clientId?: string;
  /**
   * External-facing error code.
   * TSK-06 FIX: All authentication failures return 'INVALID_KEY'.
   * Structural errors (MAP_INVALID_*) and length errors are returned as-is
   * since they reveal no exploitable information about key structure.
   * Never expose CHECKSUM_INVALID, VALIDATION_FAILED, or HOTP_COUNTER_EXHAUSTED
   * to the client — use internalError for server-side diagnostics.
   */
  error?: TSKError;
  /**
   * Internal diagnostic code — server-side anomaly engine use ONLY.
   * Must NEVER be returned to the client or included in HTTP responses.
   * TSK-06 FIX: Preserves diagnostic detail for server logs while hiding
   * structural information from external observers.
   */
  internalError?: TSKInternalError;
  /**
   * Per-segment validation details (for anomaly detection).
   * Includes segment type so anomaly engine can use type-safe detection
   * instead of fragile name-prefix heuristics.
   */
  segmentResults?: { segmentId: string; type: SegmentType; valid: boolean }[];
}

/** External-facing TSK error codes. */
export type TSKError =
  | 'CLIENT_NOT_FOUND'
  | 'KEY_LENGTH_MISMATCH'
  | 'MAP_INVALID_NO_SEGMENTS'
  | 'MAP_INVALID_NO_HOTP'
  | 'MAP_INVALID_ZERO_LENGTH_SEGMENT'
  | 'INVALID_KEY';   // TSK-06: generic external error for all auth failures

/**
 * Internal TSK error codes — server-side anomaly engine use ONLY.
 * Never expose to clients.
 */
export type TSKInternalError =
  | 'CHECKSUM_INVALID'
  | 'VALIDATION_FAILED'
  | 'HOTP_COUNTER_INVALID'
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
  maxKeyLength: 512,  // Updated to match MAX_KEY_LENGTH in tumbler-map.ts
  minKeyLength: 20,   // Updated to match MIN_KEY_LENGTH in tumbler-map.ts
};
