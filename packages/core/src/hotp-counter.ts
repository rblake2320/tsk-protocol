import type { ClientSegmentConfig, SegmentConfig } from './types.js';

/**
 * Wire-v1 HOTP counter ceiling.
 *
 * Values 0..MAX-1 may be used for derivation. MAX is a persisted exhausted
 * sentinel, which lets the final legal use commit without writing MAX+1.
 * A wider counter requires a versioned wire/storage migration.
 */
export const TSK_MAX_HOTP_COUNTER = 2_147_483_647;

/** Default number of usable counters remaining before rotation is required. */
export const DEFAULT_HOTP_ROTATION_WARNING_COUNTERS = 1_000;

export type TSKHOTPCounterErrorCode =
  | 'TSK_HOTP_COUNTER_INVALID'
  | 'TSK_HOTP_COUNTER_EXHAUSTED';

export class TSKHOTPCounterError extends RangeError {
  constructor(public readonly code: TSKHOTPCounterErrorCode, message: string) {
    super(message);
    this.name = 'TSKHOTPCounterError';
  }
}

/** True for persisted v1 counters, including the exhausted MAX sentinel. */
export function isValidHOTPStoredCounter(value: unknown): value is number {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= TSK_MAX_HOTP_COUNTER;
}

/** True only for counters that may still be used to derive a v1 credential. */
export function isUsableHOTPDerivationCounter(value: unknown): value is number {
  return isValidHOTPStoredCounter(value) && value < TSK_MAX_HOTP_COUNTER;
}

export function assertValidHOTPStoredCounter(value: unknown, label = 'HOTP counter'): asserts value is number {
  if (!isValidHOTPStoredCounter(value)) {
    throw new TSKHOTPCounterError(
      'TSK_HOTP_COUNTER_INVALID',
      `${label} must be a safe integer in [0, ${TSK_MAX_HOTP_COUNTER}]`,
    );
  }
}

export function assertUsableHOTPDerivationCounter(value: unknown, label = 'HOTP counter'): asserts value is number {
  assertValidHOTPStoredCounter(value, label);
  if (value >= TSK_MAX_HOTP_COUNTER) {
    throw new TSKHOTPCounterError(
      'TSK_HOTP_COUNTER_EXHAUSTED',
      `${label} is exhausted for wire v1`,
    );
  }
}

/** Number of legal derivations remaining from a persisted counter. */
export function hotpUsesRemaining(counter: number): number {
  assertValidHOTPStoredCounter(counter);
  return TSK_MAX_HOTP_COUNTER - counter;
}

/** The HOTP segment nearest exhaustion governs credential rotation. */
export function minimumHOTPUsesRemaining(
  segments: ReadonlyArray<Pick<SegmentConfig, 'type' | 'counter'>>,
): number | undefined {
  let minimum: number | undefined;
  for (const segment of segments) {
    if (segment.type !== 'hotp') continue;
    const counter = segment.counter ?? 0;
    assertValidHOTPStoredCounter(counter);
    const remaining = hotpUsesRemaining(counter);
    minimum = minimum === undefined ? remaining : Math.min(minimum, remaining);
  }
  return minimum;
}

export function assertValidClientHOTPInitialCounters(
  segments: ReadonlyArray<Pick<ClientSegmentConfig, 'segmentId' | 'type' | 'initialCounter'>>,
): void {
  for (const segment of segments) {
    if (segment.type !== 'hotp') continue;
    assertValidHOTPStoredCounter(
      segment.initialCounter ?? 0,
      `initial HOTP counter for ${segment.segmentId}`,
    );
  }
}

