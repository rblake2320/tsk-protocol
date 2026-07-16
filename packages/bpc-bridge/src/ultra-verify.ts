/**
 * TSK + BPC Ultra Enhancement - 7-layer composed authentication.
 *
 * The BPC authorization result and its identity binding are preflighted before
 * TSK verification can consume HOTP or lifecycle state. The bridge accepts
 * only BPC's immutable AuthSnapshot contract; mutable legacy pair objects and
 * direct scope fallbacks are intentionally unsupported.
 */

import {
  TSK_HEADERS,
  verifyTSKRequest,
  type TSKRequestData,
  type TSKServerConfig,
  type TSKVerifyResult,
  type TumblerMapStore,
} from '@tsk/server';

export type BPCScope = 'read' | 'read-write' | 'admin';
export type BPCMode = 'development' | 'production';
export type BPCCanaryClass = 'env_file' | 'docs' | 'registry_exfil';

const BPC_SCOPES = new Set<BPCScope>(['read', 'read-write', 'admin']);
const BPC_MODES = new Set<BPCMode>(['development', 'production']);
const DEFAULT_BPC_SNAPSHOT_MAX_AGE_MS = 60_000;
const MAX_BPC_SNAPSHOT_MAX_AGE_MS = 300_000;
const SAFE_ERROR_CODE = /^[a-z0-9_]{1,64}$/;
const SAFE_PAIR_ID = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_CLIENT_ID = /^[A-Za-z0-9_-]{1,128}$/;

function isBPCScope(value: unknown): value is BPCScope {
  return typeof value === 'string' && BPC_SCOPES.has(value as BPCScope);
}

function isBPCMode(value: unknown): value is BPCMode {
  return typeof value === 'string' && BPC_MODES.has(value as BPCMode);
}

export interface BPCAuthSnapshot {
  readonly pairId: string;
  readonly scope: BPCScope;
  readonly mode: BPCMode;
  readonly kind: 'legitimate' | 'ghost';
  readonly canaryClass?: BPCCanaryClass;
  readonly verifiedAt: number;
}

/** Runtime-untrusted shape returned by a BPC verification callback. */
export interface BPCLikeResult {
  ok: boolean;
  pairId?: string;
  snapshot?: BPCAuthSnapshot;
  error?: string;
  shadow?: boolean;
}

export interface UltraVerifyResult {
  ok: boolean;
  pairId?: string;
  clientId?: string;
  layers: ('bpc' | 'tsk')[];
  error?: string;
  /** Closed BPC scope captured in the immutable authorization snapshot. */
  scope?: BPCScope;
}

export interface UltraVerifyOptions {
  tskStore: TumblerMapStore;
  tskConfig?: TSKServerConfig;
  /** Maximum age/skew accepted for the per-request BPC snapshot. Default 60s. */
  bpcSnapshotMaxAgeMs?: number;
  /** Resolve a verified BPC pairId to the only allowed TSK clientId. */
  identityBinding: {
    resolve: (pairId: string) => Promise<string | null>;
  };
}

function ownDataValue(record: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function validSnapshot(
  value: unknown,
  pairId: string,
  now: number,
  maxAgeMs: number,
): value is BPCAuthSnapshot {
  if (value === null || typeof value !== 'object' || !Object.isFrozen(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const snapshot = value as object;
  if (ownDataValue(snapshot, 'pairId') !== pairId) return false;
  if (!isBPCScope(ownDataValue(snapshot, 'scope')) || !isBPCMode(ownDataValue(snapshot, 'mode'))) return false;
  if (ownDataValue(snapshot, 'kind') !== 'legitimate') return false;
  if (ownDataValue(snapshot, 'canaryClass') !== undefined) return false;
  const verifiedAt = ownDataValue(snapshot, 'verifiedAt');
  return typeof verifiedAt === 'number' &&
    Number.isSafeInteger(verifiedAt) &&
    Math.abs(now - verifiedAt) <= maxAgeMs;
}

function safeBpcError(value: unknown): string {
  return typeof value === 'string' && SAFE_ERROR_CODE.test(value)
    ? value
    : 'VERIFICATION_FAILED';
}

function getSingleHeader(req: TSKRequestData, name: string): string | undefined {
  const value = req.headers[name];
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && value.length === 1 && typeof value[0] === 'string') return value[0];
  return undefined;
}

/**
 * Verify a request through BPC and TSK without consuming TSK state on any BPC
 * shape, scope, identity-resolution, or claimed-identity denial.
 */
export async function verifyUltraRequest(
  req: TSKRequestData,
  bpcVerify: (req: TSKRequestData) => Promise<BPCLikeResult>,
  options: UltraVerifyOptions,
): Promise<UltraVerifyResult> {
  let untrustedResult: unknown;
  try {
    untrustedResult = await bpcVerify(req);
  } catch {
    return { ok: false, error: 'BPC: CALLBACK_EXCEPTION', layers: [] };
  }

  let pairId: string;
  let scope: BPCScope;
  try {
    if (untrustedResult === null || typeof untrustedResult !== 'object') {
      return { ok: false, error: 'BPC: VERIFICATION_FAILED', layers: [] };
    }
    const result = untrustedResult as object;
    if (ownDataValue(result, 'ok') !== true) {
      return {
        ok: false,
        error: `BPC: ${safeBpcError(ownDataValue(result, 'error'))}`,
        layers: [],
      };
    }
    if (ownDataValue(result, 'shadow') === true) {
      return { ok: false, error: 'BPC: SHADOW_DENIED', layers: [] };
    }
    if ('pair' in result || 'scope' in result) {
      return { ok: false, error: 'BPC: LEGACY_MUTABLE_RESULT', layers: [] };
    }

    const resultPairId = ownDataValue(result, 'pairId');
    if (typeof resultPairId !== 'string' || !SAFE_PAIR_ID.test(resultPairId)) {
      return { ok: false, error: 'BPC: MISSING_OR_INVALID_PAIR_ID', layers: [] };
    }
    const configuredMaxAge = options.bpcSnapshotMaxAgeMs ?? DEFAULT_BPC_SNAPSHOT_MAX_AGE_MS;
    if (!Number.isSafeInteger(configuredMaxAge) || configuredMaxAge < 1 ||
        configuredMaxAge > MAX_BPC_SNAPSHOT_MAX_AGE_MS) {
      return { ok: false, pairId: resultPairId, error: 'BPC: INVALID_SNAPSHOT_MAX_AGE', layers: [] };
    }
    const resultSnapshot = ownDataValue(result, 'snapshot');
    if (!validSnapshot(resultSnapshot, resultPairId, Date.now(), configuredMaxAge)) {
      return { ok: false, pairId: resultPairId, error: 'BPC: INVALID_AUTH_SNAPSHOT', layers: [] };
    }

    // Copy immutable evidence into local primitives before any further await.
    pairId = resultSnapshot.pairId;
    scope = resultSnapshot.scope;
  } catch {
    return { ok: false, error: 'BPC: INVALID_RESULT_OBJECT', layers: [] };
  }

  let expectedClientId: string | null;
  try {
    expectedClientId = await options.identityBinding.resolve(pairId);
  } catch {
    return {
      ok: false,
      pairId,
      error: 'IDENTITY_BINDING_RESOLVER_EXCEPTION',
      layers: ['bpc'],
    };
  }
  if (typeof expectedClientId !== 'string' || !SAFE_CLIENT_ID.test(expectedClientId)) {
    return {
      ok: false,
      pairId,
      error: 'IDENTITY_BINDING_NOT_FOUND',
      layers: ['bpc'],
    };
  }

  let claimedClientId: string | undefined;
  try {
    claimedClientId = getSingleHeader(req, TSK_HEADERS.CLIENT_ID);
  } catch {
    return {
      ok: false,
      pairId,
      error: 'TSK: CLIENT_ID_MISSING_OR_AMBIGUOUS',
      layers: ['bpc'],
    };
  }
  if (!claimedClientId || !SAFE_CLIENT_ID.test(claimedClientId)) {
    return {
      ok: false,
      pairId,
      error: 'TSK: CLIENT_ID_MISSING_OR_AMBIGUOUS',
      layers: ['bpc'],
    };
  }
  if (claimedClientId !== expectedClientId) {
    return {
      ok: false,
      pairId,
      clientId: claimedClientId,
      error: 'IDENTITY_BINDING_MISMATCH',
      layers: ['bpc'],
    };
  }

  let tskResult: TSKVerifyResult;
  try {
    tskResult = await verifyTSKRequest(req, options.tskStore, options.tskConfig);
  } catch {
    return {
      ok: false,
      pairId,
      error: 'TSK: VERIFIER_EXCEPTION',
      layers: ['bpc'],
    };
  }
  if (!tskResult.ok) {
    return {
      ok: false,
      pairId,
      error: `TSK: ${tskResult.error ?? 'VERIFICATION_FAILED'}`,
      layers: ['bpc'],
    };
  }

  if (tskResult.clientId !== expectedClientId) {
    return {
      ok: false,
      pairId,
      clientId: tskResult.clientId,
      error: 'IDENTITY_BINDING_POSTCHECK_MISMATCH',
      layers: ['bpc', 'tsk'],
    };
  }

  return {
    ok: true,
    pairId,
    clientId: tskResult.clientId,
    layers: ['bpc', 'tsk'],
    scope,
  };
}

/** The seven bounded security properties composed by the Ultra bridge. */
export const ULTRA_SECURITY_LAYERS = [
  { id: 1, source: 'BPC', property: 'Possession of an authorized ECDSA P-256 pair signing key' },
  { id: 2, source: 'BPC', property: 'Explicit pair registry - closed whitelist with owner approval gate' },
  { id: 3, source: 'BPC', property: 'User-chosen secret HMAC bound into every request signature' },
  { id: 4, source: 'BPC', property: 'Per-request nonce and bounded timestamp anti-replay validation' },
  { id: 5, source: 'BPC', property: 'Behavioral anomaly evaluation with ghost and shadow hard denial' },
  { id: 6, source: 'TSK', property: 'HMAC-SHA-256 segment values on time and counter schedules' },
  { id: 7, source: 'TSK', property: 'Atomic counter consumption and credential lifecycle enforcement' },
] as const;
