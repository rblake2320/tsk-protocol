/**
 * TSK + BPC Ultra Enhancement — 7-Layer Authentication
 *
 * Combines BPC (5 layers) + TSK (2 layers) without modifying BPC source code.
 * BPC's verifyBPCRequest is a pure exported function — we wrap it.
 *
 * Layer Stack:
 *   1. BPC: possession of an authorized ECDSA P-256 pair key
 *   2. BPC: Explicit pair registry (closed whitelist, owner approval)
 *   3. BPC: User-chosen secret HMAC'd into every signature
 *   4. BPC: Per-request nonce + ±60s timestamp anti-replay
 *   5. BPC: Behavioral anomaly engine (per-pair threat scoring)
 *   6. TSK: independently derived time/counter segment values
 *   7. TSK: atomic counter and lifecycle state transition
 *
 * TSK adds an independent shared-secret verifier. Compromise of either factor
 * does not by itself satisfy this bridge, but host/client compromise may expose
 * both factors and remains outside the bridge's protection boundary.
 *
 * NO BPC CODE CHANGES REQUIRED. This file is the entire bridge.
 */

import { verifyTSKRequest, type TSKRequestData, type TSKServerConfig, type TSKVerifyResult } from '@tsk/server';
import type { TumblerMapStore } from '@tsk/server';

export type BPCScope = 'read' | 'read-write' | 'admin';

const BPC_SCOPES = new Set<BPCScope>(['read', 'read-write', 'admin']);

function isBPCScope(value: unknown): value is BPCScope {
  return typeof value === 'string' && BPC_SCOPES.has(value as BPCScope);
}

/**
 * BPC verification result shape (compatible with @bpc/server BPCVerifyResult).
 * Typed generically so this file doesn't require @bpc/server as a hard dep
 * (it's a peer dep — consumers bring their own BPC).
 *
 * HIGH-03 FIX: Added `scope` and `pair` fields so the Ultra Bridge can
 * surface the BPC scope in UltraVerifyResult for cross-layer scope coherence.
 * The BPC middleware returns `pair` (the full StoredPair) on success — callers
 * can pass it through and the bridge will extract `pair.scope` automatically.
 */
export interface BPCLikeResult {
  ok: boolean;
  pairId?: string;
  error?: string;
  /**
   * The BPC pair scope ('read' | 'read-write' | 'admin').
   * If `pair.scope` is also present, both values must agree.
   */
  scope?: BPCScope;
  /**
   * The full BPC StoredPair object returned by verifyBPCRequest on success.
   * The bridge reads pair.scope from this if `scope` is not set directly.
   * Typed loosely to avoid a hard dep on @bpc/server types.
   */
  pair?: { scope?: BPCScope; [key: string]: unknown };
}

export interface UltraVerifyResult {
  ok: boolean;
  pairId?: string;
  clientId?: string;
  layers: ('bpc' | 'tsk')[];
  error?: string;
  /**
   * The verifier boundary failed after a request may have reached a
   * replay-sensitive component. Callers must preserve the operation and must
   * not infer denial, authentication, or permission to replay.
   */
  outcomeUnknown?: true;
  /**
   * HIGH-03 FIX: The BPC scope that was verified and is now propagated to
   * the caller. Callers MUST use this scope to enforce access control on
   * the downstream resource — the TSK layer alone does not enforce scope.
   *
   * Successful results always contain one BPC 0.2 closed coarse scope.
   */
  scope?: BPCScope;
}

export interface UltraVerifyOptions {
  tskStore: TumblerMapStore;
  tskConfig?: TSKServerConfig;
  /** Required: resolve BPC pairId -> expected TSK clientId. Mismatch = rejection. */
  identityBinding: {
    resolve: (pairId: string) => Promise<string | null>;
  };
}

/**
 * Verify a request through both BPC and TSK layers.
 *
 * @param req - The request data (must have both BPC and TSK headers)
 * @param bpcVerify - A function that calls BPC's verifyBPCRequest (caller brings BPC dep)
 * @param options - TSK store and config
 *
 * Example:
 *   const result = await verifyUltraRequest(req,
 *     (r) => verifyBPCRequest(r, registry, nonceStore, anomaly, bpcConfig),
 *     { tskStore, identityBinding }
 *   );
 *
 * HIGH-03: A successful result contains the verified BPC pair scope. Callers MUST
 * enforce this scope on the downstream resource. The Ultra Bridge does NOT
 * automatically block write operations for read-scoped pairs — that enforcement
 * is the caller's responsibility using result.scope.
 */
export async function verifyUltraRequest(
  req: TSKRequestData,
  bpcVerify: (req: TSKRequestData) => Promise<BPCLikeResult>,
  options: UltraVerifyOptions,
): Promise<UltraVerifyResult> {
  // --- Layers 1-5: BPC ---
  let bpcResult: BPCLikeResult;
  try {
    bpcResult = await bpcVerify(req);
  } catch {
    return {
      ok: false,
      error: 'BPC: VERIFICATION_UNKNOWN',
      outcomeUnknown: true,
      layers: [],
    };
  }
  if (!bpcResult.ok) {
    return {
      ok: false,
      error: `BPC: ${bpcResult.error ?? 'VERIFICATION_FAILED'}`,
      layers: [],
    };
  }

  // BPC 0.2 deliberately uses a closed scope enum. Enforce that contract at
  // the composition boundary before TSK can consume counter/lifecycle state.
  const directScope: unknown = bpcResult.scope;
  const pairScope: unknown = bpcResult.pair?.scope;
  if (directScope !== undefined && pairScope !== undefined && directScope !== pairScope) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      error: 'BPC: SCOPE_MISMATCH',
      layers: [],
    };
  }
  const resolvedScope = directScope ?? pairScope;
  if (!isBPCScope(resolvedScope)) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      error: 'BPC: INVALID_SCOPE',
      layers: [],
    };
  }

  // Resolve the authoritative BPC pair -> TSK client binding before TSK
  // verification. TSK validation commits replay-sensitive counter/lifecycle
  // state on success, so a missing or mismatched binding must never reach it.
  const pairId = bpcResult.pairId;
  const claimedClientId = singleHeader(req, 'x-tsk-client-id');
  if (!pairId || !claimedClientId) {
    return {
      ok: false,
      pairId,
      error: 'IDENTITY_BINDING_UNAVAILABLE',
      layers: ['bpc'],
    };
  }

  let expectedClientId: string | null;
  try {
    expectedClientId = await options.identityBinding.resolve(pairId);
  } catch {
    return {
      ok: false,
      pairId,
      error: 'IDENTITY_BINDING_UNKNOWN',
      outcomeUnknown: true,
      layers: ['bpc'],
    };
  }
  if (!expectedClientId) {
    return {
      ok: false,
      pairId,
      error: 'IDENTITY_BINDING_UNAVAILABLE',
      layers: ['bpc'],
    };
  }
  if (expectedClientId !== claimedClientId) {
    return {
      ok: false,
      pairId,
      clientId: claimedClientId,
      error: 'IDENTITY_BINDING_MISMATCH',
      layers: ['bpc'],
    };
  }

  // --- Layers 6-7: TSK ---
  let tskResult: TSKVerifyResult;
  try {
    tskResult = await verifyTSKRequest(req, options.tskStore, options.tskConfig);
  } catch {
    return {
      ok: false,
      pairId,
      error: 'TSK: VERIFICATION_UNKNOWN',
      outcomeUnknown: true,
      layers: ['bpc'],
    };
  }
  if (!tskResult.ok) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      error: `TSK: ${tskResult.error ?? 'VERIFICATION_FAILED'}`,
      layers: ['bpc'],
    };
  }

  // Preserve the post-verification invariant even though the claimed header
  // was compared before verification: the cryptographic verifier must attest
  // to the same client identity the authoritative pair binding selected.
  if (!tskResult.clientId) {
    return {
      ok: false,
      pairId,
      clientId: tskResult.clientId,
      error: 'IDENTITY_BINDING_UNAVAILABLE',
      outcomeUnknown: true,
      layers: ['bpc', 'tsk'],
    };
  }
  if (expectedClientId !== tskResult.clientId) {
    return {
      ok: false,
      pairId,
      clientId: tskResult.clientId,
      error: 'IDENTITY_BINDING_MISMATCH',
      outcomeUnknown: true,
      layers: ['bpc', 'tsk'],
    };
  }

  return {
    ok: true,
    pairId,
    clientId: tskResult.clientId,
    layers: ['bpc', 'tsk'],
    scope: resolvedScope,
  };
}

/** Reject duplicate/non-string identity headers at the binding boundary. */
function singleHeader(req: TSKRequestData, name: string): string | undefined {
  const value = req.headers[name];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * The 7 security properties of the ultra stack, for documentation/audit.
 */
export const ULTRA_SECURITY_LAYERS = [
  { id: 1, source: 'BPC', property: 'Possession of an authorized ECDSA P-256 pair signing key' },
  { id: 2, source: 'BPC', property: 'Explicit pair registry — closed whitelist with owner approval gate' },
  { id: 3, source: 'BPC', property: 'User-chosen secret HMAC\'d into every request signature' },
  { id: 4, source: 'BPC', property: 'Per-request cryptographic nonce + ±60s timestamp (anti-replay)' },
  { id: 5, source: 'BPC', property: 'Behavioral anomaly engine — per-pair threat scoring 0-100' },
  { id: 6, source: 'TSK', property: 'HMAC-SHA-256 segment values on time and counter schedules' },
  { id: 7, source: 'TSK', property: 'Atomic counter consumption and credential lifecycle enforcement' },
] as const;
