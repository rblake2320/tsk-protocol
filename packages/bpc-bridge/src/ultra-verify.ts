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
  const bpcResult = await bpcVerify(req);
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

  // --- Layers 6-7: TSK ---
  const tskResult: TSKVerifyResult = await verifyTSKRequest(req, options.tskStore, options.tskConfig);
  if (!tskResult.ok) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      error: `TSK: ${tskResult.error ?? 'VERIFICATION_FAILED'}`,
      layers: ['bpc'],
    };
  }

  // Identity binding: BPC and TSK must resolve to the same principal.
  if (!bpcResult.pairId || !tskResult.clientId) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      clientId: tskResult.clientId,
      error: 'IDENTITY_BINDING_UNAVAILABLE',
      layers: ['bpc', 'tsk'],
    };
  }

  const expectedClientId = await options.identityBinding.resolve(bpcResult.pairId);
  if (expectedClientId !== tskResult.clientId) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      clientId: tskResult.clientId,
      error: 'IDENTITY_BINDING_MISMATCH',
      layers: ['bpc', 'tsk'],
    };
  }

  return {
    ok: true,
    pairId: bpcResult.pairId,
    clientId: tskResult.clientId,
    layers: ['bpc', 'tsk'],
    scope: resolvedScope,
  };
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
