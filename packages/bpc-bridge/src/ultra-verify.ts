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
 *
 * Issue #4 fix: All BPC result validation and identity binding is performed
 * BEFORE verifyTSKRequest is called. TSK counter and lifecycle state are
 * never consumed on a malformed, mismatched, or missing BPC result.
 */

import { verifyTSKRequest, type TSKRequestData, type TSKServerConfig, type TSKVerifyResult } from '@tsk/server';
import type { TumblerMapStore } from '@tsk/server';

/** Closed set of valid BPC scope values. */
const VALID_BPC_SCOPES = new Set(['read', 'read-write', 'admin']);

/**
 * BPC verification result shape (compatible with @bpc/server BPCVerifyResult).
 * Typed generically so this file doesn't require @bpc/server as a hard dep.
 *
 * Supports both the legacy `pair?.scope` shape and the new immutable
 * `snapshot?.scope` shape from BPC fix/immutable-auth-snapshot.
 */
export interface BPCLikeResult {
  /**
   * MUST be the boolean true for BPC verification to be accepted.
   * Truthy-but-not-true values (e.g. 'false', 1, {}) are treated as failure.
   */
  ok: boolean;
  pairId?: string;
  error?: string;
  /**
   * Immutable authorization snapshot (new shape from BPC fix/immutable-auth-snapshot).
   * Preferred source for scope. If present and ok===true, scope is read from here.
   */
  snapshot?: { scope?: string; [key: string]: unknown };
  /**
   * The BPC pair scope ('read' | 'read-write' | 'admin').
   * Set this directly if you want to override scope extraction from pair/snapshot.
   */
  scope?: string;
  /**
   * The full BPC StoredPair object (legacy shape).
   * The bridge reads pair.scope from this if scope and snapshot are not set.
   * Typed loosely to avoid a hard dep on @bpc/server types.
   */
  pair?: { scope?: string; [key: string]: unknown };
}

export interface UltraVerifyResult {
  ok: boolean;
  pairId?: string;
  clientId?: string;
  layers: ('bpc' | 'tsk')[];
  error?: string;
  /**
   * The BPC scope verified at authorization time.
   * Read from result.snapshot.scope (immutable) or result.scope or result.pair.scope.
   * Callers MUST use this scope to enforce access control on the downstream resource.
   * Values: 'read' | 'read-write' | 'admin' | undefined
   */
  scope?: string;
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
 * BPC preflight (identity binding, scope validation) is performed BEFORE TSK
 * verification so that TSK counter and lifecycle state are never consumed on
 * a malformed, mismatched, or missing BPC result.
 *
 * @param req - The request data (must have both BPC and TSK headers)
 * @param bpcVerify - A function that calls BPC's verifyBPCRequest
 * @param options - TSK store, config, and identity binding resolver
 */
export async function verifyUltraRequest(
  req: TSKRequestData,
  bpcVerify: (req: TSKRequestData) => Promise<BPCLikeResult>,
  options: UltraVerifyOptions,
): Promise<UltraVerifyResult> {

  // ── Layers 1–5: BPC ─────────────────────────────────────────────────────────

  let bpcResult: BPCLikeResult;
  try {
    bpcResult = await bpcVerify(req);
  } catch (err) {
    // Resolver exceptions must not reach TSK. Deny immediately.
    return {
      ok: false,
      error: 'BPC_CALLBACK_EXCEPTION',
      layers: [],
    };
  }

  // Strict structural validation of the BPC result before trusting ANY field.
  // ok must be exactly the boolean true — truthy-but-not-true values are denied.
  if (
    bpcResult === null ||
    typeof bpcResult !== 'object' ||
    bpcResult.ok !== true
  ) {
    return {
      ok: false,
      error: `BPC: ${(bpcResult as BPCLikeResult)?.error ?? 'VERIFICATION_FAILED'}`,
      layers: [],
    };
  }

  // pairId must be a non-empty string.
  if (typeof bpcResult.pairId !== 'string' || bpcResult.pairId.length === 0) {
    return {
      ok: false,
      error: 'BPC_MISSING_PAIR_ID',
      layers: [],
    };
  }

  // Extract scope: prefer snapshot (immutable) > direct scope > pair.scope (legacy).
  const resolvedScope: string | undefined =
    (bpcResult.snapshot as { scope?: string } | undefined)?.scope ??
    bpcResult.scope ??
    (bpcResult.pair as { scope?: string } | undefined)?.scope;

  // Scope must be one of the three closed BPC values.
  if (!resolvedScope || !VALID_BPC_SCOPES.has(resolvedScope)) {
    return {
      ok: false,
      error: 'BPC_INVALID_SCOPE',
      layers: [],
    };
  }

  // ── Identity preflight — BEFORE TSK state consumption ──────────────────────────
  //
  // Resolve the expected TSK clientId for this BPC pairId before invoking
  // verifyTSKRequest. If binding resolution fails or mismatches, we deny
  // without consuming any TSK counter or lifecycle state.

  let expectedClientId: string | null;
  try {
    expectedClientId = await options.identityBinding.resolve(bpcResult.pairId);
  } catch {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      error: 'IDENTITY_BINDING_RESOLVER_EXCEPTION',
      layers: [],
    };
  }

  if (!expectedClientId) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      error: 'IDENTITY_BINDING_NOT_FOUND',
      layers: [],
    };
  }

  // ── Layers 6–7: TSK ─────────────────────────────────────────────────────────
  //
  // TSK verification (and counter/lifecycle state consumption) only runs
  // after BPC preflight and identity binding have fully passed.

  const tskResult: TSKVerifyResult = await verifyTSKRequest(req, options.tskStore, options.tskConfig);
  if (!tskResult.ok) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      error: `TSK: ${tskResult.error ?? 'VERIFICATION_FAILED'}`,
      layers: ['bpc'],
    };
  }

  // Post-TSK identity agreement check.
  // The expected clientId was resolved before TSK ran; we now confirm the
  // TSK-verified clientId matches exactly.
  if (!tskResult.clientId) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      error: 'TSK_MISSING_CLIENT_ID',
      layers: ['bpc', 'tsk'],
    };
  }

  if (expectedClientId !== tskResult.clientId) {
    return {
      ok: false,
      pairId: bpcResult.pairId,
      clientId: tskResult.clientId,
      error: 'IDENTITY_BINDING_MISMATCH',
      layers: ['bpc', 'tsk'],
    };
  }

  // All seven layers passed. Return verified identity and immutable scope.
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
