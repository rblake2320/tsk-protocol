/**
 * TSK + BPC Ultra Enhancement — 7-Layer Authentication
 *
 * Combines BPC (5 layers) + TSK (2 layers) without modifying BPC source code.
 * BPC's verifyBPCRequest is a pure exported function — we wrap it.
 *
 * Layer Stack:
 *   1. BPC: Device-bound ECDSA P-256 (TPM, extractable: false)
 *   2. BPC: Explicit pair registry (closed whitelist, owner approval)
 *   3. BPC: User-chosen secret HMAC'd into every signature
 *   4. BPC: Per-request nonce + ±60s timestamp anti-replay
 *   5. BPC: Behavioral anomaly engine (per-pair threat scoring)
 *   6. TSK: Tumbler key with per-client secret position map
 *   7. TSK: Structural secrecy (key format/positions themselves are secrets)
 *
 * A stolen credential set (pair ID + env vars) defeats BPC layers 1-3 because
 * the TPM private key is non-extractable and the user secret isn't in env vars.
 * TSK adds an independent second factor: even if BPC were somehow bypassed,
 * the attacker would also need to know which tumbler positions are live and
 * at what temporal state — information that exists only on the server.
 *
 * NO BPC CODE CHANGES REQUIRED. This file is the entire bridge.
 */

import { verifyTSKRequest, type TSKRequestData, type TSKServerConfig, type TSKVerifyResult } from '@tsk/server';
import type { TumblerMapStore } from '@tsk/server';

/**
 * BPC verification result shape (compatible with @bpc/server BPCVerifyResult).
 * Typed generically so this file doesn't require @bpc/server as a hard dep
 * (it's a peer dep — consumers bring their own BPC).
 */
export interface BPCLikeResult {
  ok: boolean;
  pairId?: string;
  error?: string;
}

export interface UltraVerifyResult {
  ok: boolean;
  pairId?: string;
  clientId?: string;
  layers: ('bpc' | 'tsk')[];
  error?: string;
}

export interface UltraVerifyOptions {
  tskStore: TumblerMapStore;
  tskConfig?: TSKServerConfig;
  /** Optional: resolve pairId -> expected TSK clientId. If provided, mismatch = rejection. */
  identityBinding?: {
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
 *     { tskStore }
 *   );
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

  // Identity binding: verify BPC pairId and TSK clientId belong to the same principal
  if (options.identityBinding && bpcResult.pairId && tskResult.clientId) {
    const expectedClientId = await options.identityBinding.resolve(bpcResult.pairId);
    if (expectedClientId !== tskResult.clientId) {
      return {
        ok: false,
        pairId: bpcResult.pairId,
        error: 'IDENTITY_BINDING_MISMATCH',
        layers: ['bpc', 'tsk'],
      };
    }
  }

  return {
    ok: true,
    pairId: bpcResult.pairId,
    clientId: tskResult.clientId,
    layers: ['bpc', 'tsk'],
  };
}

/**
 * The 7 security properties of the ultra stack, for documentation/audit.
 */
export const ULTRA_SECURITY_LAYERS = [
  { id: 1, source: 'BPC', property: 'Device-bound ECDSA P-256 private key (TPM, extractable: false)' },
  { id: 2, source: 'BPC', property: 'Explicit pair registry — closed whitelist with owner approval gate' },
  { id: 3, source: 'BPC', property: 'User-chosen secret HMAC\'d into every request signature' },
  { id: 4, source: 'BPC', property: 'Per-request cryptographic nonce + ±60s timestamp (anti-replay)' },
  { id: 5, source: 'BPC', property: 'Behavioral anomaly engine — per-pair threat scoring 0-100' },
  { id: 6, source: 'TSK', property: 'Tumbler key — TOTP/HOTP rotating segments, independent per-position' },
  { id: 7, source: 'TSK', property: 'Structural secrecy — tumbler map positions are a per-client server-side secret' },
] as const;
