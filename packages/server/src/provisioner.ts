/**
 * TSK Protocol — Server-Side Provisioner
 *
 * Key security fixes in this version:
 * 1. INPUT VALIDATION: all provisioning parameters validated before use.
 * 2. RATE LIMITING INTERFACE: RateLimiter interface allows plugging in
 *    token-bucket or sliding-window rate limiters for production deployments.
 * 3. PROVISIONER GUARD: max concurrent provisioning requests tracked to
 *    prevent provisioner spam exhausting memory.
 * 4. REVOCATION: revoke() now returns a boolean indicating whether the
 *    client existed (useful for audit logging).
 * 5. AUDIT LOGGING: structured audit callback interface for deployment evidence.
 */
import {
  generateTumblerMap,
  toProvisionPayload,
  type TumblerMap,
  type TSKProvisionPayload,
  type TumblerMapOptions,
  MIN_KEY_LENGTH,
  MAX_KEY_LENGTH,
  MIN_TUMBLERS,
  MAX_TUMBLERS,
  MIN_WINDOW_SEC,
  MAX_WINDOW_SEC,
} from '@tsk/core';
import { emitKeyGenerationCapture } from '@tsk/core';
import type { TumblerMapStore } from './store.js';

// ─── Rate Limiter Interface ───────────────────────────────────────────────────

/**
 * Rate limiter interface for provisioning endpoint protection.
 * Implement with a token-bucket or sliding-window algorithm for production.
 *
 * Example implementations:
 * - MemoryRateLimiter (included below, for dev/testing)
 * - RedisRateLimiter (recommended for production multi-server deployments)
 */
export interface ProvisionRateLimiter {
  /** Returns true if the request is allowed, false if rate limit exceeded. */
  allow(key: string): boolean;
}

/**
 * Simple in-memory token-bucket rate limiter.
 * For production, replace with a Redis-backed sliding-window implementation.
 *
 * Default: 10 provisions per minute per key.
 */
export class MemoryProvisionRateLimiter implements ProvisionRateLimiter {
  private buckets = new Map<string, { tokens: number; lastRefill: number }>();
  private readonly maxTokens: number;
  private readonly refillRateMs: number; // ms per token

  constructor(maxPerMinute = 10) {
    this.maxTokens = maxPerMinute;
    this.refillRateMs = 60_000 / maxPerMinute;
  }

  allow(key: string): boolean {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = { tokens: this.maxTokens - 1, lastRefill: now };
      this.buckets.set(key, bucket);
      return true;
    }

    // Refill tokens based on elapsed time
    const elapsed = now - bucket.lastRefill;
    const newTokens = Math.floor(elapsed / this.refillRateMs);
    if (newTokens > 0) {
      bucket.tokens = Math.min(this.maxTokens, bucket.tokens + newTokens);
      bucket.lastRefill = now;
    }

    if (bucket.tokens <= 0) return false;
    bucket.tokens--;
    return true;
  }
}

// ─── Audit Logger Interface ───────────────────────────────────────────────────

/**
 * Audit logger interface for deployment evidence.
 * All provisioning and revocation events must be logged.
 */
export interface ProvisionAuditLogger {
  logProvision(clientId: string, requestorId?: string): void;
  logRevocation(clientId: string, requestorId?: string): void;
  logRateLimitExceeded(requestorId?: string): void;
  logReplacement?(oldClientId: string, newClientId: string, requestorId: string, reason: string): void;
}

export interface ReplacementAuthorizationRequest {
  oldClientId: string;
  requestorId: string;
  reason: string;
}

export interface LifecycleAuthorizationRequest {
  clientId: string;
  requestorId: string;
  reason: string;
  action: 'revoke' | 'update';
}

// ─── Provision Result ─────────────────────────────────────────────────────────

export interface ProvisionResult {
  ok: boolean;
  clientId?: string;
  /** Safe to send to client — positions and lengths are omitted */
  provisionPayload?: TSKProvisionPayload;
  /** Full map — NEVER send to client, store server-side only */
  tumblerMap?: TumblerMap;
  error?: string;
}

// ─── Provisioner Options ──────────────────────────────────────────────────────

export interface ProvisionerOptions {
  /** Rate limiter for provisioning requests (optional, recommended for production) */
  rateLimiter?: ProvisionRateLimiter;
  /** Optional deployment audit callback. Its presence establishes no authorization status. */
  auditLogger?: ProvisionAuditLogger;
  /** Max total provisioned clients (memory guard, default: unlimited) */
  maxClients?: number;
  /** Mandatory external authorization boundary for credential replacement. */
  replacementAuthorizer?: (request: ReplacementAuthorizationRequest) => Promise<boolean>;
  /** Mandatory external authorization boundary for revoke/update operations. */
  lifecycleAuthorizer?: (request: LifecycleAuthorizationRequest) => Promise<boolean>;
}

// ─── Provisioner ──────────────────────────────────────────────────────────────

export class TSKProvisioner {
  private readonly rateLimiter?: ProvisionRateLimiter;
  private readonly auditLogger?: ProvisionAuditLogger;
  private readonly maxClients?: number;
  private readonly replacementAuthorizer?: (request: ReplacementAuthorizationRequest) => Promise<boolean>;
  private readonly lifecycleAuthorizer?: (request: LifecycleAuthorizationRequest) => Promise<boolean>;

  constructor(
    private store: TumblerMapStore,
    options: ProvisionerOptions = {},
  ) {
    this.rateLimiter = options.rateLimiter;
    this.auditLogger = options.auditLogger;
    this.maxClients = options.maxClients;
    this.replacementAuthorizer = options.replacementAuthorizer;
    this.lifecycleAuthorizer = options.lifecycleAuthorizer;
  }

  /**
   * Provision a new client.
   *
   * @param options - Map generation options (all validated before use)
   * @param requestorId - Optional identifier of the requestor (for rate limiting and audit)
   * @param lifecycle - Optional lifecycle metadata (label, expiry, usage cap)
   * @returns ProvisionResult with client payload and full map
   */
  async provision(
    options: TumblerMapOptions = {},
    requestorId?: string,
    lifecycle?: {
      /** Human-readable label for this key. */
      label?: string;
      /** Unix timestamp (ms) after which the key expires. */
      expiresAt?: number;
      /** Hard cap on successful validations. 0 or omitted = unlimited. */
      maxRequests?: number;
      /** Explicit number of remaining requests at which rotation is required. */
      rotationWarningRequests?: number;
    },
  ): Promise<ProvisionResult> {
    // ── Rate limit check ────────────────────────────────────────────────────
    if (this.rateLimiter && requestorId) {
      if (!this.rateLimiter.allow(requestorId)) {
        this.auditLogger?.logRateLimitExceeded(requestorId);
        return { ok: false, error: 'PROVISION_RATE_LIMIT_EXCEEDED' };
      }
    }

    // ── Max client guard ────────────────────────────────────────────────────
    if (this.maxClients !== undefined) {
      const existing = await this.store.list();
      if (existing.length >= this.maxClients) {
        return { ok: false, error: 'PROVISION_CLIENT_LIMIT_REACHED' };
      }
    }

    // ── Input validation (redundant with generateTumblerMap but explicit) ───
    const validationError = validateProvisionOptions(options);
    if (validationError) {
      return { ok: false, error: validationError };
    }

    try {
      const map = generateTumblerMap(options);
      // Apply lifecycle metadata if provided
      if (lifecycle) {
        if (lifecycle.label !== undefined) map.label = lifecycle.label;
        if (lifecycle.expiresAt !== undefined) map.expiresAt = lifecycle.expiresAt;
        if (lifecycle.maxRequests !== undefined && lifecycle.maxRequests > 0) {
          map.maxRequests = lifecycle.maxRequests;
        }
        if (lifecycle.rotationWarningRequests !== undefined) {
          if (!Number.isInteger(lifecycle.rotationWarningRequests) || lifecycle.rotationWarningRequests < 1) {
            return { ok: false, error: 'INVALID_ROTATION_WARNING_REQUESTS' };
          }
          if (map.maxRequests !== undefined && lifecycle.rotationWarningRequests > map.maxRequests) {
            return { ok: false, error: 'INVALID_ROTATION_WARNING_REQUESTS' };
          }
          map.rotationWarningRequests = lifecycle.rotationWarningRequests;
        }
      }
      // Initialize lifecycle tracking fields
      map.status = 'active';
      map.requestCount = 0;
      map.lastUsedAt = null;

      await this.store.set(map.clientId, map);
      this.auditLogger?.logProvision(map.clientId, requestorId);
      emitKeyGenerationCapture({
        protocol: 'tsk',
        packageName: '@tsk/server',
        event: 'tsk.client.provisioned',
        clientId: map.clientId,
        algorithm: 'HMAC-SHA-256',
        details: {
          keyLength: map.keyLength,
          segmentCount: map.segments.length,
          requestorId,
          label: lifecycle?.label,
        },
      });

      return {
        ok: true,
        clientId: map.clientId,
        provisionPayload: toProvisionPayload(map),
        tumblerMap: map,
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : 'PROVISION_FAILED',
      };
    }
  }

  /**
   * Revoke a client's tumbler map.
   * Returns true if the client existed and was revoked, false if not found.
   */
  async revoke(clientId: string, requestorId: string, reason: string): Promise<boolean> {
    if (!this.lifecycleAuthorizer || !requestorId || !reason) return false;
    if (!await this.lifecycleAuthorizer({ clientId, requestorId, reason, action: 'revoke' })) return false;
    const existing = await this.store.get(clientId);
    if (!existing) return false;

    await this.store.delete(clientId);
    this.auditLogger?.logRevocation(clientId, requestorId);
    return true;
  }

  /**
   * Create a replacement credential and revoke the prior credential in one
   * store transaction. No authorizer means replacement is disabled.
   */
  async replaceKey(
    oldClientId: string,
    options: TumblerMapOptions,
    lifecycle: {
      label?: string;
      expiresAt?: number;
      maxRequests?: number;
      rotationWarningRequests?: number;
    },
    requestorId: string,
    reason: string,
  ): Promise<ProvisionResult> {
    if (!this.replacementAuthorizer || !requestorId || !reason) {
      return { ok: false, error: 'REPLACEMENT_NOT_AUTHORIZED' };
    }
    const authorized = await this.replacementAuthorizer({ oldClientId, requestorId, reason });
    if (!authorized) return { ok: false, error: 'REPLACEMENT_NOT_AUTHORIZED' };

    const old = await this.store.get(oldClientId);
    if (!old || (old.status !== undefined && old.status !== 'active' && old.status !== 'expiring')) {
      return { ok: false, error: 'REPLACEMENT_NOT_AVAILABLE' };
    }
    const validationError = validateProvisionOptions(options);
    if (validationError) return { ok: false, error: validationError };

    try {
      const replacement = generateTumblerMap(options);
      replacement.status = 'active';
      replacement.requestCount = 0;
      replacement.lastUsedAt = null;
      replacement.label = lifecycle.label;
      replacement.expiresAt = lifecycle.expiresAt;
      if (lifecycle.maxRequests !== undefined && lifecycle.maxRequests > 0) {
        replacement.maxRequests = lifecycle.maxRequests;
      }
      if (lifecycle.rotationWarningRequests !== undefined) {
        if (!Number.isInteger(lifecycle.rotationWarningRequests) || lifecycle.rotationWarningRequests < 1 ||
            (replacement.maxRequests !== undefined && lifecycle.rotationWarningRequests > replacement.maxRequests)) {
          return { ok: false, error: 'INVALID_ROTATION_WARNING_REQUESTS' };
        }
        replacement.rotationWarningRequests = lifecycle.rotationWarningRequests;
      }

      const committed = await this.store.replaceCredential(oldClientId, replacement);
      if (!committed) return { ok: false, error: 'REPLACEMENT_COMMIT_FAILED' };
      this.auditLogger?.logReplacement?.(oldClientId, replacement.clientId, requestorId, reason);
      return {
        ok: true,
        clientId: replacement.clientId,
        provisionPayload: toProvisionPayload(replacement),
        tumblerMap: replacement,
      };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : 'REPLACEMENT_FAILED' };
    }
  }

  /**
   * Update lifecycle metadata on an existing key.
   * Allows changing label, expiry, maxRequests, warning window, and status.
   *
   * @returns true if the key was found and updated, false if not found.
   */
  async updateKey(
    clientId: string,
    updates: {
      label?: string;
      expiresAt?: number | null;
      maxRequests?: number | null;
      rotationWarningRequests?: number | null;
      status?: 'active' | 'expiring' | 'revoked' | 'expired';
    },
    requestorId: string,
    reason: string,
  ): Promise<boolean> {
    if (!this.lifecycleAuthorizer || !requestorId || !reason) return false;
    if (!await this.lifecycleAuthorizer({ clientId, requestorId, reason, action: 'update' })) return false;
    const existing = await this.store.get(clientId);
    if (!existing) return false;

    // Revoked and expired credentials cannot be reactivated or weakened through
    // metadata update. Recovery and replacement are separate ceremonies.
    if (existing.status === 'revoked' || existing.status === 'expired') return false;

    const updated = { ...existing };
    if ('label' in updates) updated.label = updates.label;
    if ('expiresAt' in updates) {
      updated.expiresAt = updates.expiresAt ?? undefined;
    }
    if ('maxRequests' in updates) {
      updated.maxRequests = updates.maxRequests ?? undefined;
    }
    if ('rotationWarningRequests' in updates) {
      const warning = updates.rotationWarningRequests;
      if (warning !== null && warning !== undefined && (!Number.isInteger(warning) || warning < 1)) {
        return false;
      }
      if (warning !== null && warning !== undefined && updated.maxRequests !== undefined && warning > updated.maxRequests) {
        return false;
      }
      updated.rotationWarningRequests = warning ?? undefined;
    }
    if (updates.status === 'revoked' || updates.status === 'expired') {
      updated.status = updates.status;
    } else if (updates.status !== undefined && updates.status !== existing.status) {
      return false;
    }

    await this.store.set(clientId, updated);
    this.auditLogger?.logProvision(clientId, requestorId); // reuse for audit trail
    return true;
  }

  /**
   * List all provisioned keys with their lifecycle metadata.
   * Returns a safe view — sharedSecret is never included.
   */
  async listKeys(): Promise<Array<{
    clientId: string;
    label?: string;
    status: string;
    createdAt: number;
    expiresAt?: number;
    maxRequests?: number;
    rotationWarningRequests?: number;
    requestCount: number;
    lastUsedAt: number | null;
    keyLength: number;
    segmentCount: number;
  }>> {
    const clientIds = await this.store.list();
    const results = await Promise.all(clientIds.map(id => this.store.get(id)));
    return results
      .filter((m): m is NonNullable<typeof m> => m !== null && m !== undefined)
      .map(m => ({
        clientId: m.clientId,
        label: m.label,
        status: m.status ?? 'active',
        createdAt: m.createdAt,
        expiresAt: m.expiresAt,
        maxRequests: m.maxRequests,
        rotationWarningRequests: m.rotationWarningRequests,
        requestCount: m.requestCount ?? 0,
        lastUsedAt: m.lastUsedAt ?? null,
        keyLength: m.keyLength,
        segmentCount: m.segments.length,
      }));
  }

  /**
   * Get a single key's lifecycle metadata.
   * Returns null if not found. Never includes sharedSecret.
   */
  async getKey(clientId: string): Promise<{
    clientId: string;
    label?: string;
    status: string;
    createdAt: number;
    expiresAt?: number;
    maxRequests?: number;
    rotationWarningRequests?: number;
    requestCount: number;
    lastUsedAt: number | null;
    keyLength: number;
    segmentCount: number;
  } | null> {
    const m = await this.store.get(clientId);
    if (!m) return null;
    return {
      clientId: m.clientId,
      label: m.label,
      status: m.status ?? 'active',
      createdAt: m.createdAt,
      expiresAt: m.expiresAt,
      maxRequests: m.maxRequests,
      rotationWarningRequests: m.rotationWarningRequests,
      requestCount: m.requestCount ?? 0,
      lastUsedAt: m.lastUsedAt ?? null,
      keyLength: m.keyLength,
      segmentCount: m.segments.length,
    };
  }
}

// ─── Option Validation ────────────────────────────────────────────────────────

/**
 * Validate provision options before passing to generateTumblerMap.
 * Returns an error string if invalid, undefined if valid.
 */
function validateProvisionOptions(options: TumblerMapOptions): string | undefined {
  if (options.keyLength !== undefined) {
    if (!Number.isInteger(options.keyLength) ||
        options.keyLength < MIN_KEY_LENGTH ||
        options.keyLength > MAX_KEY_LENGTH) {
      return `INVALID_KEY_LENGTH: must be integer in [${MIN_KEY_LENGTH}, ${MAX_KEY_LENGTH}]`;
    }
  }
  if (options.minTumblers !== undefined) {
    if (!Number.isInteger(options.minTumblers) || options.minTumblers < MIN_TUMBLERS) {
      return `INVALID_MIN_TUMBLERS: must be integer >= ${MIN_TUMBLERS}`;
    }
  }
  if (options.maxTumblers !== undefined) {
    if (!Number.isInteger(options.maxTumblers) || options.maxTumblers > MAX_TUMBLERS) {
      return `INVALID_MAX_TUMBLERS: must be integer <= ${MAX_TUMBLERS}`;
    }
  }
  if (options.minTumblers !== undefined && options.maxTumblers !== undefined) {
    if (options.minTumblers > options.maxTumblers) {
      return 'INVALID_TUMBLER_RANGE: minTumblers must be <= maxTumblers';
    }
  }
  if (options.allowedWindows !== undefined) {
    if (!Array.isArray(options.allowedWindows) || options.allowedWindows.length === 0) {
      return 'INVALID_ALLOWED_WINDOWS: must be non-empty array';
    }
    for (const w of options.allowedWindows) {
      if (!Number.isInteger(w) || w < MIN_WINDOW_SEC || w > MAX_WINDOW_SEC) {
        return `INVALID_WINDOW_SEC: ${w} must be integer in [${MIN_WINDOW_SEC}, ${MAX_WINDOW_SEC}]`;
      }
    }
  }
  return undefined;
}
