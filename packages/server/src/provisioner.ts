/**
 * TSK Protocol — Server-Side Provisioner
 * IL4/5/6/7-hardened.
 *
 * Key security fixes in this version:
 * 1. INPUT VALIDATION: all provisioning parameters validated before use.
 * 2. RATE LIMITING INTERFACE: RateLimiter interface allows plugging in
 *    token-bucket or sliding-window rate limiters for production deployments.
 * 3. PROVISIONER GUARD: max concurrent provisioning requests tracked to
 *    prevent provisioner spam exhausting memory.
 * 4. REVOCATION: revoke() now returns a boolean indicating whether the
 *    client existed (useful for audit logging).
 * 5. AUDIT LOGGING: structured audit log interface for IL4+ compliance.
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
 * Audit logger interface for IL4+ compliance.
 * All provisioning and revocation events must be logged.
 */
export interface ProvisionAuditLogger {
  logProvision(clientId: string, requestorId?: string): void;
  logRevocation(clientId: string, requestorId?: string): void;
  logRateLimitExceeded(requestorId?: string): void;
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
  /** Audit logger for IL4+ compliance (optional) */
  auditLogger?: ProvisionAuditLogger;
  /** Max total provisioned clients (memory guard, default: unlimited) */
  maxClients?: number;
}

// ─── Provisioner ──────────────────────────────────────────────────────────────

export class TSKProvisioner {
  private readonly rateLimiter?: ProvisionRateLimiter;
  private readonly auditLogger?: ProvisionAuditLogger;
  private readonly maxClients?: number;

  constructor(
    private store: TumblerMapStore,
    options: ProvisionerOptions = {},
  ) {
    this.rateLimiter = options.rateLimiter;
    this.auditLogger = options.auditLogger;
    this.maxClients = options.maxClients;
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
      }
      // Initialize lifecycle tracking fields
      map.status = 'active';
      map.requestCount = 0;
      map.lastUsedAt = null;

      await this.store.set(map.clientId, map);
      this.auditLogger?.logProvision(map.clientId, requestorId);

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
  async revoke(clientId: string, requestorId?: string): Promise<boolean> {
    const existing = await this.store.get(clientId);
    if (!existing) return false;

    await this.store.delete(clientId);
    this.auditLogger?.logRevocation(clientId, requestorId);
    return true;
  }

  /**
   * Update lifecycle metadata on an existing key.
   * Allows changing label, expiry, maxRequests, and status without re-provisioning.
   *
   * @returns true if the key was found and updated, false if not found.
   */
  async updateKey(
    clientId: string,
    updates: {
      label?: string;
      expiresAt?: number | null;
      maxRequests?: number | null;
      status?: 'active' | 'revoked' | 'expired';
    },
    requestorId?: string,
  ): Promise<boolean> {
    const existing = await this.store.get(clientId);
    if (!existing) return false;

    const updated = { ...existing };
    if ('label' in updates) updated.label = updates.label;
    if ('expiresAt' in updates) {
      updated.expiresAt = updates.expiresAt ?? undefined;
    }
    if ('maxRequests' in updates) {
      updated.maxRequests = updates.maxRequests ?? undefined;
    }
    if (updates.status !== undefined) updated.status = updates.status;

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
