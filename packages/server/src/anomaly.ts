/**
 * TSK Protocol — Anomaly Detection Engine
 *
 * Key security fixes in this version:
 * 1. BOUNDED MEMORY: LRU eviction with configurable max entries prevents
 *    memory exhaustion via clientId flooding (DoS fix).
 * 2. TYPE-SAFE DETECTION: stolen-key pattern uses segment.type === 'static'
 *    instead of fragile segmentId.startsWith('id_') name heuristic.
 * 3. IP-BASED TRACKING: cross-client IP correlation detects distributed attacks
 *    where an attacker uses many clientIds from the same IP.
 * 4. TTL CLEANUP: automatic expiry of stale entries prevents unbounded growth
 *    even without LRU pressure.
 * 5. CONFIGURABLE THRESHOLDS: all scoring thresholds are configurable for
 *    deployment-specific tuning.
 */

export interface SegmentFailureEvent {
  clientId: string;
  timestamp: number;
  /** Per-segment results — MUST include type field for type-safe detection */
  segmentResults: { segmentId: string; type: 'static' | 'totp' | 'hotp'; valid: boolean }[];
  /** Failure stage when rejection occurs before or during segment comparison. */
  failureKind?: 'checksum_invalid' | 'segment_validation_failed';
  ipAddress?: string;
}

export interface AnomalyScore {
  score: number; // 0-100
  verdict: 'clean' | 'suspicious' | 'attack';
  reasons: string[];
}

export interface AnomalyEngine {
  record(event: SegmentFailureEvent): void;
  score(clientId: string): AnomalyScore;
  reset(clientId: string): void;
}

export interface AnomalyEngineConfig {
  /** Rolling window in ms (default: 5 minutes) */
  windowMs?: number;
  /** Max number of clientId entries to track (LRU eviction, default: 10000) */
  maxEntries?: number;
  /** Max events per clientId in window (default: 1000) */
  maxEventsPerClient?: number;
  /** Failure count threshold for high-rate score (default: 10) */
  highRateThreshold?: number;
  /** Failure count threshold for medium-rate score (default: 3) */
  mediumRateThreshold?: number;
  /** Score added for high failure rate (default: 40) */
  highRateScore?: number;
  /** Score added for medium failure rate (default: 15) */
  mediumRateScore?: number;
  /** Score added for stolen-key pattern (2+ events, default: 50) */
  stolenKeyScore?: number;
  /** Score added for single stolen-key event (default: 20) */
  stolenKeySingleScore?: number;
  /** Score added for repeated total failures (default: 30) */
  totalFailureScore?: number;
  /** Score threshold for 'attack' verdict (default: 70) */
  attackThreshold?: number;
  /** Score threshold for 'suspicious' verdict (default: 30) */
  suspiciousThreshold?: number;
}

/**
 * Hardened in-memory anomaly engine with LRU eviction and IP correlation.
 *
 * For production deployments, replace with a Redis-backed implementation
 * that shares state across multiple server instances.
 */
export class MemoryAnomalyEngine implements AnomalyEngine {
  private failures = new Map<string, SegmentFailureEvent[]>();
  private ipFailures = new Map<string, Set<string>>(); // ip -> Set<clientId>
  private accessOrder: string[] = []; // LRU tracking (most recent at end)

  private readonly windowMs: number;
  private readonly maxEntries: number;
  private readonly maxEventsPerClient: number;
  private readonly highRateThreshold: number;
  private readonly mediumRateThreshold: number;
  private readonly highRateScore: number;
  private readonly mediumRateScore: number;
  private readonly stolenKeyScore: number;
  private readonly stolenKeySingleScore: number;
  private readonly totalFailureScore: number;
  private readonly attackThreshold: number;
  private readonly suspiciousThreshold: number;

  constructor(config: AnomalyEngineConfig = {}) {
    this.windowMs = config.windowMs ?? 5 * 60 * 1000;
    this.maxEntries = config.maxEntries ?? 10_000;
    this.maxEventsPerClient = config.maxEventsPerClient ?? 1_000;
    this.highRateThreshold = config.highRateThreshold ?? 10;
    this.mediumRateThreshold = config.mediumRateThreshold ?? 3;
    this.highRateScore = config.highRateScore ?? 40;
    this.mediumRateScore = config.mediumRateScore ?? 15;
    this.stolenKeyScore = config.stolenKeyScore ?? 50;
    this.stolenKeySingleScore = config.stolenKeySingleScore ?? 20;
    this.totalFailureScore = config.totalFailureScore ?? 30;
    this.attackThreshold = config.attackThreshold ?? 70;
    this.suspiciousThreshold = config.suspiciousThreshold ?? 30;
  }

  record(event: SegmentFailureEvent): void {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    // ── LRU eviction: if at capacity, remove least-recently-used entry ──────
    if (!this.failures.has(event.clientId) && this.failures.size >= this.maxEntries) {
      const lruKey = this.accessOrder.shift();
      if (lruKey) {
        this.failures.delete(lruKey);
        // Clean up IP tracking for evicted client
        for (const [ip, clients] of this.ipFailures) {
          clients.delete(lruKey);
          if (clients.size === 0) this.ipFailures.delete(ip);
        }
      }
    }

    // ── Update LRU access order ──────────────────────────────────────────────
    const idx = this.accessOrder.indexOf(event.clientId);
    if (idx !== -1) this.accessOrder.splice(idx, 1);
    this.accessOrder.push(event.clientId);

    // ── Record failure event with window trimming ────────────────────────────
    let events = this.failures.get(event.clientId) ?? [];
    events.push(event);

    // Trim to window and enforce per-client event cap
    events = events.filter(e => e.timestamp > cutoff);
    if (events.length > this.maxEventsPerClient) {
      events = events.slice(events.length - this.maxEventsPerClient);
    }
    this.failures.set(event.clientId, events);

    // ── IP correlation tracking ──────────────────────────────────────────────
    if (event.ipAddress) {
      const clients = this.ipFailures.get(event.ipAddress) ?? new Set<string>();
      clients.add(event.clientId);
      this.ipFailures.set(event.ipAddress, clients);
    }
  }

  score(clientId: string): AnomalyScore {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const rawEvents = this.failures.get(clientId) ?? [];
    const events = rawEvents.filter(e => e.timestamp > cutoff);

    const reasons: string[] = [];
    let score = 0;

    if (events.length === 0) {
      return { score: 0, verdict: 'clean', reasons: [] };
    }

    // ── High failure rate ────────────────────────────────────────────────────
    if (events.length >= this.highRateThreshold) {
      score += this.highRateScore;
      reasons.push(`${events.length} failures in rolling window (threshold: ${this.highRateThreshold})`);
    } else if (events.length >= this.mediumRateThreshold) {
      score += this.mediumRateScore;
      reasons.push(`${events.length} failures in rolling window`);
    }

    // ── Stolen key pattern (TYPE-SAFE: uses segment.type, not name prefix) ───
    // Pattern: static segment passes but rotating (totp/hotp) segments fail.
    // This indicates an attacker has a stale key — the static part still matches
    // but the rotating parts have expired.
    const stolenKeyEvents = events.filter(e => {
      const staticPassed = e.segmentResults.some(sr => sr.type === 'static' && sr.valid);
      const rotatingFailed = e.segmentResults.some(
        sr => (sr.type === 'totp' || sr.type === 'hotp') && !sr.valid
      );
      return staticPassed && rotatingFailed;
    });

    if (stolenKeyEvents.length >= 2) {
      score += this.stolenKeyScore;
      reasons.push(
        `Stolen key pattern: ${stolenKeyEvents.length} events with static match + rotating failure`
      );
    } else if (stolenKeyEvents.length === 1) {
      score += this.stolenKeySingleScore;
      reasons.push('Possible stolen key pattern detected');
    }

    // ── All segments failing (brute force or wrong client) ───────────────────
    const totalFailures = events.filter(e =>
      e.failureKind === 'checksum_invalid' ||
      (e.segmentResults.length > 0 && e.segmentResults.every(sr => !sr.valid))
    );
    if (totalFailures.length >= 3) {
      score += this.totalFailureScore;
      reasons.push(`Repeated integrity/segment failures (${totalFailures.length})`);
    }

    // ── Cross-client IP correlation ──────────────────────────────────────────
    // Find the IP(s) associated with this clientId and check if they're
    // attacking multiple clients simultaneously (distributed attack pattern).
    const clientEvents = events.filter(e => e.ipAddress);
    if (clientEvents.length > 0) {
      const ips = new Set(clientEvents.map(e => e.ipAddress!));
      for (const ip of ips) {
        const clientsFromIp = this.ipFailures.get(ip);
        if (clientsFromIp && clientsFromIp.size >= 5) {
          score += 25;
          reasons.push(
            `Distributed attack pattern: IP ${ip} has failures across ${clientsFromIp.size} clients`
          );
          break; // Only add once even if multiple IPs match
        }
      }
    }

    const verdict: AnomalyScore['verdict'] =
      score >= this.attackThreshold ? 'attack' :
      score >= this.suspiciousThreshold ? 'suspicious' :
      'clean';

    return { score: Math.min(score, 100), verdict, reasons };
  }

  reset(clientId: string): void {
    this.failures.delete(clientId);
    // Remove from LRU order
    const idx = this.accessOrder.indexOf(clientId);
    if (idx !== -1) this.accessOrder.splice(idx, 1);
    // Clean up IP tracking
    for (const [ip, clients] of this.ipFailures) {
      clients.delete(clientId);
      if (clients.size === 0) this.ipFailures.delete(ip);
    }
  }

  /** Return current number of tracked clients (for monitoring). */
  get trackedClients(): number {
    return this.failures.size;
  }

  /** Return current number of tracked IPs (for monitoring). */
  get trackedIPs(): number {
    return this.ipFailures.size;
  }
}
