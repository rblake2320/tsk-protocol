/**
 * TSK Protocol — Anomaly Detection
 *
 * Analyzes per-segment validation failures to distinguish:
 * - Clock drift (TOTP segment off by one window) → benign
 * - Stolen key replay (some segments correct, some wrong) → suspicious
 * - Mass replay flood (many failures from same client) → attack
 *
 * Segment failure patterns are the key intelligence TSK adds beyond BPC:
 * if an attacker intercepts a key and replays it, the rotating segments will
 * be wrong (expired) while the static segment may still match. This asymmetric
 * failure pattern is a strong stolen-key indicator.
 */

export interface SegmentFailureEvent {
  clientId: string;
  timestamp: number;
  segmentResults: { segmentId: string; valid: boolean }[];
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

export class MemoryAnomalyEngine implements AnomalyEngine {
  private failures = new Map<string, SegmentFailureEvent[]>();
  private windowMs: number;

  constructor(windowMs = 5 * 60 * 1000) { // 5-minute rolling window
    this.windowMs = windowMs;
  }

  record(event: SegmentFailureEvent): void {
    const events = this.failures.get(event.clientId) ?? [];
    events.push(event);
    // Trim to window
    const cutoff = Date.now() - this.windowMs;
    this.failures.set(
      event.clientId,
      events.filter(e => e.timestamp > cutoff),
    );
  }

  score(clientId: string): AnomalyScore {
    const events = this.failures.get(clientId) ?? [];
    const reasons: string[] = [];
    let score = 0;

    if (events.length === 0) {
      return { score: 0, verdict: 'clean', reasons: [] };
    }

    // High failure rate
    if (events.length >= 10) {
      score += 40;
      reasons.push(`${events.length} failures in rolling window`);
    } else if (events.length >= 3) {
      score += 15;
      reasons.push(`${events.length} failures in rolling window`);
    }

    // Stolen key pattern: static segment passes, rotating segments fail
    const stolenKeyEvents = events.filter(e => {
      const staticPassed = e.segmentResults.some(sr =>
        sr.segmentId.startsWith('id_') && sr.valid
      );
      const rotatingFailed = e.segmentResults.some(sr =>
        !sr.segmentId.startsWith('id_') && !sr.valid
      );
      return staticPassed && rotatingFailed;
    });

    if (stolenKeyEvents.length >= 2) {
      score += 50;
      reasons.push(`Stolen key pattern: ${stolenKeyEvents.length} events with static match + rotating failure`);
    } else if (stolenKeyEvents.length === 1) {
      score += 20;
      reasons.push('Possible stolen key pattern detected');
    }

    // All segments failing (wrong client entirely, or brute force)
    const totalFailures = events.filter(e =>
      e.segmentResults.every(sr => !sr.valid)
    );
    if (totalFailures.length >= 3) {
      score += 30;
      reasons.push('Repeated total failures (brute force or wrong client)');
    }

    const verdict: AnomalyScore['verdict'] =
      score >= 70 ? 'attack' :
      score >= 30 ? 'suspicious' :
      'clean';

    return { score: Math.min(score, 100), verdict, reasons };
  }

  reset(clientId: string): void {
    this.failures.delete(clientId);
  }
}
