/** Redis-backed, cross-process fencing authority. */
import type { Redis } from 'ioredis';
import type { FenceRecord, FencingStore } from './promotion.js';

const CLAIM_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if current then
  local ok, record = pcall(cjson.decode, current)
  if not ok or type(record) ~= 'table' or type(record.fenceEpoch) ~= 'number' then
    return redis.error_reply('TSK_FENCE_RECORD_CORRUPT')
  end
  if record.fenceEpoch >= tonumber(ARGV[1]) then return 0 end
end
redis.call('SET', KEYS[1], ARGV[2])
return 1
`;

const RELEASE_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if not current then return 0 end
local ok, record = pcall(cjson.decode, current)
if not ok or type(record) ~= 'table' then
  return redis.error_reply('TSK_FENCE_RECORD_CORRUPT')
end
if record.active ~= true or record.nodeId ~= ARGV[1] or
   record.fenceEpoch ~= tonumber(ARGV[2]) or record.commandId ~= ARGV[3] then
  return 0
end
record.active = false
redis.call('SET', KEYS[1], cjson.encode(record))
return 1
`;

function parseFenceRecord(raw: string): FenceRecord {
  let value: unknown;
  try { value = JSON.parse(raw); }
  catch { throw new Error('TSK_FENCE_RECORD_CORRUPT'); }
  if (!value || typeof value !== 'object') throw new Error('TSK_FENCE_RECORD_CORRUPT');
  const record = value as Partial<FenceRecord>;
  if (typeof record.nodeId !== 'string' || record.nodeId.length === 0 ||
      !Number.isSafeInteger(record.fenceEpoch) || (record.fenceEpoch ?? 0) < 1 ||
      !Number.isSafeInteger(record.expiresAt) || (record.expiresAt ?? 0) < 0 ||
      typeof record.commandId !== 'string' || record.commandId.length === 0 ||
      typeof record.active !== 'boolean') {
    throw new Error('TSK_FENCE_RECORD_CORRUPT');
  }
  return record as FenceRecord;
}

/**
 * A fencing store whose claim/release transitions execute atomically in Redis.
 *
 * The record intentionally has no Redis TTL. Expired leases remain as epoch
 * tombstones so an older command can never become current after key expiry.
 * Redis persistence, replication, ACLs, TLS, and availability remain deployment
 * responsibilities and must be tested for the selected topology.
 */
/** Durable-claim policy: after the epoch CAS SET, require `waitReplicas` replicas to ACK the write
 *  (Redis WAIT) within `waitTimeoutMs` before the claim is reported successful. This makes RPO=0 an
 *  ENFORCED property of the claim path (not a caller-side WAIT): a claim that a replica quorum did not
 *  durably receive fails closed, so a subsequent Sentinel failover cannot roll the fence epoch back. */
export interface FenceDurabilityPolicy { waitReplicas: number; waitTimeoutMs: number }

/** Thrown when the epoch CAS SET SUCCEEDED (the fence epoch was raised on the current master) but the
 *  configured replica quorum did NOT ACK within the WAIT window — so the write's DURABILITY is UNKNOWN.
 *  This is DISTINCT from an ordinary `claim() === false` (CAS refused because the epoch was not higher):
 *  here the write happened, so the caller must RECONCILE against `storedTuple` and fail closed, never
 *  treat it as a clean "not acquired". Carries the exact stored record for reconciliation. */
export class FenceDurabilityUncertainError extends Error {
  constructor(readonly acked: number, readonly required: number, readonly storedTuple: FenceRecord | null) {
    super(`fence epoch CAS wrote but only ${acked}/${required} replicas ACK'd — durability UNCERTAIN; reconcile and fail closed`);
    this.name = 'FenceDurabilityUncertainError';
  }
}

export class RedisFencingStore implements FencingStore {
  constructor(
    private readonly redis: Redis,
    private readonly key = 'tsk:fencing:writer',
    private readonly durability?: FenceDurabilityPolicy,
  ) {
    if (!key || key.length > 512) throw new Error('Redis fencing key must be 1..512 characters');
    if (durability && (!Number.isInteger(durability.waitReplicas) || durability.waitReplicas < 1 || !Number.isInteger(durability.waitTimeoutMs) || durability.waitTimeoutMs < 1)) {
      throw new Error('FenceDurabilityPolicy requires waitReplicas>=1 and waitTimeoutMs>=1');
    }
  }

  async current(): Promise<FenceRecord | null> {
    const raw = await this.redis.get(this.key);
    return raw === null ? null : parseFenceRecord(raw);
  }

  async claim(record: Omit<FenceRecord, 'active'>): Promise<boolean> {
    const next: FenceRecord = { ...record, active: true };
    parseFenceRecord(JSON.stringify(next));
    if (!this.durability) {
      const result = await this.redis.eval(CLAIM_SCRIPT, 1, this.key, String(record.fenceEpoch), JSON.stringify(next));
      return result === 1; // CAS refused (0) or acquired (1); no durability enforcement configured.
    }
    // DURABLE path. Redis WAIT tracks the writes of the CURRENT CONNECTION (per-client replication offset),
    // so WAIT is only meaningful on the SAME physical connection that ran the CAS. A shared, auto-reconnecting
    // Sentinel client is INSUFFICIENT: ioredis can RESEND/REPLAY un-replied commands on a freshly promoted
    // master, so WAIT (or a replayed EVAL) could bind a different server whose offset does not cover the CAS.
    // So we acquire a DEDICATED physical connection to the CURRENT master with ALL reconnect/retry/resend
    // DISABLED, dispatch EVAL then WAIT on that ONE socket, and treat ANY disconnect/rejection AFTER the CAS
    // was dispatched as DURABILITY-UNKNOWN → typed uncertainty (never a silent success or ordinary false).
    // The connection is closed at the end. A pre-dispatch connect failure is propagated (the claim never
    // started — the caller retries / fails closed).
    const { waitReplicas, waitTimeoutMs } = this.durability;
    const conn = this.redis.duplicate({
      lazyConnect: true,
      enableOfflineQueue: false,            // no queueing while disconnected — a dropped command rejects
      maxRetriesPerRequest: 0,              // never retry a request on another connection
      retryStrategy: () => null,            // never reconnect the data socket
      reconnectOnError: () => false,
      autoResendUnfulfilledCommands: false, // never REPLAY the un-replied EVAL/WAIT on a new master
      role: 'master',
    } as Record<string, unknown>) as unknown as {
      connect(): Promise<unknown>; disconnect(): void;
      eval(...a: unknown[]): Promise<unknown>; call(...a: unknown[]): Promise<unknown>;
    };
    const uncertain = async (acked: number): Promise<never> => {
      let stored: FenceRecord | null = null;
      try { stored = await this.current(); } catch { stored = null; }
      throw new FenceDurabilityUncertainError(acked, waitReplicas, stored);
    };
    try {
      await conn.connect(); // pre-dispatch: resolve the current master + open ONE socket; failure propagates.
      let casRes: unknown;
      try { casRes = await conn.eval(CLAIM_SCRIPT, 1, this.key, String(record.fenceEpoch), JSON.stringify(next)); }
      catch { return uncertain(0); }        // dropped during/after EVAL dispatch → the CAS may have applied
      if (casRes !== 1) return false;        // CAS refused (epoch not strictly higher) — ordinary durable no-op
      // the CAS WROTE on THIS socket. WAIT on the SAME socket binds this connection's offset (covers the CAS).
      let acked: number;
      try { acked = Number(await conn.call('WAIT', String(waitReplicas), String(waitTimeoutMs))); }
      catch { return uncertain(0); }         // dropped during/after WAIT dispatch → durability UNKNOWN
      if (!Number.isFinite(acked) || acked < waitReplicas) return uncertain(acked);
      return true;
    } finally {
      try { conn.disconnect(); } catch { /* already closed */ }
    }
  }

  async release(nodeId: string, fenceEpoch: number, commandId: string): Promise<boolean> {
    const result = await this.redis.eval(
      RELEASE_SCRIPT,
      1,
      this.key,
      nodeId,
      String(fenceEpoch),
      commandId,
    );
    return result === 1;
  }
}
