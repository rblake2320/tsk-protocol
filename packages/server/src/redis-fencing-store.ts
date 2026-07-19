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
    const result = await this.redis.eval(
      CLAIM_SCRIPT,
      1,
      this.key,
      String(record.fenceEpoch),
      JSON.stringify(next),
    );
    if (result !== 1) return false;
    if (this.durability) {
      // ENFORCE durable replication to a replica quorum before declaring the claim successful (RPO=0).
      const acked = Number(await this.redis.call('WAIT', String(this.durability.waitReplicas), String(this.durability.waitTimeoutMs)));
      if (!Number.isFinite(acked) || acked < this.durability.waitReplicas) return false; // not durable — fail closed
    }
    return true;
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
