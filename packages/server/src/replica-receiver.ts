/**
 * TSK replica receiver — the inverse of ReplicatingTumblerStore.
 *
 * Ingests replicated TumblerReplicaOps into the replica node's local
 * TumblerMapStore. Framework-agnostic: the transport calls authorizeReplica()
 * then applyTumblerOp() (or the all-in-one handleTumblerIngest()).
 *
 *  RX-01 Constant-time token auth (see authorizeReplica).
 *
 *  RX-02 Idempotent application:
 *    Replication is at-least-once. set/delete/updateCounters are absolute.
 *    consumeCounter is monotonic: replaying the same matchedCounter after the
 *    counter has already advanced is rejected by the store's CAS (no double
 *    advance), so re-delivery is safe.
 *
 *  RX-03 Tier-aware secret handling (TSK is symmetric — see HA-03′):
 *    The receiver only STORES what it was sent. Under the strip default the map
 *    arrives with sharedSecret='' (metadata only). Under the sealer opt-in it
 *    arrives sealed. The receiver NEVER unseals here — decryption (if any) and
 *    validation happen later, at failover-validation time, gated by
 *    validateOnFailover. Ingest is therefore tier-independent.
 *
 *  RX-04 Strict op validation; malformed ops are rejected, never partially
 *    applied. Map updates are reconstructed from wire entries.
 *
 * NIST SP 800-53 Rev 5: AU-9, SC-8, SC-28, SI-10.
 */
import { timingSafeEqual } from 'node:crypto';
import type { TumblerMapStore } from './store.js';
import type { TumblerReplicaOp } from './replicating-tumbler-store.js';
import type { TumblerMap } from '@tsk/core';

const MAX_CLIENT_ID_LEN = 128;
const MAX_TOKEN_LEN = 256;

export interface TumblerApplyResult {
  ok: boolean;
  error?: string;
}

/** Constant-time comparison of the presented replica token against the expected one. */
export function authorizeReplica(
  headers: Record<string, string | string[] | undefined>,
  expectedToken: string,
): boolean {
  const raw = headers['x-replica-token'];
  const presented = Array.isArray(raw) ? raw[0] : raw;
  if (!presented || typeof presented !== 'string') return false;
  if (presented.length > MAX_TOKEN_LEN || expectedToken.length > MAX_TOKEN_LEN) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(expectedToken);
  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

function isValidClientId(id: unknown): id is string {
  return typeof id === 'string' && id.length > 0 && id.length <= MAX_CLIENT_ID_LEN;
}

function isEntryArray(v: unknown): v is Array<[string, number]> {
  return Array.isArray(v) && v.every(
    (e) => Array.isArray(e) && e.length === 2 && typeof e[0] === 'string' && typeof e[1] === 'number',
  );
}

/** Validate the op envelope shape before touching the store (RX-04). */
export function validateTumblerOp(
  body: unknown,
): { ok: true; op: TumblerReplicaOp } | { ok: false; error: string } {
  if (!body || typeof body !== 'object') return { ok: false, error: 'invalid_body' };
  const op = (body as { op?: unknown }).op;
  switch (op) {
    case 'set': {
      const { clientId, map, secretSealed } = body as { clientId?: unknown; map?: unknown; secretSealed?: unknown };
      if (!isValidClientId(clientId)) return { ok: false, error: 'invalid_set_clientId' };
      if (!map || typeof map !== 'object' || (map as TumblerMap).clientId !== clientId) {
        return { ok: false, error: 'invalid_set_map' };
      }
      return { ok: true, op: { op: 'set', clientId, map: map as TumblerMap, secretSealed: secretSealed === true } };
    }
    case 'delete': {
      const clientId = (body as { clientId?: unknown }).clientId;
      if (!isValidClientId(clientId)) return { ok: false, error: 'invalid_delete' };
      return { ok: true, op: { op: 'delete', clientId } };
    }
    case 'updateCounters': {
      const { clientId, updates } = body as { clientId?: unknown; updates?: unknown };
      if (!isValidClientId(clientId)) return { ok: false, error: 'invalid_update_clientId' };
      if (!isEntryArray(updates)) return { ok: false, error: 'invalid_update_entries' };
      return { ok: true, op: { op: 'updateCounters', clientId, updates } };
    }
    case 'consumeCounter': {
      const { clientId, segmentId, matchedCounter } = body as {
        clientId?: unknown; segmentId?: unknown; matchedCounter?: unknown;
      };
      if (!isValidClientId(clientId)) return { ok: false, error: 'invalid_consume_clientId' };
      if (typeof segmentId !== 'string' || segmentId.length === 0) return { ok: false, error: 'invalid_consume_segmentId' };
      if (typeof matchedCounter !== 'number' || !Number.isFinite(matchedCounter)) {
        return { ok: false, error: 'invalid_consume_counter' };
      }
      return { ok: true, op: { op: 'consumeCounter', clientId, segmentId, matchedCounter } };
    }
    default:
      return { ok: false, error: 'unknown_op' };
  }
}

/** Apply a validated op to the replica store. Idempotent (RX-02). */
export async function applyTumblerOp(store: TumblerMapStore, op: TumblerReplicaOp): Promise<TumblerApplyResult> {
  try {
    switch (op.op) {
      case 'set':
        await store.set(op.clientId, op.map);
        return { ok: true };
      case 'delete':
        await store.delete(op.clientId);
        return { ok: true };
      case 'updateCounters':
        // RX-04: reconstruct the JS Map the store API expects from wire entries.
        await store.updateCounters(op.clientId, new Map(op.updates));
        return { ok: true };
      case 'consumeCounter':
        if (!store.consumeCounter) return { ok: false, error: 'consume_unsupported' };
        await store.consumeCounter(op.clientId, op.segmentId, op.matchedCounter);
        return { ok: true };
      default:
        return { ok: false, error: 'unknown_op' };
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'apply_failed' };
  }
}

/**
 * One-call convenience: authorize + validate + apply. Returns an HTTP-ish
 * status so the transport layer can map it directly.
 */
export async function handleTumblerIngest(
  store: TumblerMapStore,
  headers: Record<string, string | string[] | undefined>,
  body: unknown,
  expectedToken: string,
): Promise<{ status: number; result: TumblerApplyResult }> {
  if (!authorizeReplica(headers, expectedToken)) {
    return { status: 401, result: { ok: false, error: 'unauthorized' } };
  }
  const validated = validateTumblerOp(body);
  if (!validated.ok) {
    return { status: 400, result: { ok: false, error: validated.error } };
  }
  const result = await applyTumblerOp(store, validated.op);
  return { status: result.ok ? 200 : 500, result };
}
