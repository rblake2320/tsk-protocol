import { describe, expect, it, beforeEach } from 'vitest';
import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';

import {
  ContractValidationError,
  canonicalOpDigest,
  streamHeadDigest,
  type HotpMutationSanitizer,
  type OutboxRecord,
  type SanitizedMutation,
  type SignedStreamHead,
  type StreamHeadVerifier,
  type TskHotpMutation,
} from '../src/ha-outbox-contract.js';
import {
  GENESIS_HEAD,
  PgTskReceiverCheckpoint,
  StreamHeadVerificationUnavailableError,
  __unsafeMintReadyTokenForTests,
  type HotpApplier,
  type PgExecutor,
  type PgTransactor,
} from '../src/tsk-hotp-outbox-pg.js';

/** Snapshot-based in-memory transactor (LOGIC only): clone → run → commit on
 *  success, discard on throw. Reports SERIALIZABLE + rowCount so the impl's
 *  isolation + exactly-1 write assertions run. It cannot prove lock/concurrency —
 *  that is the real-PG integration. */
interface Cp { epoch: string; seq: number; head: string }
interface State { fence: Map<string, bigint>; rcv: Map<string, Cp>; applied: Array<{ s: string; e: string; q: number; d: string }>; hotp: Map<string, number> }
class MemoryTskPg implements PgTransactor {
  isolation = 'serializable';
  state: State = { fence: new Map(), rcv: new Map(), applied: [], hotp: new Map() };
  private clone(s: State): State {
    return { fence: new Map(s.fence), rcv: new Map([...s.rcv].map(([k, v]) => [k, { ...v }])), applied: s.applied.map((a) => ({ ...a })), hotp: new Map(s.hotp) };
  }
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>, _opts?: { signal?: AbortSignal }): Promise<T> {
    const work = this.clone(this.state);
    const result = await fn(makeExec(work, this.isolation));
    this.state = work;
    return result;
  }
  provision(streamId: string, epoch = 'e1'): void { this.state.fence.set(streamId, 0n); this.state.rcv.set(streamId, { epoch, seq: 0, head: '' }); }
  setFence(streamId: string, t: bigint): void { this.state.fence.set(streamId, t); }
  rcvOf(streamId: string): Cp { return this.state.rcv.get(streamId)!; }
  hotpOf(streamId: string, tumbler: string): number | undefined { return this.state.hotp.get(`${streamId}|${tumbler}`); }
}
function makeExec(s: State, isolation: string): PgExecutor {
  let pinned = 'public';
  return {
    async query(sql: string, params: unknown[] = []) {
      const P = params as string[];
      const out = (rows: Record<string, unknown>[], rc?: number) => ({ rows, rowCount: rc ?? rows.length });
      if (sql.includes('SHOW transaction_isolation')) return out([{ transaction_isolation: isolation }]);
      if (sql.includes('set_config')) { pinned = P[1]; return out([{ set_config: P[1] }]); }
      if (sql.includes('current_schema()')) return out([{ s: pinned }]);
      if (sql.includes('FROM tsk_outbox_fence')) { const t = s.fence.get(P[0]); return out(t === undefined ? [] : [{ fence_token: t.toString() }]); }
      if (sql.includes('FROM tsk_outbox_receiver_checkpoint')) { const c = s.rcv.get(P[0]); return out(c ? [{ source_epoch: c.epoch, sequence: c.seq, head_digest: c.head }] : []); }
      if (sql.includes('FROM tsk_outbox_applied')) { const a = s.applied.find((x) => x.s === P[0] && x.e === P[1] && x.q === Number(P[2])); return out(a ? [{ op_digest: a.d }] : []); }
      if (sql.includes('FROM tsk_hotp_consumed')) { const v = s.hotp.get(`${P[0]}|${P[1]}`); return out(v === undefined ? [] : [{ last_counter: v }]); }
      if (sql.includes('INSERT INTO tsk_hotp_consumed')) { const k = `${P[0]}|${P[1]}`; const cur = s.hotp.get(k); const nv = Number(P[2]); if (cur === undefined || nv > cur) { s.hotp.set(k, nv); return out([{}], 1); } return out([], 0); }
      if (sql.includes('INSERT INTO tsk_outbox_applied')) { s.applied.push({ s: P[0], e: P[1], q: Number(P[2]), d: P[3] }); return out([{}], 1); }
      if (sql.includes('UPDATE tsk_outbox_receiver_checkpoint')) { const c = s.rcv.get(P[0])!; c.seq = Number(P[1]); c.head = P[2]; return out([{}], 1); }
      throw new Error('unhandled SQL in fake: ' + sql.slice(0, 60));
    },
  };
}

// ── real ed25519 signer/verifier so the signed-head path is genuinely exercised ──
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const KEY_ID = 'tsk-key-1';
const b64u = (b: Buffer) => b.toString('base64url');
const signHead = (headDigest: string) => b64u(edSign(null, Buffer.from(headDigest, 'utf8'), privateKey));
const headVerifier: StreamHeadVerifier = {
  async verify(head) {
    if (head.keyId !== KEY_ID) throw new ContractValidationError('unknown keyId');
    const ok = edVerify(null, Buffer.from(head.headDigest, 'utf8'), publicKey as KeyObject, Buffer.from(head.signature, 'base64url'));
    if (!ok) throw new ContractValidationError('bad stream-head signature');
  },
};
const sanitizer: HotpMutationSanitizer = {
  sanitize(raw) { if (typeof raw.tumblerId !== 'string' || !Number.isInteger(raw.counter)) throw new ContractValidationError('bad'); return { tumblerId: raw.tumblerId, counter: raw.counter } as SanitizedMutation<TskHotpMutation>; },
  assertSanitized(c): asserts c is SanitizedMutation<TskHotpMutation> { if (!c || typeof c !== 'object' || 'secret' in (c as object)) throw new ContractValidationError('unsanitized'); },
};
const applied: string[] = [];
const applier: HotpApplier = { async applyInTx(_e, r) { applied.push(`${r.sequence}:${r.mutation.tumblerId}:${r.mutation.counter}`); } };

const SID = 'tsk:pair:default/v1';
function mkRecordHead(seq: number, mut: TskHotpMutation, prevHead: string, fence = '0', epoch = 'e1'): { record: OutboxRecord<TskHotpMutation>; head: SignedStreamHead } {
  const mutation = { tumblerId: mut.tumblerId, counter: mut.counter } as SanitizedMutation<TskHotpMutation>;
  const opDigest = canonicalOpDigest<TskHotpMutation>({ streamId: SID, sourceEpoch: epoch, sequence: seq, fenceToken: fence, mutation });
  const headDigest = streamHeadDigest({ streamId: SID, sequence: seq, prevHeadDigest: prevHead, opDigest, keyId: KEY_ID, alg: 'ed25519' });
  const head: SignedStreamHead = { streamId: SID, sequence: seq, prevHeadDigest: prevHead, opDigest, keyId: KEY_ID, alg: 'ed25519', headDigest, signature: signHead(headDigest) };
  const record: OutboxRecord<TskHotpMutation> = { contractVersion: '1', streamId: SID, sourceEpoch: epoch, sequence: seq, fenceToken: fence, opDigest, mutation };
  return { record, head };
}

describe('PgTskReceiverCheckpoint — HOTP exactly-once + signed hash-linked head (#10)', () => {
  let db: MemoryTskPg; let rcv: PgTskReceiverCheckpoint;
  const apply = (r: { record: OutboxRecord<TskHotpMutation>; head: SignedStreamHead }) => rcv.verifyAndApplyTumblerDelivered(r.record, r.head);
  beforeEach(() => {
    db = new MemoryTskPg(); db.provision(SID); applied.length = 0;
    rcv = new PgTskReceiverCheckpoint(db, SID, sanitizer, headVerifier, applier, __unsafeMintReadyTokenForTests(db, 'public'));
  });

  it('applies a fresh in-order record; advances checkpoint (seq+head) and consumes the HOTP counter', async () => {
    const r1 = mkRecordHead(1, { tumblerId: 'T1', counter: 5 }, GENESIS_HEAD);
    expect(await apply(r1)).toBe('applied');
    expect(db.rcvOf(SID).seq).toBe(1);
    expect(db.rcvOf(SID).head).toBe(r1.head.headDigest);
    expect(db.hotpOf(SID, 'T1')).toBe(5);
    expect(applied).toEqual(['1:T1:5']);
  });

  it('signed head: a FORGED signature is reject-fork (never applied)', async () => {
    const r = mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD);
    r.head.signature = Buffer.from('forged').toString('base64url');
    expect(await apply(r)).toBe('reject-fork');
    expect(applied.length).toBe(0);
  });

  it('signed head: a TYPED unavailability error retries (re-thrown), does NOT apply/ack/quarantine', async () => {
    const flaky: StreamHeadVerifier = { async verify() { throw new StreamHeadVerificationUnavailableError('HSM offline'); } };
    const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, flaky, applier, __unsafeMintReadyTokenForTests(db, 'public'));
    const r = mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD);
    await expect(r2.verifyAndApplyTumblerDelivered(r.record, r.head)).rejects.toBeInstanceOf(StreamHeadVerificationUnavailableError);
    expect(db.rcvOf(SID).seq).toBe(0); // not applied, not rejected — retry
    expect(applied.length).toBe(0);
  });

  it('signed head: an UNKNOWN/untyped verifier exception FAILS CLOSED (reject-fork, no ack, no retry loop)', async () => {
    const chaos: StreamHeadVerifier = { async verify() { throw new TypeError('unexpected boom'); } };
    const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, chaos, applier, __unsafeMintReadyTokenForTests(db, 'public'));
    const r = mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD);
    expect(await r2.verifyAndApplyTumblerDelivered(r.record, r.head)).toBe('reject-fork');
    expect(db.rcvOf(SID).seq).toBe(0);
    expect(applied.length).toBe(0);
  });

  it('signed head: a swapped keyId or alg is rejected (unknown key -> reject-fork; unknown alg -> reject-fork)', async () => {
    const good = mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD);
    // wrong keyId: headVerifier throws unknown keyId -> permanent reject-fork
    const wrongKey = { record: good.record, head: { ...good.head, keyId: 'attacker-key' } };
    expect(await apply(wrongKey)).toBe('reject-fork');
    // swapped alg: headDigest binds alg, so ecdsa alg makes the digest mismatch -> reject-fork at binding
    const swappedAlg = { record: good.record, head: { ...good.head, alg: 'ecdsa-p256-sha256' as const } };
    expect(await apply(swappedAlg)).toBe('reject-fork');
    expect(applied.length).toBe(0);
  });

  it('hash-chain continuity: a broken prevHeadDigest link is reject-fork', async () => {
    expect(await apply(mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD))).toBe('applied');
    // seq 2 whose prevHeadDigest does NOT equal the receiver's last head
    const bad = mkRecordHead(2, { tumblerId: 'T1', counter: 2 }, 'a'.repeat(64));
    expect(await apply(bad)).toBe('reject-fork');
    expect(db.rcvOf(SID).seq).toBe(1);
  });

  it('HOTP exactly-once: a replayed/re-used counter for a tumbler is reject-fork (no double-consume)', async () => {
    const r1 = mkRecordHead(1, { tumblerId: 'T1', counter: 10 }, GENESIS_HEAD);
    expect(await apply(r1)).toBe('applied');
    // seq 2, same tumbler, counter <= consumed (10) -> replay
    const replay = mkRecordHead(2, { tumblerId: 'T1', counter: 10 }, r1.head.headDigest);
    expect(await apply(replay)).toBe('reject-fork');
    const lower = mkRecordHead(2, { tumblerId: 'T1', counter: 3 }, r1.head.headDigest);
    expect(await apply(lower)).toBe('reject-fork');
    expect(db.hotpOf(SID, 'T1')).toBe(10); // unchanged
  });

  it('HOTP strictly-increasing (non-contiguous) counters advance; a different tumbler is independent', async () => {
    const r1 = mkRecordHead(1, { tumblerId: 'T1', counter: 10 }, GENESIS_HEAD);
    expect(await apply(r1)).toBe('applied');
    const r2 = mkRecordHead(2, { tumblerId: 'T1', counter: 25 }, r1.head.headDigest); // jump ok
    expect(await apply(r2)).toBe('applied');
    expect(db.hotpOf(SID, 'T1')).toBe(25);
    const r3 = mkRecordHead(3, { tumblerId: 'T2', counter: 1 }, r2.head.headDigest); // independent tumbler
    expect(await apply(r3)).toBe('applied');
    expect(db.hotpOf(SID, 'T2')).toBe(1);
  });

  it('tampered payload with preserved opDigest is reject-fork; head-binding mismatch is reject-fork', async () => {
    const good = mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD);
    const tampered = { record: { ...good.record, mutation: { tumblerId: 'HACK', counter: 1 } as SanitizedMutation<TskHotpMutation> }, head: good.head };
    expect(await apply(tampered)).toBe('reject-fork');
    const mismatch = { record: good.record, head: { ...good.head, opDigest: 'b'.repeat(64) } };
    expect(await apply(mismatch)).toBe('reject-fork');
  });

  it('fence exact-equality: future, stale, and missing all reject-fence', async () => {
    db.setFence(SID, 3n);
    expect(await apply(mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD, '5'))).toBe('reject-fence');
    expect(await apply(mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD, '2'))).toBe('reject-fence');
    db.state.fence.delete(SID);
    expect(await apply(mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD, '0'))).toBe('reject-fence');
  });

  it('ordering: gap, epoch, duplicate-ok, and older-fork', async () => {
    const r1 = mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD);
    expect(await apply(r1)).toBe('applied');
    expect(await apply(mkRecordHead(3, { tumblerId: 'T1', counter: 2 }, r1.head.headDigest))).toBe('reject-gap');
    const otherEpoch = mkRecordHead(2, { tumblerId: 'T1', counter: 2 }, r1.head.headDigest, '0', 'e9');
    expect(await apply(otherEpoch)).toBe('reject-epoch');
    expect(await apply(r1)).toBe('duplicate-ok'); // same seq+digest replayed
    const olderFork = mkRecordHead(1, { tumblerId: 'T1', counter: 99 }, GENESIS_HEAD);
    // seq1 already applied with a different opDigest (different counter) -> fork
    expect(await apply(olderFork)).toBe('reject-fork');
  });
});
