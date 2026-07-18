import { describe, expect, it, beforeEach } from 'vitest';
import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

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
  provisionSchemaVersion,
  type HotpApplier,
  type PgExecutor,
  type PgTransactor,
  type SchemaReadyToken,
} from '../src/tsk-hotp-outbox-pg.js';

// Real catalog rows captured from a provisioned PostgreSQL 16, replayed by the
// fake transactor so attestation GENUINELY runs — the tests obtain a real
// readiness token exactly like production (no unsafe test-only mint ships).
const CATALOG = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'tsk-manifest-catalog.fixture.json'), 'utf8')) as {
  cols: Record<string, unknown>[]; cons: Record<string, unknown>[]; idx: Record<string, unknown>[]; rel: Record<string, unknown>[]; trig: Record<string, unknown>[]; pol: Record<string, unknown>[];
};

/** Snapshot-based in-memory transactor (LOGIC only): clone → run → commit on
 *  success, discard on throw. Reports SERIALIZABLE + rowCount so the impl's
 *  isolation + exactly-1 write assertions run. It cannot prove lock/concurrency —
 *  that is the real-PG integration. */
interface Cp { epoch: string; seq: number; head: string }
interface State { fence: Map<string, bigint>; rcv: Map<string, Cp>; applied: Array<{ s: string; e: string; q: number; d: string }>; hotp: Map<string, number>; meta: number | null }
class MemoryTskPg implements PgTransactor {
  isolation = 'serializable';
  state: State = { fence: new Map(), rcv: new Map(), applied: [], hotp: new Map(), meta: null };
  private clone(s: State): State {
    return { fence: new Map(s.fence), rcv: new Map([...s.rcv].map(([k, v]) => [k, { ...v }])), applied: s.applied.map((a) => ({ ...a })), hotp: new Map(s.hotp), meta: s.meta };
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
      if (sql.includes('current_schema() AS s')) return out([{ s: pinned }]);
      // ── genuine attestation: replay the captured real catalog so schemaManifest()
      //    computes the real manifest and attestSchema() truly runs (no unsafe mint) ──
      if (sql.includes('information_schema.columns')) return out(CATALOG.cols);
      if (sql.includes('pg_get_constraintdef')) return out(CATALOG.cons);
      if (sql.includes('pg_indexes')) return out(CATALOG.idx);
      if (sql.includes('pg_get_triggerdef')) return out(CATALOG.trig);
      if (sql.includes('pg_policy')) return out(CATALOG.pol);
      if (sql.includes('rel.relkind')) return out(CATALOG.rel);
      if (sql.includes('INSERT INTO tsk_outbox_meta')) { s.meta = 1; return out([{}], 1); }
      if (sql.includes('FROM tsk_outbox_meta')) return out(s.meta === null ? [] : [{ schema_version: s.meta }]);
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
  let db: MemoryTskPg; let rcv: PgTskReceiverCheckpoint; let ready: SchemaReadyToken;
  const apply = (r: { record: OutboxRecord<TskHotpMutation>; head: SignedStreamHead }) => rcv.verifyAndApplyTumblerDelivered(r.record, r.head);
  beforeEach(async () => {
    db = new MemoryTskPg(); db.provision(SID); applied.length = 0;
    // real attestation path: replays the captured catalog, computes+matches the
    // manifest, stamps meta, and mints a transactor-bound token — same as production.
    ready = await provisionSchemaVersion(db, 'public');
    rcv = new PgTskReceiverCheckpoint(db, SID, sanitizer, headVerifier, applier, ready);
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
    const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, flaky, applier, ready);
    const r = mkRecordHead(1, { tumblerId: 'T1', counter: 1 }, GENESIS_HEAD);
    await expect(r2.verifyAndApplyTumblerDelivered(r.record, r.head)).rejects.toBeInstanceOf(StreamHeadVerificationUnavailableError);
    expect(db.rcvOf(SID).seq).toBe(0); // not applied, not rejected — retry
    expect(applied.length).toBe(0);
  });

  it('signed head: an UNKNOWN/untyped verifier exception FAILS CLOSED (reject-fork, no ack, no retry loop)', async () => {
    const chaos: StreamHeadVerifier = { async verify() { throw new TypeError('unexpected boom'); } };
    const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, chaos, applier, ready);
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

  it('(TOCTOU) mutating the caller record DURING headVerifier.verify does NOT change what is applied/consumed', async () => {
    const r = mkRecordHead(1, { tumblerId: 'T1', counter: 5 }, GENESIS_HEAD);
    // an attacker mutates the caller-owned record object mid-verification, then the
    // (unchanged) head signature still verifies. The receiver must apply/consume the
    // ORIGINAL snapshot value (5/T1), never the mutated evil value.
    const mutatingVerifier: StreamHeadVerifier = {
      async verify(head) {
        (r.record.mutation as { counter: number; tumblerId: string }).counter = 999;
        (r.record.mutation as { counter: number; tumblerId: string }).tumblerId = 'EVIL';
        const ok = edVerify(null, Buffer.from(head.headDigest, 'utf8'), publicKey as KeyObject, Buffer.from(head.signature, 'base64url'));
        if (!ok) throw new ContractValidationError('bad');
      },
    };
    const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, mutatingVerifier, applier, ready);
    expect(await r2.verifyAndApplyTumblerDelivered(r.record, r.head)).toBe('applied');
    expect(applied).toEqual(['1:T1:5']);          // ORIGINAL applied, not 999/EVIL
    expect(db.hotpOf(SID, 'T1')).toBe(5);          // ORIGINAL counter consumed
    expect(db.hotpOf(SID, 'EVIL')).toBeUndefined();
  });

  it('(gated race) mutating the record TUPLE (sequence/fenceToken/opDigest) mid-verify is defeated by the frozen snapshot', async () => {
    const r = mkRecordHead(1, { tumblerId: 'T1', counter: 7 }, GENESIS_HEAD);
    const evil: StreamHeadVerifier = {
      async verify(head) {
        // attacker rewrites tuple fields on the caller-owned record AFTER the snapshot
        (r.record as { sequence: number }).sequence = 999;
        (r.record as { opDigest: string }).opDigest = 'b'.repeat(64);
        (r.record as { fenceToken: string }).fenceToken = '5';
        const ok = edVerify(null, Buffer.from(head.headDigest, 'utf8'), publicKey as KeyObject, Buffer.from(head.signature, 'base64url'));
        if (!ok) throw new ContractValidationError('bad');
      },
    };
    const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, evil, applier, ready);
    expect(await r2.verifyAndApplyTumblerDelivered(r.record, r.head)).toBe('applied');
    expect(db.rcvOf(SID).seq).toBe(1);                  // ORIGINAL seq applied, not 999
    expect(db.rcvOf(SID).head).toBe(r.head.headDigest); // checkpoint advanced to the ORIGINAL head
    expect(applied).toEqual(['1:T1:7']);
  });

  it('(gated race) mutating the HEAD (headDigest/opDigest/sequence) mid-verify does not change the persisted checkpoint head', async () => {
    const r = mkRecordHead(1, { tumblerId: 'T1', counter: 8 }, GENESIS_HEAD);
    const original = r.head.headDigest;
    const evil: StreamHeadVerifier = {
      async verify(head) {
        // `head` is the FROZEN snapshot; mutating the caller's original head must not matter
        (r.head as { headDigest: string }).headDigest = 'c'.repeat(64);
        (r.head as { opDigest: string }).opDigest = 'd'.repeat(64);
        (r.head as { sequence: number }).sequence = 999;
        const ok = edVerify(null, Buffer.from(head.headDigest, 'utf8'), publicKey as KeyObject, Buffer.from(head.signature, 'base64url'));
        if (!ok) throw new ContractValidationError('bad');
      },
    };
    const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, evil, applier, ready);
    expect(await r2.verifyAndApplyTumblerDelivered(r.record, r.head)).toBe('applied');
    expect(db.rcvOf(SID).head).toBe(original);          // ORIGINAL head digest persisted, not 'cccc…'
    expect(applied).toEqual(['1:T1:8']);
  });

  describe('(MED) transparent Proxy is ACCEPTED (not rejected) but snapshotted to a stable frozen copy', () => {
    // A faithful Proxy over exact plain data passes getPrototypeOf/ownKeys/
    // getOwnPropertyDescriptor, so it is NOT rejected — by design. The safety
    // property is STABILITY: each descriptor value is read once and frozen before
    // any await, so neither the Proxy nor a later target mutation can change what
    // is applied/consumed/persisted.
    it('record + head presented as transparent Proxies are accepted and applied from the frozen snapshot', async () => {
      const r = mkRecordHead(1, { tumblerId: 'T1', counter: 5 }, GENESIS_HEAD);
      const recProxy = new Proxy({ ...r.record, mutation: { ...r.record.mutation } }, {});
      const headProxy = new Proxy({ ...r.head }, {});
      expect(await rcv.verifyAndApplyTumblerDelivered(recProxy as OutboxRecord<TskHotpMutation>, headProxy as SignedStreamHead)).toBe('applied');
      expect(db.rcvOf(SID).seq).toBe(1);
      expect(db.rcvOf(SID).head).toBe(r.head.headDigest);
      expect(applied).toEqual(['1:T1:5']);
    });

    it('mutating a Proxy target (record tuple + nested mutation) mid-verify does not change what is applied/consumed', async () => {
      const r = mkRecordHead(1, { tumblerId: 'T1', counter: 5 }, GENESIS_HEAD);
      const target = { ...r.record, mutation: { ...r.record.mutation } };
      const recProxy = new Proxy(target, {}); // faithful forwarding — passes every structural check
      const evil: StreamHeadVerifier = {
        async verify(head) {
          (target as { sequence: number }).sequence = 999;
          (target.mutation as { counter: number }).counter = 999;
          (target.mutation as { tumblerId: string }).tumblerId = 'EVIL';
          const ok = edVerify(null, Buffer.from(head.headDigest, 'utf8'), publicKey as KeyObject, Buffer.from(head.signature, 'base64url'));
          if (!ok) throw new ContractValidationError('bad');
        },
      };
      const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, evil, applier, ready);
      expect(await r2.verifyAndApplyTumblerDelivered(recProxy as OutboxRecord<TskHotpMutation>, r.head)).toBe('applied');
      expect(db.rcvOf(SID).seq).toBe(1);            // frozen snapshot seq, not 999
      expect(applied).toEqual(['1:T1:5']);          // ORIGINAL applied
      expect(db.hotpOf(SID, 'T1')).toBe(5);
      expect(db.hotpOf(SID, 'EVIL')).toBeUndefined();
    });

    it('mutating a Proxy target head mid-verify does not change the persisted checkpoint head', async () => {
      const r = mkRecordHead(1, { tumblerId: 'T1', counter: 6 }, GENESIS_HEAD);
      const original = r.head.headDigest;
      const target = { ...r.head };
      const headProxy = new Proxy(target, {});
      const evil: StreamHeadVerifier = {
        async verify(head) {
          (target as { headDigest: string }).headDigest = 'c'.repeat(64);
          (target as { opDigest: string }).opDigest = 'd'.repeat(64);
          const ok = edVerify(null, Buffer.from(head.headDigest, 'utf8'), publicKey as KeyObject, Buffer.from(head.signature, 'base64url'));
          if (!ok) throw new ContractValidationError('bad');
        },
      };
      const r2 = new PgTskReceiverCheckpoint(db, SID, sanitizer, evil, applier, ready);
      expect(await r2.verifyAndApplyTumblerDelivered(r.record, headProxy as SignedStreamHead)).toBe('applied');
      expect(db.rcvOf(SID).head).toBe(original);    // ORIGINAL head digest persisted, not 'cccc…'
      expect(applied).toEqual(['1:T1:6']);
    });
  });

  describe('(MED) strict snapshot validator rejects non-plain / accessor / symbol / extra-key shapes', () => {
    const valid = () => mkRecordHead(1, { tumblerId: 'T1', counter: 5 }, GENESIS_HEAD);
    const rejects = (record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead) =>
      expect(rcv.verifyAndApplyTumblerDelivered(record, head)).rejects.toThrow(ContractValidationError);

    it('record: an accessor (getter) property is rejected', async () => {
      const { record, head } = valid();
      const bad = { ...record };
      Object.defineProperty(bad, 'opDigest', { get: () => record.opDigest, enumerable: true, configurable: true });
      await rejects(bad as OutboxRecord<TskHotpMutation>, head);
    });
    it('record: an extra own key is rejected', async () => {
      const { record, head } = valid();
      await rejects({ ...record, evil: 1 } as unknown as OutboxRecord<TskHotpMutation>, head);
    });
    it('record: a symbol key is rejected', async () => {
      const { record, head } = valid();
      await rejects({ ...record, [Symbol('x')]: 1 } as OutboxRecord<TskHotpMutation>, head);
    });
    it('record: an inherited (non-plain prototype) value is rejected', async () => {
      const { record, head } = valid();
      const bad = Object.assign(Object.create({ contractVersion: '1' }), record);
      await rejects(bad as OutboxRecord<TskHotpMutation>, head);
    });
    it('record.mutation: a nested accessor is rejected', async () => {
      const { record, head } = valid();
      const mut: Record<string, unknown> = { tumblerId: 'T1' };
      Object.defineProperty(mut, 'counter', { get: () => 5, enumerable: true, configurable: true });
      await rejects({ ...record, mutation: mut } as unknown as OutboxRecord<TskHotpMutation>, head);
    });
    it('head: an extra own key is rejected', async () => {
      const { record, head } = valid();
      await rejects(record, { ...head, evil: 1 } as unknown as SignedStreamHead);
    });
    it('head: an accessor (getter) property is rejected', async () => {
      const { record, head } = valid();
      const bad = { ...head };
      Object.defineProperty(bad, 'signature', { get: () => head.signature, enumerable: true, configurable: true });
      await rejects(record, bad as SignedStreamHead);
    });
    it('head: a missing key is rejected', async () => {
      const { record, head } = valid();
      const bad: Record<string, unknown> = { ...head };
      delete bad.signature;
      await rejects(record, bad as unknown as SignedStreamHead);
    });
  });
});
