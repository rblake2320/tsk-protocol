import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { AddressInfo } from 'node:net';

import { canonicalOpDigest, streamHeadDigest, type OutboxRecord, type SignedStreamHead, type TskHotpMutation, type SanitizedMutation, type ReceiverDecision } from '../src/ha-outbox-contract.js';
import type { TskAckReceipt, TskAckReceiptVerifier } from '../src/tsk-hotp-outbox-pg.js';
import {
  HttpOutboxTransport,
  OutboxTransportError,
  MemoryReplayNonceStore,
  createHttpOutboxReceiver,
  type HttpOutboxReceiverOptions,
} from '../src/http-outbox-transport.js';

// ── fixtures: structurally-valid record + head; HMAC-signed decision-bound ack ──
const SID = 'tsk:pair:default/v1';
const GENESIS_HEAD = '0'.repeat(64);
function mkRH(seq: number, counter: number): { record: OutboxRecord<TskHotpMutation>; head: SignedStreamHead } {
  const mutation = { tumblerId: 'T1', counter } as SanitizedMutation<TskHotpMutation>;
  const opDigest = canonicalOpDigest<TskHotpMutation>({ streamId: SID, sourceEpoch: 'e1', sequence: seq, fenceToken: '0', mutation });
  const headDigest = streamHeadDigest({ streamId: SID, sequence: seq, prevHeadDigest: GENESIS_HEAD, opDigest, keyId: 'k1', alg: 'ed25519' });
  const head: SignedStreamHead = { streamId: SID, sequence: seq, prevHeadDigest: GENESIS_HEAD, opDigest, keyId: 'k1', alg: 'ed25519', headDigest, signature: 'ZHVtbXk' };
  const record: OutboxRecord<TskHotpMutation> = { contractVersion: '1', streamId: SID, sourceEpoch: 'e1', sequence: seq, fenceToken: '0', opDigest, mutation };
  return { record, head };
}

const RID = 'receiver-B';
const ACK_KEY = 'ack-key-1';
const ackSecret = Buffer.alloc(32, 7);
const ackBody = (a: Pick<TskAckReceipt, 'receiverId' | 'keyId' | 'streamId' | 'sourceEpoch' | 'sequence' | 'opDigest' | 'decision' | 'issuedAt'>) =>
  `${a.receiverId}|${a.keyId}|${a.streamId}|${a.sourceEpoch}|${a.sequence}|${a.opDigest}|${a.decision}|${a.issuedAt}`;
const ackSign = (a: Omit<TskAckReceipt, 'signature'>) => createHmac('sha256', ackSecret).update(ackBody(a)).digest('base64url');
const ackVerifier: TskAckReceiptVerifier = {
  async verify(receipt, record) {
    if (receipt.receiverId !== RID || receipt.keyId !== ACK_KEY) throw new Error('bad ack identity');
    if (receipt.streamId !== record.streamId || receipt.sourceEpoch !== record.sourceEpoch || receipt.sequence !== record.sequence || receipt.opDigest !== record.opDigest) throw new Error('ack does not bind record');
    const expect = Buffer.from(ackSign(receipt), 'base64url');
    const got = Buffer.from(receipt.signature, 'base64url');
    if (got.length !== expect.length || !timingSafeEqual(got, expect)) throw new Error('bad ack signature');
  },
};
function signedAck(record: OutboxRecord<TskHotpMutation>, decision: ReceiverDecision, over?: Partial<TskAckReceipt>): TskAckReceipt {
  const base = { streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence, opDigest: record.opDigest, decision, receiverId: RID, keyId: ACK_KEY, issuedAt: '1700000000000', ...over };
  return { ...base, signature: ackSign(base) };
}

const REQ_KEY = 'req-key-1';
const reqSecret = Buffer.alloc(32, 9);

// one server; each test installs a fresh handler (fresh nonce store) via `install`
let server: Server;
let baseUrl = '';
let handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void;
function install(opts: Partial<HttpOutboxReceiverOptions> & { keys?: Record<string, Buffer> }) {
  const keys = opts.keys ?? { [REQ_KEY]: reqSecret };
  handler = createHttpOutboxReceiver({
    resolveRequestKey: (kid) => keys[kid] ?? null,
    receive: opts.receive ?? (async (record) => signedAck(record, 'applied')),
    nonceStore: opts.nonceStore ?? new MemoryReplayNonceStore(),
    now: opts.now,
    freshnessMs: opts.freshnessMs,
  });
}
beforeAll(async () => {
  server = createServer((req, res) => handler(req, res));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/ingest`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => install({}));

function client(over: Partial<ConstructorParameters<typeof HttpOutboxTransport>[0]> = {}) {
  return new HttpOutboxTransport({ url: baseUrl, fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: reqSecret, ackVerifier, ...over });
}

describe('HttpOutboxTransport <-> createHttpOutboxReceiver (authenticated, decision-bound)', () => {
  it('delivers over loopback and returns the receiver-signed applied ack', async () => {
    const { record, head } = mkRH(1, 5);
    const ack = await client().deliverAndAwaitAck(record, head);
    expect(ack.decision).toBe('applied');
    expect(ack.opDigest).toBe(record.opDigest);
  });

  it('rejects a bad request signature (wrong secret) -> 401 -> retriable throw', async () => {
    const { record, head } = mkRH(1, 5);
    const err = await client({ requestSecret: Buffer.alloc(32, 1) }).deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
    expect(err.retriable).toBe(true);
  });

  it('rejects an unknown keyId', async () => {
    const { record, head } = mkRH(1, 5);
    await expect(client({ requestKeyId: 'req-key-1', requestSecret: reqSecret })).toBeTruthy();
    install({ keys: { 'other-key': reqSecret } }); // server no longer knows req-key-1
    await expect(client().deliverAndAwaitAck(record, head)).rejects.toBeInstanceOf(OutboxTransportError);
  });

  it('rejects a replayed nonce (durable single-use) even with a valid signature', async () => {
    const { record, head } = mkRH(1, 5);
    const c = client({ nonce: () => 'fixed-nonce-abcdefghijklmnop' });
    await c.deliverAndAwaitAck(record, head);               // first use ok
    await expect(c.deliverAndAwaitAck(record, head)).rejects.toBeInstanceOf(OutboxTransportError); // replay -> 401
  });

  it('rejects a stale timestamp outside the freshness window', async () => {
    const { record, head } = mkRH(1, 5);
    const c = client({ now: () => 1_000 }); // far outside the receiver's real-time freshness window
    await expect(c.deliverAndAwaitAck(record, head)).rejects.toBeInstanceOf(OutboxTransportError);
  });

  it('rejects a forged / wrong-signature ack (fail-closed, never accepted)', async () => {
    install({ receive: async (record) => ({ ...signedAck(record, 'applied'), signature: 'AAAA' }) });
    const { record, head } = mkRH(1, 5);
    await expect(client().deliverAndAwaitAck(record, head)).rejects.toBeInstanceOf(OutboxTransportError);
  });

  it('rejects an ack that does not bind to the delivered record', async () => {
    const other = mkRH(2, 9);
    install({ receive: async () => signedAck(other.record, 'applied') }); // ack for a different opDigest/seq
    const { record, head } = mkRH(1, 5);
    const err = await client().deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
    expect(String(err.message)).toMatch(/bind/);
  });

  it('a network failure throws a retriable error and never fabricates an ack', async () => {
    const { record, head } = mkRH(1, 5);
    const c = new HttpOutboxTransport({ url: 'http://127.0.0.1:9/ingest', fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: reqSecret, ackVerifier, timeoutMs: 500 });
    const err = await c.deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
    expect(err.retriable).toBe(true);
  });

  it('supports key rotation overlap (receiver accepts multiple keyIds)', async () => {
    const newSecret = Buffer.alloc(32, 3);
    install({ keys: { [REQ_KEY]: reqSecret, 'req-key-2': newSecret } });
    const { record, head } = mkRH(1, 5);
    await expect(client().deliverAndAwaitAck(record, head)).resolves.toMatchObject({ decision: 'applied' });
    await expect(client({ requestKeyId: 'req-key-2', requestSecret: newSecret }).deliverAndAwaitAck(record, head)).resolves.toMatchObject({ decision: 'applied' });
  });

  it('rejects unsafe construction (short secret, bad url)', () => {
    expect(() => new HttpOutboxTransport({ url: baseUrl, fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: 'short', ackVerifier })).toThrow();
    expect(() => new HttpOutboxTransport({ url: 'ftp://x/y', fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: reqSecret, ackVerifier })).toThrow();
  });
});
