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
const RESP_KEY = 'resp-key-1';
const respSecret = Buffer.alloc(32, 5);

// one server; each test installs a fresh handler (fresh nonce store) via `install`
let server: Server;
let baseUrl = '';
let handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void;
function install(opts: Partial<HttpOutboxReceiverOptions> & { keys?: Record<string, Buffer> }) {
  const keys = opts.keys ?? { [REQ_KEY]: reqSecret };
  handler = createHttpOutboxReceiver({
    expectedPath: '/ingest',
    resolveRequestKey: (kid) => keys[kid] ?? null,
    responseKeyId: RESP_KEY,
    responseSecret: respSecret,
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
  return new HttpOutboxTransport({ url: baseUrl, fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: reqSecret, resolveResponseKey: (kid: string) => (kid === RESP_KEY ? respSecret : null), ackVerifier, ...over });
}

describe('HttpOutboxTransport <-> createHttpOutboxReceiver (authenticated, decision-bound)', () => {
  it('delivers over loopback and returns the receiver-signed applied ack', async () => {
    const { record, head } = mkRH(1, 5);
    const ack = await client().deliverAndAwaitAck(record, head);
    expect(ack.decision).toBe('applied');
    expect(ack.opDigest).toBe(record.opDigest);
  });

  it('rejects a bad request signature (wrong secret) -> 401 -> TERMINAL (auth is not retriable)', async () => {
    const { record, head } = mkRH(1, 5);
    const err = await client({ requestSecret: Buffer.alloc(32, 1) }).deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
    expect(err.retriable).toBe(false); // auth/protocol/validation is terminal, not retried forever
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
    const c = new HttpOutboxTransport({ url: 'http://127.0.0.1:9/ingest', fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: reqSecret, resolveResponseKey: (kid: string) => (kid === RESP_KEY ? respSecret : null), ackVerifier, timeoutMs: 500 });
    const err = await c.deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
    expect(err.retriable).toBe(true);
  });

  it('rejects a request to a path this receiver does not serve (path authorized, not just signed)', async () => {
    const { record, head } = mkRH(1, 5);
    const wrong = client({ url: baseUrl.replace('/ingest', '/wrong') });
    await expect(wrong.deliverAndAwaitAck(record, head)).rejects.toBeInstanceOf(OutboxTransportError);
  });

  it('bounds the response-body read by the deadline (no unbounded body hang)', async () => {
    const { record, head } = mkRH(1, 5);
    const hangingFetch: never = (async (_u: string, init: { signal?: AbortSignal }) => ({
      status: 200,
      headers: { get: (n: string) => (n === 'content-type' ? 'application/json' : null) },
      text: () => new Promise<string>((_, reject) => { init.signal?.addEventListener('abort', () => reject(init.signal!.reason), { once: true }); }),
    })) as never;
    const c = new HttpOutboxTransport({ url: baseUrl, fetch: hangingFetch, requestKeyId: REQ_KEY, requestSecret: reqSecret, resolveResponseKey: (kid: string) => (kid === RESP_KEY ? respSecret : null), ackVerifier, timeoutMs: 200 });
    const err = await c.deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
  });

  it('classifies an oversize request as TERMINAL (non-retriable) and never dispatches', async () => {
    const { record, head } = mkRH(1, 5);
    let dispatched = false;
    const spyFetch: never = (async () => { dispatched = true; throw new Error('should not be called'); }) as never;
    const c = new HttpOutboxTransport({ url: baseUrl, fetch: spyFetch, requestKeyId: REQ_KEY, requestSecret: reqSecret, resolveResponseKey: (kid: string) => (kid === RESP_KEY ? respSecret : null), ackVerifier, maxRequestBytes: 8 });
    const err = await c.deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
    expect(err.retriable).toBe(false); // terminal — not retried forever against the receiver's 413
    expect(dispatched).toBe(false);
  });

  it('rejects a replayed response envelope not bound to this request attempt (stale challenge)', async () => {
    const { record, head } = mkRH(1, 5);
    // a MITM returns a well-formed envelope whose challenge is for a DIFFERENT attempt
    const staleFetch: never = (async () => ({
      status: 200,
      headers: { get: (n: string) => (n === 'content-type' ? 'application/json' : null) },
      text: async () => JSON.stringify({ v: 'TSKv1-ack', keyId: RESP_KEY, challenge: 'some-other-attempt-nonce', requestDigest: 'deadbeef', receipt: signedAck(record, 'applied'), sig: 'AAAA' }),
    })) as never;
    const c = new HttpOutboxTransport({ url: baseUrl, fetch: staleFetch, requestKeyId: REQ_KEY, requestSecret: reqSecret, resolveResponseKey: (kid: string) => (kid === RESP_KEY ? respSecret : null), ackVerifier });
    const err = await c.deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
    expect(String(err.message)).toMatch(/attempt/);
  });

  it('supports key rotation overlap (receiver accepts multiple keyIds)', async () => {
    const newSecret = Buffer.alloc(32, 3);
    install({ keys: { [REQ_KEY]: reqSecret, 'req-key-2': newSecret } });
    const { record, head } = mkRH(1, 5);
    await expect(client().deliverAndAwaitAck(record, head)).resolves.toMatchObject({ decision: 'applied' });
    await expect(client({ requestKeyId: 'req-key-2', requestSecret: newSecret }).deliverAndAwaitAck(record, head)).resolves.toMatchObject({ decision: 'applied' });
  });

  it('classifies a 5xx / network as TRANSIENT (retriable)', async () => {
    install({ receive: async () => { throw new Error('receiver DB blip'); } }); // -> 500
    const { record, head } = mkRH(1, 5);
    const err = await client().deliverAndAwaitAck(record, head).catch((e) => e);
    expect(err).toBeInstanceOf(OutboxTransportError);
    expect(err.retriable).toBe(true);
  });

  it('rejects a receipt with EXTRA keys (strict exact-key set)', async () => {
    install({ receive: async (record) => ({ ...signedAck(record, 'applied'), extra: 1 } as unknown as TskAckReceipt) });
    const { record, head } = mkRH(1, 5);
    await expect(client().deliverAndAwaitAck(record, head)).rejects.toBeInstanceOf(OutboxTransportError);
  });

  it('rejects a reply signed under an unknown response key (client cannot resolve it)', async () => {
    const { record, head } = mkRH(1, 5);
    const c = client({ resolveResponseKey: () => null }); // client knows no response key
    await expect(c.deliverAndAwaitAck(record, head)).rejects.toBeInstanceOf(OutboxTransportError);
  });

  it('rejects an application/jsonjunk content-type (strict MIME, not startsWith)', async () => {
    // craft the request manually so we control the content-type header
    const { record, head } = mkRH(1, 5);
    const res = await fetch(baseUrl, { method: 'POST', headers: { 'content-type': 'application/jsonjunk' }, body: JSON.stringify({ record, head }) });
    expect(res.status).toBe(415);
  });

  it('enforces the nonce retention >= 2x freshness invariant at composition', () => {
    expect(() => createHttpOutboxReceiver({
      expectedPath: '/ingest', resolveRequestKey: () => reqSecret, responseKeyId: RESP_KEY, responseSecret: respSecret,
      receive: async (r) => signedAck(r, 'applied'), nonceStore: new MemoryReplayNonceStore(1_000), freshnessMs: 30_000,
    })).toThrow(/retentionMs/);
  });

  it('rejects a url with embedded credentials or a fragment', () => {
    for (const url of ['http://u:p@127.0.0.1:1/ingest', 'http://127.0.0.1:1/ingest#frag']) {
      expect(() => new HttpOutboxTransport({ url, fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: reqSecret, resolveResponseKey: () => respSecret, ackVerifier })).toThrow();
    }
  });

  it('rejects unsafe construction (short secret, bad url)', () => {
    expect(() => new HttpOutboxTransport({ url: baseUrl, fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: 'short', resolveResponseKey: (kid: string) => (kid === RESP_KEY ? respSecret : null), ackVerifier })).toThrow();
    expect(() => new HttpOutboxTransport({ url: 'ftp://x/y', fetch: fetch as never, requestKeyId: REQ_KEY, requestSecret: reqSecret, resolveResponseKey: (kid: string) => (kid === RESP_KEY ? respSecret : null), ackVerifier })).toThrow();
  });
});
