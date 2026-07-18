import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

import { ContractValidationError, canonicalize, assertStreamHeadBinds } from './ha-outbox-contract.js';
import type { OutboxRecord, SignedStreamHead, TskHotpMutation, ReceiverDecision } from './ha-outbox-contract.js';
import type { TskAckReceipt, TskAckReceiptVerifier, TskOutboxTransport } from './tsk-hotp-outbox-pg.js';

/**
 * Authenticated, decision-bound AND request-attempt-bound HTTP transport for the
 * durable HOTP-outbox publisher -> receiver hop (node A -> node B). It is the ONLY
 * A->B path in the two-node topology, so it is treated as fully untrusted and every
 * boundary is bounded and fail-closed.
 *
 *  - REQUEST auth: HMAC-SHA256 over a length-PREFIXED framing of
 *    (domain, keyId, method, exact-path, timestamp, nonce, sha256(raw body)). The
 *    receiver authorizes the EXACT path, checks freshness, verifies the signature over
 *    the RAW BYTES, and burns a DURABLE single-use nonce, BEFORE parsing/applying.
 *  - RESPONSE binding: the reply envelope is MAC'd (framed) over the fresh request nonce
 *    (challenge) + request body digest + path + canonical receipt, so a prior signed
 *    receipt cannot be replayed for another attempt. Inside sits a decision-bound
 *    `TskAckReceipt` the publisher verifies separately.
 *  - The WHOLE exchange (connect + bounded streaming body + parse + verify) is raced
 *    against a deadline — a hostile body/verifier that ignores the abort signal cannot
 *    hang the publisher. Errors are classified: auth/protocol/validation are TERMINAL
 *    (retriable:false); network/timeout/5xx are TRANSIENT (retriable:true). A throw
 *    NEVER fabricates an ack.
 *
 * BOUNDARY: HMAC is the slice-1 mechanism (mTLS is a deployment upgrade). NOT an HA
 * claim; #10 stays OPEN until the full acceptance drill passes.
 */

const HDR = { keyId: 'x-tsk-key-id', ts: 'x-tsk-timestamp', nonce: 'x-tsk-nonce', sig: 'x-tsk-signature' } as const;
const CONTENT_TYPE = 'application/json';
const REQ_DOMAIN = 'TSKv1-req';
const ACK_DOMAIN = 'TSKv1-ack';
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_FRESHNESS_MS = 30_000;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_BODY_READ_MS = 10_000;
const DEFAULT_NONCE_RETENTION_MS = 120_000;
const DEFAULT_MAX_CLOCK_SKEW_MS = 60_000;
const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const RECEIPT_KEYS = ['streamId', 'sourceEpoch', 'sequence', 'opDigest', 'decision', 'receiverId', 'keyId', 'issuedAt', 'signature'] as const;
const RECEIPT_TYPES: Record<(typeof RECEIPT_KEYS)[number], 'string' | 'number'> = {
  streamId: 'string', sourceEpoch: 'string', sequence: 'number', opDigest: 'string', decision: 'string', receiverId: 'string', keyId: 'string', issuedAt: 'string', signature: 'string',
};
const ENVELOPE_KEYS = ['v', 'keyId', 'challenge', 'requestDigest', 'receipt', 'sig'] as const;

const sha256hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const hmac = (secret: Buffer, msg: Buffer): Buffer => createHmac('sha256', secret).update(msg).digest();
const b64u = (b: Buffer): string => b.toString('base64url');
function ctEqualB64u(a: string, expected: Buffer): boolean {
  let got: Buffer;
  try { got = Buffer.from(a, 'base64url'); } catch { return false; }
  return got.length === expected.length && timingSafeEqual(got, expected);
}
function frame(...parts: (string | Buffer)[]): Buffer {
  const bufs: Buffer[] = [];
  for (const p of parts) {
    const b = Buffer.isBuffer(p) ? p : Buffer.from(p, 'utf8');
    const len = Buffer.alloc(4); len.writeUInt32BE(b.length, 0);
    bufs.push(len, b);
  }
  return Buffer.concat(bufs);
}
function toSecret(s: Buffer | string, label: string): Buffer {
  const b = Buffer.isBuffer(s) ? s : Buffer.from(String(s), 'utf8');
  if (b.length < 32) throw new ContractValidationError(`${label} must be >= 32 bytes`);
  return b;
}
function posInt(n: number, label: string): number {
  if (!Number.isSafeInteger(n) || n < 1) throw new ContractValidationError(`${label} must be a positive safe integer`);
  return n;
}
function isPlainObject(o: unknown): o is Record<string, unknown> {
  if (o === null || typeof o !== 'object') return false;
  const p = Object.getPrototypeOf(o);
  return p === Object.prototype || p === null;
}
/** exact-key set (no extras, no missing, no symbols). */
function hasExactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Reflect.ownKeys(o);
  if (own.length !== keys.length || own.some((k) => typeof k === 'symbol')) return false;
  for (const k of keys) if (!Object.prototype.hasOwnProperty.call(o, k)) return false;
  return true;
}
function strictReceipt(o: unknown): TskAckReceipt {
  if (!isPlainObject(o) || !hasExactKeys(o, RECEIPT_KEYS)) throw new ContractValidationError('receipt has an invalid key set');
  for (const k of RECEIPT_KEYS) if (typeof o[k] !== RECEIPT_TYPES[k]) throw new ContractValidationError(`receipt.${k} must be ${RECEIPT_TYPES[k]}`);
  return Object.freeze({
    streamId: o.streamId as string, sourceEpoch: o.sourceEpoch as string, sequence: o.sequence as number, opDigest: o.opDigest as string,
    decision: o.decision as ReceiverDecision, receiverId: o.receiverId as string, keyId: o.keyId as string, issuedAt: o.issuedAt as string, signature: o.signature as string,
  });
}
/** strict application/json (rejects application/jsonjunk); params after ';' allowed. */
function isJsonMime(ct: string | null | undefined): boolean {
  if (!ct) return false;
  return ct.split(';', 1)[0].trim().toLowerCase() === CONTENT_TYPE;
}

// ── durable replay-nonce store ───────────────────────────────────────────────

export interface ReplayNonceStore {
  /** How long a nonce is retained; the receiver enforces this covers its acceptance
   *  horizon (>= 2x freshness) so a nonce cannot be pruned while a replay is possible. */
  readonly retentionMs: number;
  checkAndStore(nonce: string): Promise<boolean>;
}

export class MemoryReplayNonceStore implements ReplayNonceStore {
  readonly retentionMs: number;
  private readonly seen = new Map<string, number>();
  constructor(retentionMs = DEFAULT_NONCE_RETENTION_MS, private readonly now: () => number = Date.now) {
    this.retentionMs = posInt(retentionMs, 'retentionMs');
  }
  async checkAndStore(nonce: string): Promise<boolean> {
    const t = this.now();
    for (const [k, exp] of this.seen) if (exp <= t) this.seen.delete(k);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, t + this.retentionMs);
    return true;
  }
}

export const TSK_TRANSPORT_NONCE_SCHEMA = `
CREATE TABLE IF NOT EXISTS tsk_transport_nonce (
  nonce      text        PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS tsk_transport_nonce_expiry ON tsk_transport_nonce (expires_at);
`.trim();

type QueryFn = (sql: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[]; rowCount: number }>;

export interface PgReplayNonceStoreOptions {
  retentionMs?: number;
  maxClockSkewMs?: number;
  now?: () => number;
}

/** Durable replay-nonce store. DB-authored expiry (`now() + retention`, never a sender
 *  timestamp), same-clock pruning, asserted DB/app skew (fail closed), atomic insert. */
export class PgReplayNonceStore implements ReplayNonceStore {
  readonly retentionMs: number;
  private readonly maxClockSkewMs: number;
  private readonly now: () => number;
  constructor(private readonly query: QueryFn, opts: PgReplayNonceStoreOptions = {}) {
    this.retentionMs = posInt(opts.retentionMs ?? DEFAULT_NONCE_RETENTION_MS, 'retentionMs');
    this.maxClockSkewMs = posInt(opts.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS, 'maxClockSkewMs');
    this.now = opts.now ?? Date.now;
  }
  async checkAndStore(nonce: string): Promise<boolean> {
    const dbNow = Number((await this.query("SELECT (extract(epoch from now()) * 1000)::bigint::text AS ms")).rows[0]?.ms);
    if (!Number.isFinite(dbNow) || Math.abs(dbNow - this.now()) > this.maxClockSkewMs) {
      throw new ContractValidationError('replay-nonce store: DB/app clock skew exceeds the allowed bound (fail closed)');
    }
    await this.query('DELETE FROM tsk_transport_nonce WHERE expires_at < now()');
    const res = await this.query(
      "INSERT INTO tsk_transport_nonce (nonce, expires_at) VALUES ($1, now() + ($2 || ' milliseconds')::interval) ON CONFLICT (nonce) DO NOTHING",
      [nonce, String(this.retentionMs)],
    );
    return res.rowCount === 1;
  }
}

// ── client: HttpOutboxTransport ──────────────────────────────────────────────

export interface FetchResponseLike {
  status: number;
  headers: { get(name: string): string | null };
  /** Preferred: a web ReadableStream read under a hard cap with cancel. */
  body?: ReadableStream<Uint8Array> | null;
  /** Fallback if `body` is absent (bounded by a post-read check). */
  text?(): Promise<string>;
}
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal; redirect?: 'manual' | 'error' | 'follow' },
) => Promise<FetchResponseLike>;

export class OutboxTransportError extends Error {
  readonly retriable: boolean;
  constructor(message: string, options?: ErrorOptions & { retriable?: boolean }) {
    super(message, options);
    this.name = 'OutboxTransportError';
    this.retriable = options?.retriable ?? true;
  }
}
const terminal = (m: string, cause?: unknown): OutboxTransportError => new OutboxTransportError(m, { retriable: false, cause });
const transient = (m: string, cause?: unknown): OutboxTransportError => new OutboxTransportError(m, { retriable: true, cause });

export interface HttpOutboxTransportOptions {
  url: string;
  fetch: FetchLike;
  requestKeyId: string;
  requestSecret: Buffer | string;
  /** Resolve a RESPONSE keyId to its secret (or null). Multiple valid keyIds = rotation overlap. */
  resolveResponseKey(keyId: string): Buffer | string | null;
  ackVerifier: TskAckReceiptVerifier;
  now?: () => number;
  nonce?: () => string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRequestBytes?: number;
}

export class HttpOutboxTransport implements TskOutboxTransport {
  private readonly url: URL;
  private readonly path: string;
  private readonly reqSecret: Buffer;
  private readonly now: () => number;
  private readonly nonce: () => string;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxRequestBytes: number;

  constructor(private readonly opts: HttpOutboxTransportOptions) {
    if (typeof opts.fetch !== 'function') throw new ContractValidationError('fetch is required');
    if (typeof opts.resolveResponseKey !== 'function') throw new ContractValidationError('resolveResponseKey is required');
    if (!KEY_ID_RE.test(opts.requestKeyId)) throw new ContractValidationError('invalid requestKeyId');
    this.url = new URL(opts.url);
    if (this.url.protocol !== 'http:' && this.url.protocol !== 'https:') throw new ContractValidationError('transport url must be http(s)');
    if (this.url.username || this.url.password) throw new ContractValidationError('transport url must not embed credentials');
    if (this.url.hash) throw new ContractValidationError('transport url must not contain a fragment');
    this.path = this.url.pathname + this.url.search;
    this.reqSecret = toSecret(opts.requestSecret, 'requestSecret');
    this.now = opts.now ?? Date.now;
    this.nonce = opts.nonce ?? (() => b64u(randomBytes(24)));
    this.timeoutMs = posInt(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, 'timeoutMs');
    this.maxResponseBytes = posInt(opts.maxResponseBytes ?? DEFAULT_MAX_BODY_BYTES, 'maxResponseBytes');
    this.maxRequestBytes = posInt(opts.maxRequestBytes ?? DEFAULT_MAX_BODY_BYTES, 'maxRequestBytes');
  }

  async deliverAndAwaitAck(record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead): Promise<TskAckReceipt> {
    const body = canonicalize({ record, head });
    const bodyBuf = Buffer.from(body, 'utf8');
    if (bodyBuf.length > this.maxRequestBytes) throw terminal(`request body ${bodyBuf.length}B exceeds maxRequestBytes ${this.maxRequestBytes}B`);
    const nonce = this.nonce();
    if (!NONCE_RE.test(nonce)) throw terminal('nonce generator produced an invalid nonce');
    const tnum = this.now();
    if (!Number.isSafeInteger(tnum)) throw terminal('clock produced a non-integer timestamp');
    const ts = String(tnum);
    const bodyDigest = sha256hex(bodyBuf);
    const controller = new AbortController();
    let timer!: ReturnType<typeof setTimeout>;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { try { controller.abort(); } catch { /* noop */ } reject(transient(`transport deadline ${this.timeoutMs}ms exceeded`)); }, this.timeoutMs);
    });
    // race the ENTIRE operation against the deadline; swallow any late settlement so a
    // hostile body/verifier that ignores the abort cannot hang or double-reject.
    const work = this.doDeliver(record, body, bodyDigest, ts, nonce, controller.signal);
    work.catch(() => { /* swallowed: deadline may have already won */ });
    try {
      return await Promise.race([work, deadline]);
    } finally {
      clearTimeout(timer);
      try { controller.abort(); } catch { /* noop */ }
    }
  }

  private async doDeliver(record: OutboxRecord<TskHotpMutation>, body: string, bodyDigest: string, ts: string, nonce: string, signal: AbortSignal): Promise<TskAckReceipt> {
    const sig = b64u(hmac(this.reqSecret, frame(REQ_DOMAIN, this.opts.requestKeyId, 'POST', this.path, ts, nonce, bodyDigest)));
    let res: FetchResponseLike;
    try {
      res = await this.opts.fetch(this.url.toString(), {
        method: 'POST',
        headers: { 'content-type': CONTENT_TYPE, [HDR.keyId]: this.opts.requestKeyId, [HDR.ts]: ts, [HDR.nonce]: nonce, [HDR.sig]: sig },
        body, signal, redirect: 'manual',
      });
    } catch (err) {
      throw err instanceof OutboxTransportError ? err : transient('transport request failed', err);
    }
    if (res.status >= 300 && res.status < 400) throw terminal(`transport received a redirect (${res.status})`);
    if (res.status >= 500) throw transient(`transport received HTTP ${res.status}`);
    if (res.status !== 200) throw terminal(`transport received HTTP ${res.status}`); // 4xx: auth/protocol -> terminal
    if (!isJsonMime(res.headers.get('content-type'))) throw terminal('transport reply is not application/json');
    const cl = Number(res.headers.get('content-length') ?? 'NaN');
    if (Number.isFinite(cl) && cl > this.maxResponseBytes) throw terminal('transport reply too large');
    const text = await this.readCapped(res, signal);
    return this.verifyEnvelope(text, record, nonce, bodyDigest);
  }

  /** Read the response body under a HARD cap, cancelling the stream at the limit
   *  (Content-Length was only an optimization; a chunked reply has none). */
  private async readCapped(res: FetchResponseLike, signal: AbortSignal): Promise<string> {
    const stream = res.body;
    if (stream && typeof stream.getReader === 'function') {
      const reader = stream.getReader();
      const chunks: Buffer[] = [];
      let total = 0;
      try {
        for (;;) {
          if (signal.aborted) throw transient('transport aborted');
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > this.maxResponseBytes) { try { await reader.cancel(); } catch { /* noop */ } throw terminal('transport reply too large'); }
          chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
        }
      } finally {
        try { reader.releaseLock(); } catch { /* noop */ }
      }
      return Buffer.concat(chunks).toString('utf8');
    }
    if (typeof res.text === 'function') {
      const t = await res.text();
      if (Buffer.byteLength(t, 'utf8') > this.maxResponseBytes) throw terminal('transport reply too large');
      return t;
    }
    throw terminal('transport response exposes neither a body stream nor text()');
  }

  private async verifyEnvelope(text: string, record: OutboxRecord<TskHotpMutation>, sentNonce: string, sentBodyDigest: string): Promise<TskAckReceipt> {
    let env: unknown;
    try { env = JSON.parse(text); } catch (err) { throw terminal('transport reply is not valid JSON', err); }
    if (!isPlainObject(env) || !hasExactKeys(env, ENVELOPE_KEYS) || env.v !== ACK_DOMAIN
      || typeof env.keyId !== 'string' || typeof env.challenge !== 'string' || typeof env.requestDigest !== 'string' || typeof env.sig !== 'string') {
      throw terminal('transport reply envelope malformed');
    }
    if (env.challenge !== sentNonce || env.requestDigest !== sentBodyDigest) throw terminal('transport reply not bound to this request attempt');
    const respSecretRaw = this.opts.resolveResponseKey(env.keyId);
    if (respSecretRaw === null) throw terminal('transport reply signed under an unknown response key');
    const respSecret = toSecret(respSecretRaw, 'resolved response secret');
    let receipt: TskAckReceipt;
    try { receipt = strictReceipt(env.receipt); } catch (err) { throw terminal('transport reply receipt malformed', err); }
    const mac = hmac(respSecret, frame(ACK_DOMAIN, env.keyId, env.challenge, env.requestDigest, this.path, canonicalize(receipt)));
    if (!ctEqualB64u(env.sig, mac)) throw terminal('transport reply envelope MAC invalid');
    if (receipt.streamId !== record.streamId || receipt.sourceEpoch !== record.sourceEpoch || receipt.sequence !== record.sequence || receipt.opDigest !== record.opDigest) {
      throw terminal('transport reply does not bind to the delivered record');
    }
    try { await this.opts.ackVerifier.verify(receipt, record); } catch (err) { throw terminal('transport reply ack signature/authorization invalid', err); }
    return receipt;
  }
}

// ── receiver: authenticated ingest handler ───────────────────────────────────

export interface HttpOutboxReceiverOptions {
  expectedPath: string;
  resolveRequestKey(keyId: string): Buffer | string | null;
  responseKeyId: string;
  responseSecret: Buffer | string;
  receive(record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead): Promise<TskAckReceipt>;
  nonceStore: ReplayNonceStore;
  now?: () => number;
  freshnessMs?: number;
  maxBodyBytes?: number;
  bodyReadMs?: number;
}

export function createHttpOutboxReceiver(opts: HttpOutboxReceiverOptions): (req: IncomingMessage, res: ServerResponse) => void {
  const now = opts.now ?? Date.now;
  const freshnessMs = posInt(opts.freshnessMs ?? DEFAULT_FRESHNESS_MS, 'freshnessMs');
  const maxBodyBytes = posInt(opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES, 'maxBodyBytes');
  const bodyReadMs = posInt(opts.bodyReadMs ?? DEFAULT_BODY_READ_MS, 'bodyReadMs');
  if (typeof opts.expectedPath !== 'string' || !opts.expectedPath.startsWith('/')) throw new ContractValidationError('expectedPath must be an absolute request path');
  if (!KEY_ID_RE.test(opts.responseKeyId)) throw new ContractValidationError('invalid responseKeyId');
  const respSecret = toSecret(opts.responseSecret, 'responseSecret');
  // enforce the replay-store retains a nonce across the whole acceptance horizon (both
  // freshness directions) plus margin — else a still-acceptable nonce could be pruned.
  if (!(opts.nonceStore.retentionMs >= 2 * freshnessMs)) throw new ContractValidationError('nonceStore.retentionMs must be >= 2x freshnessMs (acceptance horizon + margin)');

  const send = (res: ServerResponse, status: number, obj: unknown): void => {
    const payload = canonicalize(obj);
    res.statusCode = status;
    res.setHeader('content-type', CONTENT_TYPE);
    res.setHeader('content-length', String(Buffer.byteLength(payload, 'utf8')));
    res.end(payload);
  };

  return (req, res) => {
    void (async () => {
      try {
        if (req.method !== 'POST') return send(res, 405, { error: 'method not allowed' });
        if ((req.url ?? '') !== opts.expectedPath) return send(res, 404, { error: 'not found' });
        if (!isJsonMime(req.headers['content-type'])) return send(res, 415, { error: 'unsupported media type' });

        let body: Buffer;
        try { body = await readBodyCapped(req, maxBodyBytes, bodyReadMs); }
        catch (e) { return send(res, e instanceof Error && e.message === 'timeout' ? 408 : 413, { error: 'body read failed' }); }

        const keyId = header(req, HDR.keyId), ts = header(req, HDR.ts), nonce = header(req, HDR.nonce), sig = header(req, HDR.sig);
        if (!keyId || !ts || !nonce || !sig || !KEY_ID_RE.test(keyId) || !NONCE_RE.test(nonce)) return send(res, 401, { error: 'unauthenticated' });
        const secretRaw = opts.resolveRequestKey(keyId);
        if (secretRaw === null) return send(res, 401, { error: 'unknown key' });
        const secretBuf = Buffer.isBuffer(secretRaw) ? secretRaw : Buffer.from(String(secretRaw), 'utf8');
        if (secretBuf.length < 32) return send(res, 500, { error: 'ingest failed' }); // misconfigured key, don't leak
        const tsNum = Number(ts);
        if (!Number.isSafeInteger(tsNum) || Math.abs(now() - tsNum) > freshnessMs) return send(res, 401, { error: 'stale or invalid timestamp' });
        const bodyDigest = sha256hex(body);
        const expected = hmac(secretBuf, frame(REQ_DOMAIN, keyId, 'POST', req.url ?? '', ts, nonce, bodyDigest));
        if (!ctEqualB64u(sig, expected)) return send(res, 401, { error: 'bad signature' });
        if (!(await opts.nonceStore.checkAndStore(nonce))) return send(res, 401, { error: 'replay' });

        let parsed: { record: OutboxRecord<TskHotpMutation>; head: SignedStreamHead };
        try { parsed = JSON.parse(body.toString('utf8')) as typeof parsed; } catch { return send(res, 400, { error: 'invalid json' }); }
        if (!isPlainObject(parsed) || !isPlainObject(parsed.record) || !isPlainObject(parsed.head)) return send(res, 400, { error: 'invalid envelope' });
        try { assertStreamHeadBinds(parsed.record, parsed.head); } catch { return send(res, 400, { error: 'head does not bind record' }); }

        const receipt = await opts.receive(parsed.record, parsed.head);
        const envelopeSig = b64u(hmac(respSecret, frame(ACK_DOMAIN, opts.responseKeyId, nonce, bodyDigest, req.url ?? '', canonicalize(receipt))));
        return send(res, 200, { v: ACK_DOMAIN, keyId: opts.responseKeyId, challenge: nonce, requestDigest: bodyDigest, receipt, sig: envelopeSig });
      } catch {
        try { send(res, 500, { error: 'ingest failed' }); } catch { /* response already gone */ }
      }
    })();
  };
}

function header(req: IncomingMessage, name: string): string | null {
  const v = req.headers[name];
  return typeof v === 'string' ? v : Array.isArray(v) ? (v[0] ?? null) : null;
}
function readBodyCapped(req: IncomingMessage, maxBytes: number, readMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const timer = setTimeout(() => { req.destroy(); reject(new Error('timeout')); }, readMs);
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > maxBytes) { clearTimeout(timer); req.destroy(); reject(new Error('too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks)); });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}
