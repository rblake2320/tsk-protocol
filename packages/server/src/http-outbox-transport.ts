import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

import { ContractValidationError, canonicalize, assertStreamHeadBinds } from './ha-outbox-contract.js';
import type { OutboxRecord, SignedStreamHead, TskHotpMutation, ReceiverDecision } from './ha-outbox-contract.js';
import type { TskAckReceipt, TskAckReceiptVerifier, TskOutboxTransport } from './tsk-hotp-outbox-pg.js';

/**
 * Authenticated, decision-bound AND request-attempt-bound HTTP transport for the
 * durable HOTP-outbox publisher -> receiver hop (node A -> node B). It is the ONLY
 * A->B path in the two-node topology, so it is treated as fully untrusted.
 *
 *  - REQUEST auth: HMAC-SHA256 over a length-PREFIXED framing of
 *    (version, keyId, method, exact-path, timestamp, nonce, sha256(raw body)) — no
 *    delimiter ambiguity, keyId+version bound in. The receiver authorizes the EXACT
 *    path, checks freshness, verifies the signature over the RAW BYTES, and burns a
 *    DURABLE single-use nonce, all BEFORE parsing or applying anything.
 *  - RESPONSE binding: the reply is an envelope MAC'd (framed) over the fresh request
 *    nonce (challenge) + request body digest + path + the canonical receipt, so a prior
 *    signed 'applied' receipt CANNOT be replayed for a different attempt. Inside sits a
 *    decision-bound `TskAckReceipt` the publisher verifies separately.
 *  - Any network/HTTP/timeout/oversize/malformed/auth condition THROWS (retriable,
 *    row stays undelivered) and NEVER fabricates an ack (fail-closed ambiguity,
 *    reconciled by the receiver's idempotency -> duplicate-ok).
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
const RECEIPT_KEYS: ReadonlyArray<[keyof TskAckReceipt, 'string' | 'number']> = [
  ['streamId', 'string'], ['sourceEpoch', 'string'], ['sequence', 'number'], ['opDigest', 'string'],
  ['decision', 'string'], ['receiverId', 'string'], ['keyId', 'string'], ['issuedAt', 'string'], ['signature', 'string'],
];

const sha256hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const hmac = (secret: Buffer, msg: Buffer): Buffer => createHmac('sha256', secret).update(msg).digest();
const b64u = (b: Buffer): string => b.toString('base64url');
function ctEqualB64u(a: string, expected: Buffer): boolean {
  let got: Buffer;
  try { got = Buffer.from(a, 'base64url'); } catch { return false; }
  return got.length === expected.length && timingSafeEqual(got, expected);
}
/** Unambiguous length-prefixed framing: each field is uint32-BE(len) || bytes, so no
 *  field value (path, nonce, keyId) can be shifted across a delimiter. */
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
function isPlainObject(o: unknown): o is Record<string, unknown> {
  if (o === null || typeof o !== 'object') return false;
  const p = Object.getPrototypeOf(o);
  return p === Object.prototype || p === null;
}
/** Strictly validate a JSON-parsed receipt to exact keys + primitive types, then FREEZE. */
function strictReceipt(o: unknown): TskAckReceipt {
  if (!isPlainObject(o)) throw new ContractValidationError('receipt is not a plain object');
  for (const [k, t] of RECEIPT_KEYS) if (typeof o[k] !== t) throw new ContractValidationError(`receipt.${String(k)} must be ${t}`);
  const r: TskAckReceipt = {
    streamId: o.streamId as string, sourceEpoch: o.sourceEpoch as string, sequence: o.sequence as number, opDigest: o.opDigest as string,
    decision: o.decision as ReceiverDecision, receiverId: o.receiverId as string, keyId: o.keyId as string, issuedAt: o.issuedAt as string, signature: o.signature as string,
  };
  return Object.freeze(r);
}

// ── durable replay-nonce store ───────────────────────────────────────────────

/** Records a single-use nonce for its retention window. Returns true if FRESH (first
 *  use), false if already seen (replay). MUST be durable + retained AT LEAST the request
 *  acceptance horizon, and MUST use its OWN authoritative clock for expiry. */
export interface ReplayNonceStore {
  checkAndStore(nonce: string): Promise<boolean>;
}

export class MemoryReplayNonceStore implements ReplayNonceStore {
  private readonly seen = new Map<string, number>();
  constructor(private readonly retentionMs = DEFAULT_NONCE_RETENTION_MS, private readonly now: () => number = Date.now) {}
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
  /** Retention MUST be >= the receiver freshness window (+ a safety margin) so a nonce
   *  cannot be pruned while a replay within the acceptance horizon is still possible. */
  retentionMs?: number;
  /** Fail closed if the DB clock and app clock diverge beyond this (a clock-ahead DB
   *  could otherwise prune a still-acceptable nonce). */
  maxClockSkewMs?: number;
  now?: () => number;
}

/** Durable replay-nonce store. Expiry is computed by the DB (`now() + retention`) — never
 *  from a sender-supplied timestamp — pruning uses the same DB clock, the DB/app skew is
 *  asserted, and insertion is a single atomic INSERT ... ON CONFLICT DO NOTHING. */
export class PgReplayNonceStore implements ReplayNonceStore {
  private readonly retentionMs: number;
  private readonly maxClockSkewMs: number;
  private readonly now: () => number;
  constructor(private readonly query: QueryFn, opts: PgReplayNonceStoreOptions = {}) {
    this.retentionMs = opts.retentionMs ?? DEFAULT_NONCE_RETENTION_MS;
    this.maxClockSkewMs = opts.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
    this.now = opts.now ?? Date.now;
  }
  async checkAndStore(nonce: string): Promise<boolean> {
    const dbNow = Number((await this.query("SELECT (extract(epoch from now()) * 1000)::bigint::text AS ms")).rows[0]?.ms);
    if (!Number.isFinite(dbNow) || Math.abs(dbNow - this.now()) > this.maxClockSkewMs) {
      throw new ContractValidationError('replay-nonce store: DB/app clock skew exceeds the allowed bound (fail closed)');
    }
    // prune only rows already past their DB-authored retention (never a still-acceptable one)
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
  text(): Promise<string>;
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
    this.retriable = options?.retriable ?? true; // default: undelivered -> retry
  }
}

export interface HttpOutboxTransportOptions {
  url: string;
  fetch: FetchLike;
  requestKeyId: string;
  requestSecret: Buffer | string;
  /** Shared key that MACs the response envelope (challenge binding). */
  responseKeyId: string;
  responseSecret: Buffer | string;
  ackVerifier: TskAckReceiptVerifier;
  now?: () => number;
  nonce?: () => string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  /** Preflight cap on the request body; a record exceeding it is a TERMINAL (non-retriable)
   *  delivery error, not retried forever against the receiver's own body cap. Must be
   *  <= the receiver's maxBodyBytes. */
  maxRequestBytes?: number;
}

export class HttpOutboxTransport implements TskOutboxTransport {
  private readonly url: URL;
  private readonly path: string;
  private readonly reqSecret: Buffer;
  private readonly respSecret: Buffer;
  private readonly now: () => number;
  private readonly nonce: () => string;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxRequestBytes: number;

  constructor(private readonly opts: HttpOutboxTransportOptions) {
    if (typeof opts.fetch !== 'function') throw new ContractValidationError('fetch is required');
    if (!KEY_ID_RE.test(opts.requestKeyId)) throw new ContractValidationError('invalid requestKeyId');
    if (!KEY_ID_RE.test(opts.responseKeyId)) throw new ContractValidationError('invalid responseKeyId');
    this.url = new URL(opts.url);
    if (this.url.protocol !== 'http:' && this.url.protocol !== 'https:') throw new ContractValidationError('transport url must be http(s)');
    this.path = this.url.pathname + this.url.search;
    this.reqSecret = toSecret(opts.requestSecret, 'requestSecret');
    this.respSecret = toSecret(opts.responseSecret, 'responseSecret');
    this.now = opts.now ?? Date.now;
    this.nonce = opts.nonce ?? (() => b64u(randomBytes(24))); // CSPRNG
    this.timeoutMs = posInt(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, 'timeoutMs');
    this.maxResponseBytes = posInt(opts.maxResponseBytes ?? DEFAULT_MAX_BODY_BYTES, 'maxResponseBytes');
    this.maxRequestBytes = posInt(opts.maxRequestBytes ?? DEFAULT_MAX_BODY_BYTES, 'maxRequestBytes');
  }

  async deliverAndAwaitAck(record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead): Promise<TskAckReceipt> {
    const body = canonicalize({ record, head });
    const bodyBuf = Buffer.from(body, 'utf8');
    if (bodyBuf.length > this.maxRequestBytes) {
      throw new OutboxTransportError(`request body ${bodyBuf.length}B exceeds maxRequestBytes ${this.maxRequestBytes}B`, { retriable: false });
    }
    const bodyDigest = sha256hex(bodyBuf);
    const ts = String(this.now());
    const nonce = this.nonce();
    const sig = b64u(hmac(this.reqSecret, frame(REQ_DOMAIN, this.opts.requestKeyId, 'POST', this.path, ts, nonce, bodyDigest)));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new OutboxTransportError(`transport timeout after ${this.timeoutMs}ms`)), this.timeoutMs);
    try {
      let res: FetchResponseLike;
      try {
        res = await this.opts.fetch(this.url.toString(), {
          method: 'POST',
          headers: { 'content-type': CONTENT_TYPE, [HDR.keyId]: this.opts.requestKeyId, [HDR.ts]: ts, [HDR.nonce]: nonce, [HDR.sig]: sig },
          body,
          signal: controller.signal,
          redirect: 'manual',
        });
      } catch (err) {
        throw err instanceof OutboxTransportError ? err : new OutboxTransportError('transport request failed', { cause: err });
      }
      if (res.status >= 300 && res.status < 400) throw new OutboxTransportError(`transport received a redirect (${res.status})`);
      if (res.status !== 200) throw new OutboxTransportError(`transport received HTTP ${res.status}`);
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.toLowerCase().startsWith(CONTENT_TYPE)) throw new OutboxTransportError(`transport reply content-type '${ct}' is not ${CONTENT_TYPE}`);
      const len = Number(res.headers.get('content-length') ?? 'NaN');
      if (Number.isFinite(len) && len > this.maxResponseBytes) throw new OutboxTransportError('transport reply too large');
      let text: string;
      try { text = await res.text(); } catch (err) { throw err instanceof OutboxTransportError ? err : new OutboxTransportError('failed to read transport reply', { cause: err }); }
      if (Buffer.byteLength(text, 'utf8') > this.maxResponseBytes) throw new OutboxTransportError('transport reply too large');
      return await this.verifyEnvelope(text, record, nonce, bodyDigest);
    } finally {
      clearTimeout(timer); // cleared only AFTER the body read (or its abort) settles
    }
  }

  private async verifyEnvelope(text: string, record: OutboxRecord<TskHotpMutation>, sentNonce: string, sentBodyDigest: string): Promise<TskAckReceipt> {
    let env: unknown;
    try { env = JSON.parse(text); } catch (err) { throw new OutboxTransportError('transport reply is not valid JSON', { cause: err }); }
    if (!isPlainObject(env) || env.v !== ACK_DOMAIN || env.keyId !== this.opts.responseKeyId
      || typeof env.challenge !== 'string' || typeof env.requestDigest !== 'string' || typeof env.sig !== 'string') {
      throw new OutboxTransportError('transport reply envelope malformed');
    }
    // request-attempt binding: a replayed prior envelope has a different challenge/digest.
    if (env.challenge !== sentNonce || env.requestDigest !== sentBodyDigest) throw new OutboxTransportError('transport reply not bound to this request attempt');
    let receipt: TskAckReceipt;
    try { receipt = strictReceipt(env.receipt); } catch (err) { throw new OutboxTransportError('transport reply receipt malformed', { cause: err }); }
    const mac = hmac(this.respSecret, frame(ACK_DOMAIN, this.opts.responseKeyId, env.challenge, env.requestDigest, this.path, canonicalize(receipt)));
    if (!ctEqualB64u(env.sig, mac)) throw new OutboxTransportError('transport reply envelope MAC invalid');
    // decision binding to THIS record + the TSK-level receipt signature (publisher trust).
    if (receipt.streamId !== record.streamId || receipt.sourceEpoch !== record.sourceEpoch || receipt.sequence !== record.sequence || receipt.opDigest !== record.opDigest) {
      throw new OutboxTransportError('transport reply does not bind to the delivered record');
    }
    try { await this.opts.ackVerifier.verify(receipt, record); } catch (err) { throw new OutboxTransportError('transport reply ack signature/authorization invalid', { cause: err }); }
    return receipt;
  }
}

function posInt(n: number, label: string): number {
  if (!Number.isSafeInteger(n) || n < 1) throw new ContractValidationError(`${label} must be a positive safe integer`);
  return n;
}

// ── receiver: authenticated ingest handler ───────────────────────────────────

export interface HttpOutboxReceiverOptions {
  /** The EXACT request target this receiver serves (e.g. '/ingest'). Authorized before
   *  anything else so a broadly-mounted handler cannot process a correctly-signed request
   *  for another path. */
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
        if ((req.url ?? '') !== opts.expectedPath) return send(res, 404, { error: 'not found' }); // authorize exact path first
        const ct = String(req.headers['content-type'] ?? '');
        if (!ct.toLowerCase().startsWith(CONTENT_TYPE)) return send(res, 415, { error: 'unsupported media type' });

        let body: Buffer;
        try { body = await readBodyCapped(req, maxBodyBytes, bodyReadMs); }
        catch (e) { return send(res, e instanceof Error && e.message === 'timeout' ? 408 : 413, { error: 'body read failed' }); }

        // ── authenticate RAW BYTES before any parsing ──
        const keyId = header(req, HDR.keyId), ts = header(req, HDR.ts), nonce = header(req, HDR.nonce), sig = header(req, HDR.sig);
        if (!keyId || !ts || !nonce || !sig || !KEY_ID_RE.test(keyId) || !NONCE_RE.test(nonce)) return send(res, 401, { error: 'unauthenticated' });
        const secretRaw = opts.resolveRequestKey(keyId);
        if (secretRaw === null) return send(res, 401, { error: 'unknown key' });
        const secret = Buffer.isBuffer(secretRaw) ? secretRaw : Buffer.from(String(secretRaw), 'utf8');
        const tsNum = Number(ts);
        if (!Number.isFinite(tsNum) || Math.abs(now() - tsNum) > freshnessMs) return send(res, 401, { error: 'stale or invalid timestamp' });
        const bodyDigest = sha256hex(body);
        const expected = hmac(secret, frame(REQ_DOMAIN, keyId, 'POST', req.url ?? '', ts, nonce, bodyDigest));
        if (!ctEqualB64u(sig, expected)) return send(res, 401, { error: 'bad signature' });
        if (!(await opts.nonceStore.checkAndStore(nonce))) return send(res, 401, { error: 'replay' }); // durable single-use, only after a valid sig

        // ── parse + structurally validate, then apply ──
        let parsed: { record: OutboxRecord<TskHotpMutation>; head: SignedStreamHead };
        try { parsed = JSON.parse(body.toString('utf8')) as typeof parsed; } catch { return send(res, 400, { error: 'invalid json' }); }
        if (!isPlainObject(parsed) || !isPlainObject(parsed.record) || !isPlainObject(parsed.head)) return send(res, 400, { error: 'invalid envelope' });
        try { assertStreamHeadBinds(parsed.record, parsed.head); } catch { return send(res, 400, { error: 'head does not bind record' }); }

        const receipt = await opts.receive(parsed.record, parsed.head);
        // request-attempt-bound envelope: MAC over the fresh nonce + body digest + path + receipt.
        const macMsg = frame(ACK_DOMAIN, opts.responseKeyId, nonce, bodyDigest, req.url ?? '', canonicalize(receipt));
        const envelopeSig = b64u(hmac(respSecret, macMsg));
        return send(res, 200, { v: ACK_DOMAIN, keyId: opts.responseKeyId, challenge: nonce, requestDigest: bodyDigest, receipt, sig: envelopeSig });
      } catch (err) {
        try { send(res, 500, { error: 'ingest failed', detail: err instanceof Error ? err.message : String(err) }); } catch { /* response already gone */ }
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
    const timer = setTimeout(() => { req.destroy(); reject(new Error('timeout')); }, readMs); // slowloris guard
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > maxBytes) { clearTimeout(timer); req.destroy(); reject(new Error('too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks)); });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}
