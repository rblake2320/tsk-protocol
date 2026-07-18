import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

import { ContractValidationError, canonicalize, assertStreamHeadBinds } from './ha-outbox-contract.js';
import type { OutboxRecord, SignedStreamHead, TskHotpMutation } from './ha-outbox-contract.js';
import type { TskAckReceipt, TskAckReceiptVerifier, TskOutboxTransport } from './tsk-hotp-outbox-pg.js';

/**
 * Authenticated, decision-bound HTTP transport for the durable HOTP-outbox
 * publisher -> receiver hop (node A -> node B). It is the ONLY A->B path in the
 * two-node topology, so it is treated as fully untrusted:
 *
 *  - Every request is HMAC-SHA256 signed over method + path + timestamp + nonce +
 *    the exact bounded raw-body digest, under a keyId (rotation: the receiver may
 *    accept several keyIds during overlap). The receiver AUTHENTICATES THE RAW
 *    BYTES (freshness window, durable single-use nonce, constant-time signature)
 *    BEFORE any JSON parsing or semantic processing.
 *  - The reply is a receiver-signed `TskAckReceipt` whose signature binds the
 *    decision to THIS exact record; the client verifies it and refuses a receipt
 *    that does not bind or does not verify.
 *  - A transient network / HTTP / timeout / oversize / malformed-reply condition
 *    THROWS (leaving the row undelivered for retry) and NEVER fabricates an ack.
 *    Ambiguity (request sent, reply lost) is therefore fail-closed retriable and
 *    reconciled by the receiver's idempotency (redelivery -> duplicate-ok).
 *
 * BOUNDARY: HMAC shared-secret auth is the slice-1 mechanism; mTLS is a deployment
 * upgrade. This is NOT an HA claim — #10 stays OPEN until the full acceptance drill
 * (crash / snapshot+tail resync / promotion / Redis authority failover) passes.
 */

const HDR = { keyId: 'x-tsk-key-id', ts: 'x-tsk-timestamp', nonce: 'x-tsk-nonce', sig: 'x-tsk-signature' } as const;
const CONTENT_TYPE = 'application/json';
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_FRESHNESS_MS = 30_000;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;

const sha256hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const hmac = (secret: Buffer, msg: string): Buffer => createHmac('sha256', secret).update(msg, 'utf8').digest();
const b64u = (b: Buffer): string => b.toString('base64url');
function ctEqualB64u(a: string, expected: Buffer): boolean {
  let got: Buffer;
  try { got = Buffer.from(a, 'base64url'); } catch { return false; }
  return got.length === expected.length && timingSafeEqual(got, expected);
}
/** Canonical bytes to sign/verify: newline-joined, unambiguous, order-fixed. */
function signingString(method: string, path: string, ts: string, nonce: string, bodyDigestHex: string): string {
  return `TSKv1\n${method}\n${path}\n${ts}\n${nonce}\n${bodyDigestHex}`;
}

// ── replay-nonce store (durable) ─────────────────────────────────────────────

/** Records a single-use nonce until `expiresAtMs`. Returns true if this nonce is
 *  FRESH (first use), false if it was already seen (a replay). MUST be durable so
 *  a receiver restart cannot reopen the replay window. */
export interface ReplayNonceStore {
  checkAndStore(nonce: string, expiresAtMs: number): Promise<boolean>;
}

/** Non-durable store for hermetic unit tests only. */
export class MemoryReplayNonceStore implements ReplayNonceStore {
  private readonly seen = new Map<string, number>();
  constructor(private readonly now: () => number = Date.now) {}
  async checkAndStore(nonce: string, expiresAtMs: number): Promise<boolean> {
    const t = this.now();
    for (const [k, exp] of this.seen) if (exp <= t) this.seen.delete(k);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, expiresAtMs);
    return true;
  }
}

/** DDL for the durable nonce table used by {@link PgReplayNonceStore}. */
export const TSK_TRANSPORT_NONCE_SCHEMA = `
CREATE TABLE IF NOT EXISTS tsk_transport_nonce (
  nonce      text        PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS tsk_transport_nonce_expiry ON tsk_transport_nonce (expires_at);
`.trim();

type QueryFn = (sql: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[]; rowCount: number }>;

/** Durable replay-nonce store backed by a single INSERT ... ON CONFLICT DO NOTHING
 *  (atomic first-writer-wins). Opportunistically prunes expired rows. */
export class PgReplayNonceStore implements ReplayNonceStore {
  constructor(private readonly query: QueryFn) {}
  async checkAndStore(nonce: string, expiresAtMs: number): Promise<boolean> {
    await this.query('DELETE FROM tsk_transport_nonce WHERE expires_at < now()');
    const res = await this.query(
      "INSERT INTO tsk_transport_nonce (nonce, expires_at) VALUES ($1, to_timestamp($2 / 1000.0)) ON CONFLICT (nonce) DO NOTHING",
      [nonce, expiresAtMs],
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

/** Retriable network/transport failure: leaves the outbox row undelivered so the
 *  publisher retries. NEVER thrown after a verified ack. */
export class OutboxTransportError extends Error {
  readonly retriable = true;
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'OutboxTransportError';
  }
}

export interface HttpOutboxTransportOptions {
  url: string;
  fetch: FetchLike;
  requestKeyId: string;
  requestSecret: Buffer | string;
  ackVerifier: TskAckReceiptVerifier;
  now?: () => number;
  nonce?: () => string;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export class HttpOutboxTransport implements TskOutboxTransport {
  private readonly url: URL;
  private readonly path: string;
  private readonly secret: Buffer;
  private readonly now: () => number;
  private readonly nonce: () => string;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(private readonly opts: HttpOutboxTransportOptions) {
    if (typeof opts.fetch !== 'function') throw new ContractValidationError('fetch is required');
    if (!KEY_ID_RE.test(opts.requestKeyId)) throw new ContractValidationError('invalid requestKeyId');
    this.url = new URL(opts.url);
    if (this.url.protocol !== 'http:' && this.url.protocol !== 'https:') throw new ContractValidationError('transport url must be http(s)');
    this.path = this.url.pathname + this.url.search;
    this.secret = Buffer.isBuffer(opts.requestSecret) ? opts.requestSecret : Buffer.from(String(opts.requestSecret), 'utf8');
    if (this.secret.length < 32) throw new ContractValidationError('requestSecret must be >= 32 bytes');
    this.now = opts.now ?? Date.now;
    this.nonce = opts.nonce ?? (() => b64u(createHash('sha256').update(`${this.now()}:${Math.random()}`).digest()).slice(0, 32));
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxResponseBytes = opts.maxResponseBytes ?? DEFAULT_MAX_BODY_BYTES;
  }

  async deliverAndAwaitAck(record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead): Promise<TskAckReceipt> {
    const body = canonicalize({ record, head });
    const bodyBuf = Buffer.from(body, 'utf8');
    const ts = String(this.now());
    const nonce = this.nonce();
    const sig = b64u(hmac(this.secret, signingString('POST', this.path, ts, nonce, sha256hex(bodyBuf))));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new OutboxTransportError(`transport timeout after ${this.timeoutMs}ms`)), this.timeoutMs);
    let res: FetchResponseLike;
    try {
      res = await this.opts.fetch(this.url.toString(), {
        method: 'POST',
        headers: {
          'content-type': CONTENT_TYPE,
          [HDR.keyId]: this.opts.requestKeyId,
          [HDR.ts]: ts,
          [HDR.nonce]: nonce,
          [HDR.sig]: sig,
        },
        body,
        signal: controller.signal,
        redirect: 'manual', // a redirect is never a valid ack path
      });
    } catch (err) {
      throw err instanceof OutboxTransportError ? err : new OutboxTransportError('transport request failed', { cause: err });
    } finally {
      clearTimeout(timer);
    }
    if (res.status >= 300 && res.status < 400) throw new OutboxTransportError(`transport received a redirect (${res.status})`);
    if (res.status !== 200) throw new OutboxTransportError(`transport received HTTP ${res.status}`);
    const ct = res.headers.get('content-type') ?? '';
    if (!ct.toLowerCase().startsWith(CONTENT_TYPE)) throw new OutboxTransportError(`transport reply content-type '${ct}' is not ${CONTENT_TYPE}`);
    const len = Number(res.headers.get('content-length') ?? 'NaN');
    if (Number.isFinite(len) && len > this.maxResponseBytes) throw new OutboxTransportError('transport reply too large');
    let text: string;
    try { text = await res.text(); } catch (err) { throw new OutboxTransportError('failed to read transport reply', { cause: err }); }
    if (Buffer.byteLength(text, 'utf8') > this.maxResponseBytes) throw new OutboxTransportError('transport reply too large');
    let ack: TskAckReceipt;
    try { ack = JSON.parse(text) as TskAckReceipt; } catch (err) { throw new OutboxTransportError('transport reply is not valid JSON', { cause: err }); }
    // the receipt MUST bind to exactly the record we delivered (decision-bound)...
    if (ack === null || typeof ack !== 'object'
      || ack.streamId !== record.streamId || ack.sourceEpoch !== record.sourceEpoch
      || ack.sequence !== record.sequence || ack.opDigest !== record.opDigest) {
      throw new OutboxTransportError('transport reply does not bind to the delivered record');
    }
    // ...and its signature MUST verify (fail-closed: a forged/swapped-decision ack throws).
    try { await this.opts.ackVerifier.verify(ack, record); } catch (err) { throw new OutboxTransportError('transport reply ack signature/authorization invalid', { cause: err }); }
    return ack;
  }
}

// ── receiver: authenticated ingest handler ───────────────────────────────────

export interface HttpOutboxReceiverOptions {
  /** Resolve a request keyId to its secret, or null if unknown. Returning a valid
   *  secret for MULTIPLE keyIds implements rotation overlap. */
  resolveRequestKey(keyId: string): Buffer | string | null;
  /** Applies the delivered record and returns the receiver-signed decision ack. */
  receive(record: OutboxRecord<TskHotpMutation>, head: SignedStreamHead): Promise<TskAckReceipt>;
  nonceStore: ReplayNonceStore;
  now?: () => number;
  freshnessMs?: number;
  maxBodyBytes?: number;
}

/** node:http request handler that authenticates the RAW BYTES before any semantic
 *  processing, then applies the record and replies with the signed ack. */
export function createHttpOutboxReceiver(opts: HttpOutboxReceiverOptions): (req: IncomingMessage, res: ServerResponse) => void {
  const now = opts.now ?? Date.now;
  const freshnessMs = opts.freshnessMs ?? DEFAULT_FRESHNESS_MS;
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

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
        const ct = String(req.headers['content-type'] ?? '');
        if (!ct.toLowerCase().startsWith(CONTENT_TYPE)) return send(res, 415, { error: 'unsupported media type' });

        // read the raw bytes under a hard cap
        let body: Buffer;
        try { body = await readBodyCapped(req, maxBodyBytes); } catch { return send(res, 413, { error: 'payload too large' }); }

        // ── authenticate RAW BYTES before any parsing ──
        const keyId = header(req, HDR.keyId);
        const ts = header(req, HDR.ts);
        const nonce = header(req, HDR.nonce);
        const sig = header(req, HDR.sig);
        if (!keyId || !ts || !nonce || !sig || !KEY_ID_RE.test(keyId) || !NONCE_RE.test(nonce)) return send(res, 401, { error: 'unauthenticated' });
        const secretRaw = opts.resolveRequestKey(keyId);
        if (secretRaw === null) return send(res, 401, { error: 'unknown key' });
        const secret = Buffer.isBuffer(secretRaw) ? secretRaw : Buffer.from(String(secretRaw), 'utf8');
        const tsNum = Number(ts);
        if (!Number.isFinite(tsNum) || Math.abs(now() - tsNum) > freshnessMs) return send(res, 401, { error: 'stale or invalid timestamp' });
        const expected = hmac(secret, signingString('POST', req.url ?? '', ts, nonce, sha256hex(body)));
        if (!ctEqualB64u(sig, expected)) return send(res, 401, { error: 'bad signature' });
        // durable single-use nonce (replay rejection) — only after the signature is valid
        if (!(await opts.nonceStore.checkAndStore(nonce, tsNum + freshnessMs))) return send(res, 401, { error: 'replay' });

        // ── only now: parse + structurally validate ──
        let parsed: { record: OutboxRecord<TskHotpMutation>; head: SignedStreamHead };
        try { parsed = JSON.parse(body.toString('utf8')) as typeof parsed; } catch { return send(res, 400, { error: 'invalid json' }); }
        if (!parsed || typeof parsed !== 'object' || typeof parsed.record !== 'object' || typeof parsed.head !== 'object') return send(res, 400, { error: 'invalid envelope' });
        try { assertStreamHeadBinds(parsed.record, parsed.head); } catch { return send(res, 400, { error: 'head does not bind record' }); }

        const ack = await opts.receive(parsed.record, parsed.head);
        return send(res, 200, ack);
      } catch (err) {
        // fail closed: any internal error is a delivery failure the publisher retries
        try { send(res, 500, { error: 'ingest failed', detail: err instanceof Error ? err.message : String(err) }); } catch { /* response already gone */ }
      }
    })();
  };
}

function header(req: IncomingMessage, name: string): string | null {
  const v = req.headers[name];
  return typeof v === 'string' ? v : Array.isArray(v) ? (v[0] ?? null) : null;
}
function readBodyCapped(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > maxBytes) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
