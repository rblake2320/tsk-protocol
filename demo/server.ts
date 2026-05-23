/**
 * TSK Demo Server
 *
 * Real backend wired to @tsk/server and @tsk/core — serves the demo UI and
 * validates every request through the full TSK verification pipeline.
 *
 * Run:  npx tsx server.ts
 * Open: http://localhost:3200
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync, existsSync, appendFileSync } from 'node:fs';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createTSKServer,
  verifyTSKRequest,
} from '../packages/server/src/index.ts';

const PORT      = 3200;
const DEMO_DIR  = dirname(fileURLToPath(import.meta.url));
const EVENT_LOG = join(DEMO_DIR, 'analytics.ndjson');

// ── In-memory analytics store ────────────────────────────────────────────────
interface AnalyticsEvent {
  event: string; session: string; ts: number; site: string; [k: string]: unknown;
}
const analyticsEvents: AnalyticsEvent[] = [];

const { store, provisioner, anomaly } = createTSKServer();

// ── Helpers ──────────────────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function cors(res: ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type,X-TSK-Client-ID,X-TSK-Key,X-TSK-Version');
}

function json(res: ServerResponse, status: number, data: unknown): void {
  cors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function log(method: string, path: string, result: string): void {
  const ts = new Date().toISOString().slice(11, 23);
  console.log(`[${ts}] ${method} ${path} => ${result}`);
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.jsx':  'application/javascript',
  '.css':  'text/css',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.json': 'application/json',
};

function serveFile(res: ServerResponse, filePath: string): boolean {
  if (!existsSync(filePath)) return false;
  const ext  = extname(filePath);
  const mime = MIME[ext] ?? 'application/octet-stream';
  cors(res);
  res.writeHead(200, { 'Content-Type': mime });
  res.end(readFileSync(filePath));
  return true;
}

// ── TSK Verification Helper ──────────────────────────────────────────────────

async function verifyTSK(req: IncomingMessage, ip: string) {
  return verifyTSKRequest(
    { headers: req.headers as Record<string, string | string[] | undefined> },
    store,
    { anomaly, ipAddress: ip },
  );
}

// ── HTTP Server ──────────────────────────────────────────────────────────────

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const method = (req.method ?? 'GET').toUpperCase();
  const url    = req.url ?? '/';
  const path   = url.split('?')[0];
  const ip     = req.socket.remoteAddress ?? '0.0.0.0';

  // ── CORS preflight ─────────────────────────────────────────────────────────
  if (method === 'OPTIONS') {
    cors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // ── Static files ─────────────────────────────────────────────────────────
    if (method === 'GET' && (path === '/' || path === '/index.html')) {
      if (serveFile(res, join(DEMO_DIR, 'index.html'))) return;
    }
    if (method === 'GET' && path.startsWith('/assets/')) {
      const file = join(DEMO_DIR, path);
      if (serveFile(res, file)) return;
    }
    // Serve JSX files and other demo assets
    if (method === 'GET' && path.endsWith('.jsx')) {
      const file = join(DEMO_DIR, path.replace(/^\//, ''));
      if (serveFile(res, file)) return;
    }

    // ── Provision ────────────────────────────────────────────────────────────
    if (method === 'POST' && path === '/tsk/provision') {
      const result = await provisioner.provision({}, ip);
      if (!result.ok) {
        log(method, path, `PROVISION DENIED (${result.error})`);
        json(res, 400, { error: result.error });
        return;
      }
      log(method, path, `PROVISIONED client=${result.clientId}`);
      json(res, 200, {
        ok: true,
        clientId: result.clientId,
        provisionPayload: result.provisionPayload,
        sharedSecret: result.tumblerMap!.sharedSecret,
        serverMap: result.tumblerMap,
      });
      return;
    }

    // ── Revoke ───────────────────────────────────────────────────────────────
    if (method === 'POST' && path === '/tsk/revoke') {
      const rawBody = await readBody(req);
      let body: { clientId?: string };
      try {
        body = JSON.parse(rawBody.toString()) as { clientId?: string };
      } catch {
        json(res, 400, { error: 'invalid_json' });
        return;
      }
      if (!body.clientId) {
        json(res, 400, { error: 'missing_client_id' });
        return;
      }
      await store.delete(body.clientId);
      log(method, path, `REVOKED client=${body.clientId}`);
      json(res, 200, { revoked: true });
      return;
    }

    // ── Anomaly ──────────────────────────────────────────────────────────────
    if (method === 'GET' && path === '/tsk/anomaly') {
      // Gather scores for all known clients
      const clients = await store.list();
      const scores: Record<string, unknown> = {};
      for (const cid of clients) {
        scores[cid] = anomaly.score(cid);
      }
      json(res, 200, {
        trackedClients: anomaly.trackedClients,
        trackedIPs: anomaly.trackedIPs,
        scores,
      });
      return;
    }

    // ── TSK-Protected: GET /api/data ─────────────────────────────────────────
    if (method === 'GET' && path === '/api/data') {
      const result = await verifyTSK(req, ip);
      if (!result.ok) {
        log(method, path, `DENIED (${result.error})`);
        json(res, 401, { error: result.error });
        return;
      }
      log(method, path, `PASS client=${result.clientId}`);
      json(res, 200, { ok: true, message: 'TSK verified', clientId: result.clientId, ts: Date.now() });
      return;
    }

    // ── TSK-Protected: GET /api/secret ───────────────────────────────────────
    if (method === 'GET' && path === '/api/secret') {
      const result = await verifyTSK(req, ip);
      if (!result.ok) {
        log(method, path, `DENIED (${result.error})`);
        json(res, 401, { error: result.error });
        return;
      }
      log(method, path, `PASS client=${result.clientId}`);
      json(res, 200, { secret: 'sensitive-data', clientId: result.clientId });
      return;
    }

    // ── TSK-Protected: POST /api/action ──────────────────────────────────────
    if (method === 'POST' && path === '/api/action') {
      const result = await verifyTSK(req, ip);
      if (!result.ok) {
        log(method, path, `DENIED (${result.error})`);
        json(res, 401, { error: result.error });
        return;
      }
      log(method, path, `PASS client=${result.clientId}`);
      json(res, 200, { done: true, clientId: result.clientId });
      return;
    }

    // ── Analytics: POST /analytics/event ────────────────────────────────────
    if (method === 'POST' && path === '/analytics/event') {
      const rawBody = await readBody(req);
      try {
        const evt = JSON.parse(rawBody.toString()) as AnalyticsEvent;
        evt.serverTs = Date.now();
        evt.ip = ip;
        analyticsEvents.push(evt);
        // Persist to NDJSON log (survives server restarts)
        appendFileSync(EVENT_LOG, JSON.stringify(evt) + '\n');
        cors(res);
        res.writeHead(204);
        res.end();
      } catch {
        json(res, 400, { error: 'invalid_json' });
      }
      return;
    }

    // ── Analytics: GET /analytics ────────────────────────────────────────────
    if (method === 'GET' && path === '/analytics') {
      // Summarize events by type
      const counts: Record<string, number> = {};
      const screens: Record<string, number> = {};
      const sessions = new Set<string>();
      for (const e of analyticsEvents) {
        counts[e.event] = (counts[e.event] || 0) + 1;
        if (e.event === 'screen_view' && e.screen) {
          screens[e.screen as string] = (screens[e.screen as string] || 0) + 1;
        }
        if (e.session) sessions.add(e.session);
      }
      json(res, 200, {
        totalEvents: analyticsEvents.length,
        uniqueSessions: sessions.size,
        eventCounts: counts,
        screenViews: screens,
        recentEvents: analyticsEvents.slice(-20).reverse(),
      });
      return;
    }

    json(res, 404, { error: 'not_found' });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(method, path, `ERROR: ${msg}`);
    json(res, 500, { error: 'internal_error', detail: msg });
  }
});

process.on('uncaughtException',  (err)    => console.error('[CRITICAL] Uncaught:', err));
process.on('unhandledRejection', (reason) => console.error('[CRITICAL] Rejection:', reason));

server.listen(PORT, () => {
  console.log(`\nTSK Demo Server running on http://localhost:${PORT}`);
  console.log('');
  console.log('  POST /tsk/provision         Provision a new client');
  console.log('  POST /tsk/revoke            Revoke a client');
  console.log('  GET  /tsk/anomaly           Anomaly scores');
  console.log('  GET  /api/data    [TSK]     Protected endpoint');
  console.log('  GET  /api/secret  [TSK]     Protected endpoint');
  console.log('  POST /api/action  [TSK]     Protected endpoint');
  console.log('');
});
