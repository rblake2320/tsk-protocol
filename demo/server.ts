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
  TSKProvisioner,
  MemoryAnomalyEngine,
} from '../packages/server/src/index.js';
// File store imported DIRECTLY — not re-exported via index.ts.
// Enterprise ultra_server imports @tsk/server; this import bypasses that path.
import { FileTumblerStore } from '../packages/server/src/file-store.js';

const PORT         = 3200;
const DEMO_DIR     = dirname(fileURLToPath(import.meta.url));
const EVENT_LOG    = join(DEMO_DIR, 'analytics.ndjson');
const SERVER_START = Date.now();
const ADMIN_TOKEN  = process.env['TSK_ADMIN_TOKEN'] ?? 'demo-admin-token';

// ── In-memory analytics store ────────────────────────────────────────────────
interface AnalyticsEvent {
  event: string; session: string; ts: number; site: string; [k: string]: unknown;
}
const analyticsEvents: AnalyticsEvent[] = [];

// ── Persistent storage when TSK_DATA_DIR is set — demo data stays isolated ──
// NEVER point TSK_DATA_DIR at enterprise directories (%APPDATA%\SelfConnect\).
// Demo state and enterprise state (ultra_server) must never share a path.
const DATA_DIR = process.env['TSK_DATA_DIR'];
let store: FileTumblerStore | ReturnType<typeof createTSKServer>['store'];
let provisioner: TSKProvisioner;
let anomaly: MemoryAnomalyEngine;

if (DATA_DIR) {
  console.log(`[TSK] Persistent store: ${DATA_DIR}`);
  store      = new FileTumblerStore(join(DATA_DIR, 'tsk-maps.json'));
  provisioner = new TSKProvisioner(store);
  anomaly    = new MemoryAnomalyEngine();
} else {
  ({ store, provisioner, anomaly } = createTSKServer());
}

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
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type,Authorization,X-TSK-Client-ID,X-TSK-Key,X-TSK-Version');
}

function verifyAdmin(headers: Record<string, string | string[] | undefined>): boolean {
  const auth = headers['authorization'];
  const token = Array.isArray(auth) ? auth[0] : (auth ?? '');
  return token === `Bearer ${ADMIN_TOKEN}`;
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
  res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-store' });
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
      const rawBody = await readBody(req);
      let provisionOpts: { keyLength?: number; rotatingCount?: number; ttlMs?: number | null; maxRequests?: number | null; label?: string } = {};
      try { provisionOpts = JSON.parse(rawBody.toString()); } catch { /* empty body is fine */ }

      const expiresAt = (provisionOpts.ttlMs != null && provisionOpts.ttlMs > 0) ? Date.now() + provisionOpts.ttlMs : undefined;
      const maxRequests = (provisionOpts.maxRequests != null && provisionOpts.maxRequests > 0) ? provisionOpts.maxRequests : undefined;
      const label = provisionOpts.label ?? undefined;

      const result = await provisioner.provision(
        { keyLength: provisionOpts.keyLength, minTumblers: provisionOpts.rotatingCount, maxTumblers: provisionOpts.rotatingCount },
        ip,
      );
      if (!result.ok) {
        log(method, path, `PROVISION DENIED (${result.error})`);
        json(res, 400, { error: result.error });
        return;
      }

      // Stamp lifecycle fields on the stored map
      const fullMap = result.tumblerMap!;
      if (expiresAt) fullMap.expiresAt = expiresAt;
      if (maxRequests !== undefined) fullMap.maxRequests = maxRequests;
      fullMap.requestCount = 0;
      if (label) fullMap.label = label;
      await store.set(fullMap.clientId, fullMap);

      log(method, path, `PROVISIONED client=${result.clientId}${label ? ` label=${label}` : ''}`);
      json(res, 200, {
        ok: true,
        clientId: result.clientId,
        expiresAt: expiresAt ?? null,
        maxRequests: maxRequests ?? null,
        label: label ?? null,
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

    // ── TSK-Protected: PUT /api/admin/config ─────────────────────────────────
    if (method === 'PUT' && path === '/api/admin/config') {
      const result = await verifyTSK(req, ip);
      if (!result.ok) {
        log(method, path, `DENIED (${result.error})`);
        json(res, 401, { error: result.error });
        return;
      }
      log(method, path, `PASS client=${result.clientId}`);
      json(res, 200, { updated: true, clientId: result.clientId });
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

    // ── Health ────────────────────────────────────────────────────────────────
    if (method === 'GET' && path === '/health') {
      const clients = await store.list();
      const sessions = new Set(analyticsEvents.map(e => e.session));
      // Count expired clients
      let expiredCount = 0;
      const now = Date.now();
      for (const cid of clients) {
        const m = await store.get(cid);
        if (m?.expiresAt && now > m.expiresAt) expiredCount++;
      }
      json(res, 200, {
        status: 'ok',
        uptimeMs: Date.now() - SERVER_START,
        port: PORT,
        clientCount: clients.length,
        expiredCount,
        trackedClients: anomaly.trackedClients,
        trackedIPs: anomaly.trackedIPs,
        analyticsEvents: analyticsEvents.length,
        uniqueSessions: sessions.size,
        ts: Date.now(),
      });
      return;
    }

    // ── Admin: list clients ───────────────────────────────────────────────────
    if (method === 'GET' && path === '/tsk/admin/clients') {
      if (!verifyAdmin(req.headers as Record<string, string | string[] | undefined>)) {
        json(res, 401, { error: 'unauthorized' });
        return;
      }
      const url_obj = new URL(req.url ?? '/', `http://localhost:${PORT}`);
      const fullExport = url_obj.searchParams.get('export') === 'true';
      const clients = await store.list();
      const result = await Promise.all(clients.map(async cid => {
        const map = await store.get(cid);
        if (!map) return null;
        const score = anomaly.score(cid);
        return {
          clientId: cid,
          createdAt: new Date(map.createdAt).toISOString(),
          keyLength: map.keyLength,
          sharedSecret: fullExport ? map.sharedSecret : '••••' + map.sharedSecret.slice(-4),
          expiresAt: map.expiresAt ? new Date(map.expiresAt).toISOString() : null,
          expiresIn: map.expiresAt ? Math.max(0, map.expiresAt - Date.now()) : null,
          maxRequests: map.maxRequests ?? null,
          requestCount: map.requestCount ?? 0,
          status: map.status ?? 'active',
          label: map.label ?? null,
          lastUsedAt: map.lastUsedAt ? new Date(map.lastUsedAt).toISOString() : null,
          segments: map.segments.map(s => ({
            segmentId: s.segmentId,
            type: s.type,
            position: s.position,
            length: s.position[1] - s.position[0],
            ...(s.type === 'totp' ? { windowSec: s.windowSec } : {}),
            ...(s.type === 'hotp' ? { counter: s.counter ?? 0 } : {}),
          })),
          anomaly: score,
        };
      }));
      log(method, path, `ADMIN clients=${clients.length} export=${fullExport}`);
      json(res, 200, { clientCount: clients.length, clients: result.filter(Boolean) });
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
  console.log('  POST /tsk/provision               Provision a new client');
  console.log('  POST /tsk/revoke                  Revoke a client');
  console.log('  GET  /tsk/anomaly                 Anomaly scores (all clients)');
  console.log('  GET  /tsk/admin/clients  [admin]  List clients + map info');
  console.log('  GET  /tsk/admin/clients?export=true  Full export with secrets');
  console.log('  GET  /health                      Server health + metrics');
  console.log('  GET  /analytics                   Analytics event summary');
  console.log('  GET  /api/data         [TSK]     Protected endpoint');
  console.log('  GET  /api/secret       [TSK]     Protected endpoint');
  console.log('  POST /api/action       [TSK]     Protected endpoint');
  console.log('  PUT  /api/admin/config [TSK]     Protected endpoint');
  console.log(`  Admin token: ${process.env['TSK_ADMIN_TOKEN'] ? 'custom token configured' : 'demo default active'}`);
  console.log('');
});
