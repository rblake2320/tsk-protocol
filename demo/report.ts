#!/usr/bin/env node
/**
 * report.ts — Health + key-map report for TSK and/or BPC demo servers.
 *
 * Usage:
 *   npx tsx report.ts                          # TSK only (default)
 *   npx tsx report.ts --bpc                    # TSK + BPC
 *   npx tsx report.ts --tsk-only               # TSK only (explicit)
 *   npx tsx report.ts --bpc-only               # BPC only
 *   npx tsx report.ts --export                 # Include full secrets in TSK client export
 *   npx tsx report.ts --format json            # JSON output instead of table
 *   npx tsx report.ts --tsk http://host:3200   # Custom TSK URL
 *   npx tsx report.ts --bpc-url http://host:3101
 *   npx tsx report.ts --token my-admin-token   # Admin token (default: demo-admin-token)
 */

const DEFAULT_TSK = 'http://localhost:3200';
const DEFAULT_BPC = 'http://localhost:3101';
const DEFAULT_TOK = 'demo-admin-token';

// ── CLI arg parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function flag(name: string): boolean {
  return args.includes(name);
}
function opt(name: string, def: string): string {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
}

const tskUrl   = opt('--tsk', DEFAULT_TSK);
const bpcUrl   = opt('--bpc-url', DEFAULT_BPC);
const token    = opt('--token', DEFAULT_TOK);
const format   = opt('--format', 'table') as 'table' | 'json';
const fullExport = flag('--export');
const bpcOnly  = flag('--bpc-only');
const tskOnly  = flag('--tsk-only');
const showBpc  = flag('--bpc') || flag('--bpc-only');
const showTsk  = !bpcOnly;

// ── Fetch helpers ─────────────────────────────────────────────────────────────

async function get(url: string, adminToken?: string): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (adminToken) headers['Authorization'] = `Bearer ${adminToken}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.json();
}

async function tryGet(url: string, adminToken?: string): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  try {
    const data = await get(url, adminToken);
    return { ok: true, data };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

const RESET  = '\x1b[0m';
const BOLD   = '\x1b[1m';
const DIM    = '\x1b[2m';
const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED    = '\x1b[31m';
const CYAN   = '\x1b[36m';

function color(s: string, c: string) { return `${c}${s}${RESET}`; }
function bold(s: string) { return color(s, BOLD); }
function dim(s: string)  { return color(s, DIM); }
function green(s: string){ return color(s, GREEN); }
function yellow(s: string){return color(s, YELLOW); }
function red(s: string)  { return color(s, RED); }
function cyan(s: string) { return color(s, CYAN); }

function fmtUptime(ms: number): string {
  if (ms < 60_000) return `${(ms / 1000).toFixed(0)}s`;
  if (ms < 3_600_000) return `${(ms / 60_000).toFixed(1)}m`;
  return `${(ms / 3_600_000).toFixed(2)}h`;
}

function fmtVerdict(v: string): string {
  if (v === 'attack')     return red(v.toUpperCase());
  if (v === 'suspicious') return yellow(v);
  return green(v);
}

function hr(char = '─', width = 72) { return dim(char.repeat(width)); }

function section(title: string) {
  console.log('');
  console.log(bold(cyan(`▸ ${title}`)));
  console.log(hr());
}

function kv(key: string, value: string, indent = 0) {
  const pad = ' '.repeat(indent);
  console.log(`${pad}${dim(key.padEnd(28 - indent))}  ${value}`);
}

// ── TSK Report ────────────────────────────────────────────────────────────────

async function reportTSK() {
  console.log('');
  console.log(bold(`TSK Protocol  ${dim(tskUrl)}`));
  console.log(hr('═'));

  // Health
  section('Server Health');
  const health = await tryGet(`${tskUrl}/health`);
  if (!health.ok) {
    console.log(red(`  ✗ Server unreachable — ${health.error}`));
    return null;
  }
  const h = health.data as Record<string, unknown>;
  kv('status',          green('● online'));
  kv('uptime',          fmtUptime(h.uptimeMs as number));
  kv('active clients',  String(h.clientCount));
  kv('expired clients', String(h.expiredCount ?? 0));
  kv('tracked clients', String(h.trackedClients) + dim(' (anomaly engine)'));
  kv('tracked IPs',     String(h.trackedIPs));
  kv('analytics events',String(h.analyticsEvents) + dim(` (${h.uniqueSessions} sessions)`));

  // Anomaly per client
  section('Anomaly Scores');
  const anom = await tryGet(`${tskUrl}/tsk/anomaly`);
  if (anom.ok) {
    const a = anom.data as { scores: Record<string, { score: number; verdict: string; reasons: string[] }> };
    const entries = Object.entries(a.scores ?? {});
    if (entries.length === 0) {
      console.log(dim('  no clients tracked yet'));
    } else {
      for (const [cid, s] of entries) {
        const bar = '█'.repeat(Math.round(s.score / 10)) + '░'.repeat(10 - Math.round(s.score / 10));
        console.log(`  ${dim(cid)}  ${bar} ${String(s.score).padStart(3)} / 100  ${fmtVerdict(s.verdict)}`);
        if (s.reasons.length > 0) {
          for (const r of s.reasons) console.log(`    ${dim('›')} ${r}`);
        }
      }
    }
  }

  // Client map details (admin)
  section('Client Maps  ' + dim(`(admin · ${fullExport ? 'FULL EXPORT' : 'secrets redacted'})`));
  const clients = await tryGet(`${tskUrl}/tsk/admin/clients${fullExport ? '?export=true' : ''}`, token);
  if (!clients.ok) {
    console.log(yellow(`  ⚠ Admin endpoint denied — ${clients.error}`));
    console.log(dim(`  Set TSK_ADMIN_TOKEN env or pass --token <token>`));
  } else {
    const c = clients.data as { clientCount: number; clients: Array<Record<string, unknown>> };
    console.log(dim(`  ${c.clientCount} client(s) registered`));
    for (const cl of c.clients ?? []) {
      console.log('');
      kv('clientId',  bold(cl.clientId as string), 2);
      kv('createdAt', cl.createdAt as string, 2);
      kv('keyLength', String(cl.keyLength) + ' chars', 2);
      kv('secret',    fullExport ? yellow(cl.sharedSecret as string) : dim(cl.sharedSecret as string), 2);
      // Lifecycle fields
      const status = String(cl.status ?? 'active');
      kv('status', status === 'expired' ? red(status) : green(status), 2);
      if (cl.label) kv('label', String(cl.label), 2);
      if (cl.expiresAt) {
        const expiresIn = cl.expiresIn as number;
        const expiryStr = expiresIn > 0
          ? `${cl.expiresAt as string}  ${dim(`in ${fmtUptime(expiresIn)}`)}`
          : red(`${cl.expiresAt as string}  EXPIRED`);
        kv('expiresAt', expiryStr, 2);
      } else {
        kv('expiresAt', dim('never'), 2);
      }
      const requestCount = (cl.requestCount as number) ?? 0;
      const maxRequestsVal = cl.maxRequests as number | null;
      kv('requests', maxRequestsVal ? `${requestCount} / ${maxRequestsVal}` : `${requestCount} / ${dim('unlimited')}`, 2);
      if (cl.lastUsedAt) {
        kv('lastUsedAt', cl.lastUsedAt as string, 2);
      } else {
        kv('lastUsedAt', dim('never'), 2);
      }
      const segs = cl.segments as Array<Record<string, unknown>>;
      for (const s of segs ?? []) {
        const pos = (s.position as number[]).join('–');
        const extra = s.type === 'totp' ? `  window=${s.windowSec}s` :
                      s.type === 'hotp' ? `  counter=${s.counter}` : '';
        console.log(`    ${dim('seg')} ${String(s.type).padEnd(10)} pos [${pos}]  len=${s.length}${extra}`);
      }
      const score = cl.anomaly as { score: number; verdict: string };
      if (score) kv('anomaly', `${score.score}/100  ${fmtVerdict(score.verdict)}`, 2);
    }
  }

  // Analytics summary
  section('Analytics');
  const ana = await tryGet(`${tskUrl}/analytics`);
  if (ana.ok) {
    const a = ana.data as Record<string, unknown>;
    kv('total events',    String(a.totalEvents));
    kv('unique sessions', String(a.uniqueSessions));
    const ev = a.eventCounts as Record<string, number>;
    for (const [k, v] of Object.entries(ev ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 10)) {
      console.log(`    ${dim(k.padEnd(24))}  ${v}`);
    }
    const sv = a.screenViews as Record<string, number>;
    if (Object.keys(sv ?? {}).length > 0) {
      console.log(dim('  screen views:'));
      for (const [k, v] of Object.entries(sv)) {
        console.log(`    ${dim(k.padEnd(20))}  ${v}`);
      }
    }
  }

  return h;
}

// ── BPC Report ────────────────────────────────────────────────────────────────

async function reportBPC() {
  console.log('');
  console.log(bold(`BPC Protocol  ${dim(bpcUrl)}`));
  console.log(hr('═'));

  // Health
  section('Server Health');
  const health = await tryGet(`${bpcUrl}/health`);
  if (!health.ok) {
    console.log(yellow(`  ○ Server offline or unreachable — ${health.error}`));
    console.log(dim('  Start with: cd bpc-protocol/demo-bpc && npx tsx server.ts'));
    return null;
  }
  const h = health.data as Record<string, unknown>;
  kv('status',       green('● online'));
  kv('uptime',       fmtUptime(h.uptimeMs as number));
  kv('pairs',        `${h.activePairs} active / ${h.pairCount} total`);
  kv('threat score', `${h.threatScore ?? 0} / 100`);
  kv('analytics',    String(h.analyticsEvents) + dim(` (${h.uniqueSessions} sessions)`));

  // Registered pairs (admin)
  section('Registered Pairs  ' + dim('(admin · secrets redacted)'));
  const pairs = await tryGet(`${bpcUrl}/bpc/pairs`, token);
  if (!pairs.ok) {
    console.log(yellow(`  ⚠ Admin denied — ${pairs.error}`));
  } else {
    const p = pairs.data as { pairs: Array<Record<string, unknown>> };
    const list = p.pairs ?? [];
    if (list.length === 0) {
      console.log(dim('  no pairs registered'));
    } else {
      for (const pair of list) {
        console.log('');
        kv('pairId',    bold(pair.pairId as string), 2);
        kv('scope',     String(pair.scope ?? '—'), 2);
        kv('status',    pair.status === 'active' ? green(String(pair.status)) : yellow(String(pair.status)), 2);
        kv('createdAt', String(pair.createdAt ?? '—'), 2);
        if (pair.rotatedTo)    kv('rotatedTo', String(pair.rotatedTo), 2);
        if (pair.revokedAt)    kv('revokedAt', red(String(pair.revokedAt)), 2);
      }
    }
  }

  // Anomaly
  section('Anomaly Engine');
  const anom = await tryGet(`${bpcUrl}/bpc/anomaly`, token);
  if (anom.ok) {
    const a = anom.data as { score: number; counters: Record<string, unknown> };
    kv('threat score', `${a.score} / 100  ${fmtVerdict(a.score >= 70 ? 'attack' : a.score >= 30 ? 'suspicious' : 'clean')}`);
    if (a.counters && Object.keys(a.counters).length > 0) {
      for (const [k, v] of Object.entries(a.counters)) {
        console.log(`  ${dim(k.padEnd(28))}  ${v}`);
      }
    }
  }

  // Audit log (today)
  section('Audit Log · Today');
  const audit = await tryGet(`${bpcUrl}/bpc/audit/daily`, token);
  if (audit.ok) {
    const a = audit.data as { date: string; count: number; entries: Array<Record<string, unknown>> };
    kv('date',    a.date);
    kv('entries', String(a.count));
    for (const e of (a.entries ?? []).slice(0, 10)) {
      const ts = new Date(e.timestamp as number).toLocaleTimeString();
      console.log(`  ${dim(ts)}  ${String(e.action).padEnd(10)}  ${e.pairId ?? '—'}`);
    }
    if (a.count > 10) console.log(dim(`  … and ${a.count - 10} more`));
  }

  return h;
}

// ── JSON output mode ──────────────────────────────────────────────────────────

async function reportJSON() {
  const result: Record<string, unknown> = { generatedAt: new Date().toISOString() };

  if (showTsk) {
    const [health, anom, clients, analytics] = await Promise.all([
      tryGet(`${tskUrl}/health`),
      tryGet(`${tskUrl}/tsk/anomaly`),
      tryGet(`${tskUrl}/tsk/admin/clients${fullExport ? '?export=true' : ''}`, token),
      tryGet(`${tskUrl}/analytics`),
    ]);
    result['tsk'] = { url: tskUrl, health: health.data ?? health.error, anomaly: anom.data, clients: clients.data, analytics: analytics.data };
  }

  if (showBpc) {
    const [health, pairs, anom, audit] = await Promise.all([
      tryGet(`${bpcUrl}/health`),
      tryGet(`${bpcUrl}/bpc/pairs`, token),
      tryGet(`${bpcUrl}/bpc/anomaly`, token),
      tryGet(`${bpcUrl}/bpc/audit/daily`, token),
    ]);
    result['bpc'] = { url: bpcUrl, health: health.data ?? health.error, pairs: pairs.data, anomaly: anom.data, audit: audit.data };
  }

  console.log(JSON.stringify(result, null, 2));
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  if (format === 'json') {
    await reportJSON();
    return;
  }

  console.log(bold('\nTSK / BPC Health & Key Report'));
  console.log(dim(new Date().toLocaleString()));

  if (showTsk) await reportTSK();
  if (showBpc) await reportBPC();

  console.log('');
  console.log(hr());
  console.log(dim('Run with --export to include full secrets in TSK client output'));
  console.log(dim('Run with --format json for machine-readable output'));
  console.log(dim('Run with --bpc to also report on the BPC server at :3101'));
  console.log('');
}

main().catch(err => { console.error(red('Fatal:'), err.message); process.exit(1); });
