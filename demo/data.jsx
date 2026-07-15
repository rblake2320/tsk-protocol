// data.jsx — Real TSK crypto via Web Crypto API (HMAC-SHA256).
// Replaces the design's fake hmacish() pseudo-HMAC with genuine crypto.subtle.sign().

const SERVER = 'http://localhost:3200';
const enc = new TextEncoder();

// ── Web Crypto helpers ────────────────────────────────────────────────────────

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}

function b64urlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Cache imported CryptoKey objects (importKey is expensive; same hex → same key)
const _keyCache = new Map();
async function importHmacKey(secretHex) {
  if (_keyCache.has(secretHex)) return _keyCache.get(secretHex);
  const key = await crypto.subtle.importKey(
    'raw', hexToBytes(secretHex),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  _keyCache.set(secretHex, key);
  return key;
}

async function hmacB64url(secretHex, label) {
  const key = await importHmacKey(secretHex);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(label));
  return b64urlEncode(new Uint8Array(sig));
}

// Pad or truncate a base64url value to exactly `len` chars.
// Mirrors server's padOrTruncateClient(): HMAC(secret, "pad:round:current") rounds.
async function padOrTruncate(secretHex, value, len) {
  if (value.length >= len) return value.slice(0, len);
  let result = value;
  let round = 0;
  while (result.length < len) {
    result += await hmacB64url(secretHex, `pad:${round}:${result}`);
    round++;
  }
  return result.slice(0, len);
}

// ── Server provisioning ───────────────────────────────────────────────────────

// Convert server provision response into the local map format that all screens expect.
// serverMap has absolute positions; provisionPayload has ordered segment lengths.
function buildLocalMap(clientId, sharedSecret, serverMap, provisionPayload) {
  // Build segment list from serverMap (which has absolute positions)
  const segments = serverMap.segments.map(seg => ({
    id: seg.segmentId,
    type: seg.type,
    position: seg.position,
    length: seg.position[1] - seg.position[0],
    windowSec: seg.windowSec ?? null,
    counter: seg.counter ?? 0,
    label: seg.type.toUpperCase(),
  }));

  // Add checksum segment
  const csPos = serverMap.checksum.position;
  segments.push({
    id: 'seg_checksum',
    type: 'checksum',
    position: csPos,
    length: csPos[1] - csPos[0],
    label: 'CHECKSUM',
  });

  // Sort by position start
  segments.sort((a, b) => a.position[0] - b.position[0]);

  return {
    clientId,
    sharedSecret,
    keyLength: serverMap.keyLength,
    segments,
    order: segments.map(s => s.id),
    createdAt: serverMap.createdAt,
    version: '1.0',
    // Lifecycle fields
    expiresAt: serverMap.expiresAt ?? null,
    maxRequests: serverMap.maxRequests ?? null,
    requestCount: serverMap.requestCount ?? 0,
    status: serverMap.status ?? 'active',
    label: serverMap.label ?? null,
    lastUsedAt: serverMap.lastUsedAt ?? null,
    // Keep provision payload for client-SDK key generation context
    clientSegments: provisionPayload.clientSegments,
    checksumLength: provisionPayload.checksumLength,
    // provisionPayload shape for the provisioning screen display
    provisionPayload: {
      clientId,
      sharedSecret: '••••••••' + sharedSecret.slice(-4),
      keyLength: serverMap.keyLength,
      segments: provisionPayload.clientSegments.map(s => ({
        id: s.segmentId,
        type: s.type,
        ...(s.windowSec ? { windowSec: s.windowSec } : {}),
      })),
      version: '1',
    },
  };
}

async function provisionFromServer(opts = {}) {
  const res = await fetch(`${SERVER}/tsk/provision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(opts),
  });
  if (!res.ok) throw new Error(`Provision failed: ${res.status}`);
  const data = await res.json();
  return buildLocalMap(
    data.clientId,
    data.sharedSecret,
    data.serverMap,
    data.provisionPayload
  );
}

// What to show in the provisioning screen's "client receives" panel
function provisionPayload(map) {
  return map.provisionPayload;
}

// ── Key generation (async, real HMAC-SHA256) ──────────────────────────────────

async function generateKey(map, nowMs = Date.now(), counters = {}) {
  if (!map) return null;
  const parts = {};
  const trace = {};

  for (const seg of map.segments) {
    if (seg.type === 'checksum') continue;

    let label;
    if (seg.type === 'static') {
      label = `static:${seg.id}`;
      trace[seg.id] = { T: null, label: 'static' };
    } else if (seg.type === 'totp') {
      const T = Math.floor(nowMs / 1000 / seg.windowSec);
      label = `totp:${seg.id}:${T}`;
      trace[seg.id] = {
        T,
        label: `T=${T % 10000}`,
        windowSec: seg.windowSec,
        elapsedMs: nowMs % (seg.windowSec * 1000),
      };
    } else if (seg.type === 'hotp') {
      const c = counters[seg.id] ?? seg.counter ?? 0;
      label = `hotp:${seg.id}:${c}`;
      trace[seg.id] = { T: c, label: `c=${c}` };
    }

    const raw = await hmacB64url(map.sharedSecret, label);
    parts[seg.id] = await padOrTruncate(map.sharedSecret, raw, seg.length);
  }

  // Assemble in positional order
  const ordered = map.segments.slice().sort((a, b) => a.position[0] - b.position[0]);
  let body = '';
  for (const seg of ordered) {
    if (seg.type === 'checksum') continue;
    body += parts[seg.id];
  }

  // Checksum: HMAC(secret, "checksum:" + body)[0..checksumLen]
  const csLen = map.segments.find(s => s.type === 'checksum')?.length ?? 12;
  const csRaw = await hmacB64url(map.sharedSecret, `checksum:${body}`);
  parts['seg_checksum'] = csRaw.slice(0, csLen);

  // Full key
  let full = '';
  for (const seg of ordered) {
    full += parts[seg.id];
  }

  return { key: full, parts, trace, ordered };
}

// ── useGenerateKey: async key generation hook ─────────────────────────────────
// Replaces all useMemo(() => generateKey(...)) calls across screens.
// Returns null until first result is ready, then updates on every tick.

function useGenerateKey(map, nowMs, counters) {
  const [gen, setGen] = useState(null);
  // Stable dependency: only recompute when the 250ms time slot changes or counters change
  const slot = Math.floor((nowMs || Date.now()) / 250);
  const countersKey = JSON.stringify(counters || {});
  const mapId = map?.clientId;

  useEffect(() => {
    if (!map) return;
    let cancelled = false;
    const t = slot * 250;
    generateKey(map, t, counters || {}).then(result => {
      if (!cancelled) setGen(result);
    });
    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mapId, slot, countersKey]);

  return gen;
}

// ── Anomaly engine (pure local scoring — same as spec) ────────────────────────

function evalAnomaly(events) {
  const now = Date.now();
  const window5m = events.filter(e => now - e.t < 5 * 60 * 1000);
  let score = 0;
  const reasons = [];
  if (window5m.length >= 10) { score += 40; reasons.push('≥10 failures in 5m window (+40)'); }
  else if (window5m.length >= 3) { score += 15; reasons.push(`${window5m.length} failures in window (+15)`); }
  const rotFails = window5m.filter(e => e.kind === 'fail-rotating').length;
  if (rotFails >= 2) { score += 50; reasons.push('Static passes, rotating fails ×2+ (+50)'); }
  else if (rotFails === 1) { score += 20; reasons.push('Static passes, rotating fails ×1 (+20)'); }
  if (window5m.length >= 3) { score += 30; reasons.push(`Total failures ×${window5m.length} (+30)`); }
  score = Math.min(100, score);
  const verdict = score >= 70 ? 'attack' : score >= 30 ? 'suspicious' : 'clean';
  return { score, verdict, reasons, windowSize: window5m.length };
}

// ── Server validation helper ──────────────────────────────────────────────────
// Used by the attack lab to send real TSK requests and get real server verdicts.

async function verifyWithServer(clientId, keyStr) {
  try {
    const res = await fetch(`${SERVER}/api/data`, {
      headers: {
        'X-TSK-Client-ID': clientId,
        'X-TSK-Key': keyStr,
        'X-TSK-Version': '1',
      },
    });
    const data = await res.json();
    return { status: res.status, ok: res.ok, data };
  } catch (e) {
    return { status: 0, ok: false, data: { error: e.message } };
  }
}

// ── Fetch real anomaly score from server ──────────────────────────────────────

async function fetchServerAnomaly(clientId) {
  try {
    const res = await fetch(`${SERVER}/tsk/anomaly`);
    const data = await res.json();
    return data.scores?.[clientId] ?? null;
  } catch {
    return null;
  }
}

// ── DEMO_MAP bootstrap ────────────────────────────────────────────────────────
// Provision a demo client from the server at startup.
// Screens should check window.DEMO_MAP !== null before rendering.

window.DEMO_MAP = null;
window.DEMO_MAP_READY = provisionFromServer().then(map => {
  window.DEMO_MAP = map;
  return map;
}).catch(err => {
  console.error('[TSK] Failed to provision DEMO_MAP:', err);
  return null;
});

// ── Exports ───────────────────────────────────────────────────────────────────
Object.assign(window, {
  hexToBytes, b64urlEncode, hmacB64url, padOrTruncate,
  importHmacKey, generateKey, useGenerateKey,
  provisionFromServer, provisionPayload, buildLocalMap,
  evalAnomaly, verifyWithServer, fetchServerAnomaly,
  SERVER,
});
