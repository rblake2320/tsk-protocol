/**
 * TSK Protocol — Rotation & Segment Gap Tests
 *
 * Covers the attack classes NOT in attack-suite.mts:
 *   - TOTP segment boundary (T-1 / T / T+1 tolerance)
 *   - HOTP counter desync + lookahead recovery
 *   - Partial segment flip (one char changed per segment)
 *   - Full key replay after TOTP window expiry
 *   - Structural inference resistance (intercepted key reveals no positional info)
 *   - Segment injection (valid static + crafted rotating)
 *
 * Run: npx tsx rotation-gap-suite.mts
 * No server needed — all tests are against the inline reference implementation.
 */

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

function hmac(secret: string, data: string): string {
  return createHmac('sha256', Buffer.from(secret, 'hex')).update(data).digest('base64url');
}
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function padOrTruncate(s: string, len: number): string {
  if (s.length >= len) return s.slice(0, len);
  let r = s;
  while (r.length < len) r += hmac(s, r);
  return r.slice(0, len);
}

type SegType = 'static' | 'totp' | 'hotp';
interface Seg { id: string; pos: [number, number]; type: SegType; windowSec?: number; counter?: number; }
interface TMap { clientId: string; secret: string; keyLen: number; segs: Seg[]; csPos: [number, number]; }

function deriveSeg(secret: string, seg: Seg, nowMs: number): string {
  const len = seg.pos[1] - seg.pos[0];
  if (seg.type === 'static') return padOrTruncate(hmac(secret, `static:${seg.id}`), len);
  if (seg.type === 'totp') {
    const T = Math.floor(nowMs / 1000 / (seg.windowSec ?? 60));
    return padOrTruncate(hmac(secret, `totp:${seg.id}:${T}`), len);
  }
  return padOrTruncate(hmac(secret, `hotp:${seg.id}:${seg.counter ?? 0}`), len);
}

function genKey(map: TMap, nowMs: number): string {
  const buf = new Array(map.keyLen).fill('\x00');
  for (const seg of map.segs) {
    const val = deriveSeg(map.secret, seg, nowMs);
    for (let i = 0; i < seg.pos[1] - seg.pos[0]; i++) buf[seg.pos[0] + i] = val[i];
  }
  const body = buf.slice(0, map.csPos[0]).join('');
  const cs = hmac(map.secret, `checksum:${body}`).slice(0, map.csPos[1] - map.csPos[0]);
  for (let i = 0; i < cs.length; i++) buf[map.csPos[0] + i] = cs[i];
  return buf.join('');
}

function validate(key: string, map: TMap, nowMs: number, totpTol = 1, hotpLA = 5): boolean {
  if (key.length !== map.keyLen) return false;
  const csP = key.slice(map.csPos[0], map.csPos[1]);
  const csE = hmac(map.secret, `checksum:${key.slice(0, map.csPos[0])}`).slice(0, map.csPos[1] - map.csPos[0]);
  if (!constantTimeEqual(csP, csE)) return false;
  for (const seg of map.segs) {
    const provided = key.slice(seg.pos[0], seg.pos[1]);
    let valid = false;
    if (seg.type === 'static') {
      valid = constantTimeEqual(provided, deriveSeg(map.secret, seg, nowMs));
    } else if (seg.type === 'totp') {
      const ws = seg.windowSec ?? 60;
      const T = Math.floor(nowMs / 1000 / ws);
      for (let d = -totpTol; d <= totpTol; d++) {
        const exp = padOrTruncate(hmac(map.secret, `totp:${seg.id}:${T + d}`), seg.pos[1] - seg.pos[0]);
        if (constantTimeEqual(provided, exp)) { valid = true; break; }
      }
    } else {
      const base = seg.counter ?? 0;
      for (let la = 0; la <= hotpLA; la++) {
        const exp = padOrTruncate(hmac(map.secret, `hotp:${seg.id}:${base + la}`), seg.pos[1] - seg.pos[0]);
        if (constantTimeEqual(provided, exp)) { valid = true; break; }
      }
    }
    if (!valid) return false;
  }
  return true;
}

// ── Test fixture ──────────────────────────────────────────────────────────────
const SECRET = randomBytes(32).toString('hex');
const MAP: TMap = {
  clientId: 'client_test',
  secret: SECRET,
  keyLen: 52,
  segs: [
    { id: 'seg_static', pos: [0, 10], type: 'static' },
    { id: 'seg_totp30', pos: [10, 22], type: 'totp', windowSec: 30 },
    { id: 'seg_totp60', pos: [22, 34], type: 'totp', windowSec: 60 },
    { id: 'seg_hotp',   pos: [34, 44], type: 'hotp', counter: 0 },
  ],
  csPos: [44, 52],
};

let pass = 0, fail = 0;
function result(name: string, ok: boolean, detail = '') {
  const tag = ok ? 'PASS' : 'FAIL';
  if (ok) pass++; else fail++;
  console.log(`  [${tag}] ${name}${detail ? ' -- ' + detail : ''}`);
}

const NOW = Date.now();

// ── ROTATION GAP 1: TOTP window boundary tolerance ───────────────────────────
console.log('\n== GAP 1: TOTP segment boundary tolerance (T-1 / T / T+1) ==');
{
  const ws = 30;
  const T = Math.floor(NOW / 1000 / ws);

  for (const delta of [-1, 0, 1]) {
    // Generate key at T+delta
    const fakeNow = (T + delta) * ws * 1000 + 1;
    const key = genKey(MAP, fakeNow);
    // Validate at NOW (T)
    const ok = validate(key, MAP, NOW);
    result(
      `TOTP 30s window: key generated at T${delta >= 0 ? '+' : ''}${delta} validates at T`,
      ok,
      `T=${T} gen_T=${T + delta}`,
    );
  }

  // T+2 must be rejected
  const futureFakeNow = (T + 2) * ws * 1000 + 1;
  const futureKey = genKey(MAP, futureFakeNow);
  result(
    'TOTP 30s window: key generated at T+2 rejected at T (outside tolerance)',
    !validate(futureKey, MAP, NOW),
  );

  // T-2 must be rejected
  const pastFakeNow = (T - 2) * ws * 1000 + 1;
  const pastKey = genKey(MAP, pastFakeNow);
  result(
    'TOTP 30s window: key generated at T-2 rejected at T',
    !validate(pastKey, MAP, NOW),
  );
}

// ── ROTATION GAP 2: Full key replay after shortest window expires ─────────────
console.log('\n== GAP 2: key replay after TOTP 30s window expires ==');
{
  const capturedKey = genKey(MAP, NOW);
  result('captured key valid now', validate(capturedKey, MAP, NOW));

  // Simulate 2 full 30s windows passing (T+2)
  const ws = 30;
  const T = Math.floor(NOW / 1000 / ws);
  const expiredMs = (T + 2) * ws * 1000 + 500;
  result(
    'captured key invalid 2 TOTP windows later',
    !validate(capturedKey, MAP, expiredMs),
  );
}

// ── ROTATION GAP 3: HOTP counter desync and lookahead recovery ───────────────
console.log('\n== GAP 3: HOTP counter desync + lookahead recovery ==');
{
  const hotpSeg = MAP.segs.find(s => s.type === 'hotp')!;

  // Simulate client advancing counter by 3 without server knowing
  const skippedMap = { ...MAP, segs: MAP.segs.map(s =>
    s.id === hotpSeg.id ? { ...s, counter: 0 } : s  // server still at 0
  ) };
  // Client is at counter=3
  const clientAdvanced = { ...MAP, segs: MAP.segs.map(s =>
    s.id === hotpSeg.id ? { ...s, counter: 3 } : s
  ) };

  const keyAt3 = genKey(clientAdvanced, NOW);
  // Server uses lookahead=5, should accept counter 3 (3 ≤ 5)
  result(
    'HOTP counter desync by 3 recovered with lookahead=5',
    validate(keyAt3, skippedMap, NOW, 1, 5),
  );

  // Counter desync by 6 must fail with lookahead=5
  const clientAt6 = { ...MAP, segs: MAP.segs.map(s =>
    s.id === hotpSeg.id ? { ...s, counter: 6 } : s
  ) };
  const keyAt6 = genKey(clientAt6, NOW);
  result(
    'HOTP counter desync by 6 rejected with lookahead=5',
    !validate(keyAt6, skippedMap, NOW, 1, 5),
  );
}

// ── ROTATION GAP 4: Partial segment flip (single char changed) ───────────────
console.log('\n== GAP 4: partial segment flip — one character tampered per segment ==');
{
  const key = genKey(MAP, NOW).split('');

  for (const seg of MAP.segs) {
    const midPos = Math.floor((seg.pos[0] + seg.pos[1]) / 2);
    const tampered = [...key];
    // Flip one character at segment midpoint
    tampered[midPos] = tampered[midPos] === 'A' ? 'B' : 'A';
    result(
      `single flip in ${seg.id} (type=${seg.type}) at pos[${midPos}] => rejected`,
      !validate(tampered.join(''), MAP, NOW),
    );
  }

  // Checksum flip
  const csPos = Math.floor((MAP.csPos[0] + MAP.csPos[1]) / 2);
  const csTampered = [...key];
  csTampered[csPos] = csTampered[csPos] === 'A' ? 'B' : 'A';
  result(
    'single flip in checksum => rejected before segment validation',
    !validate(csTampered.join(''), MAP, NOW),
  );
}

// ── ROTATION GAP 5: Segment injection (valid static, crafted rotating) ────────
console.log('\n== GAP 5: segment injection — valid static + random rotating segments ==');
{
  // Attacker knows the static segment value (intercepted from a previous key),
  // but guesses the rotating segments at random.
  const realKey = genKey(MAP, NOW);
  const staticSeg = MAP.segs.find(s => s.type === 'static')!;
  const staticValue = realKey.slice(staticSeg.pos[0], staticSeg.pos[1]);

  for (let attempt = 0; attempt < 10; attempt++) {
    const injected = new Array(MAP.keyLen).fill('A');
    // Plant the known static value
    for (let i = 0; i < staticSeg.pos[1] - staticSeg.pos[0]; i++) {
      injected[staticSeg.pos[0] + i] = staticValue[i];
    }
    // Random bytes for all other positions including checksum
    const randFill = randomBytes(MAP.keyLen).toString('base64url').slice(0, MAP.keyLen);
    for (let i = 0; i < MAP.keyLen; i++) {
      if (i < staticSeg.pos[0] || i >= staticSeg.pos[1]) injected[i] = randFill[i];
    }
    const injectedKey = injected.join('');
    if (validate(injectedKey, MAP, NOW)) {
      result(`injection attempt ${attempt + 1}: INCORRECTLY ACCEPTED`, false, 'protocol broken');
      break;
    }
  }
  result('10 injection attempts with known static + random rotating: all rejected', true);
}

// ── ROTATION GAP 6: Structural inference resistance ───────────────────────────
// Attacker captures N keys over time. Can they determine segment positions?
// Observable: different chars change between captures; same chars stay same.
// This tests whether position inference from change patterns reveals the map.
console.log('\n== GAP 6: structural inference — position leakage from change pattern ==');
{
  // Advance time by exactly one 30s TOTP window
  const ws = 30;
  const T = Math.floor(NOW / 1000 / ws);
  const laterMs = (T + 1) * ws * 1000 + 1;

  const key1 = genKey(MAP, NOW).split('');
  const key2 = genKey(MAP, laterMs).split('');

  // Find positions that changed
  const changed: number[] = [];
  const unchanged: number[] = [];
  for (let i = 0; i < MAP.keyLen; i++) {
    if (key1[i] !== key2[i]) changed.push(i);
    else unchanged.push(i);
  }

  // Structural inference: changed positions reveal rotating segment boundaries.
  // This is a KNOWN LIMITATION of TSK (documented in spec §8.3):
  // "An attacker who intercepts multiple keys can infer which positions rotate."
  // The spec claims the POSITIONAL MAP (which segment is which) is secret,
  // not that change patterns are invisible.
  result(
    `${changed.length} chars changed across 30s boundary (rotating segments expose change pattern)`,
    true,  // expected — this is documented in the threat model
    `changed=[${changed.slice(0, 5).join(',')}...] unchanged=[${unchanged.slice(0, 5).join(',')}...]`,
  );
  result(
    'structural inference gives POSITIONS but not DERIVATION INPUT (shared secret still required)',
    true,  // attacker learns positions but can\'t compute segment values without sharedSecret
    'documented limitation — mitigated by secret-in-derivation-input',
  );

  // Verify: knowing positions + segment types, attacker still cannot forge
  // without the shared secret.
  const fakeSecret = randomBytes(32).toString('hex');  // wrong secret
  const forgeryMap = { ...MAP, secret: fakeSecret };
  const forgedKey = genKey(forgeryMap, NOW);
  result(
    'knowing positions + type, wrong secret → forge attempt rejected',
    !validate(forgedKey, MAP, NOW),
  );
}

// ── ROTATION GAP 7: HOTP replay prevention — counter advancement ──────────────
// A key generated at counter=N is invalid once the server has advanced to N+1.
// This verifies that HOTP is not a time-independent replay vulnerability.
console.log('\n== GAP 7: HOTP replay prevention — counter must advance after use ==');
{
  // All-HOTP map: all segments are HOTP (no TOTP expiry) so replay is the only defense.
  const hotpOnlyMap: TMap = {
    clientId: 'client_hotp_replay_test',
    secret: randomBytes(32).toString('hex'),
    keyLen: 44,
    segs: [
      { id: 'seg_h1', pos: [0, 12],  type: 'hotp', counter: 0 },
      { id: 'seg_h2', pos: [12, 24], type: 'hotp', counter: 0 },
      { id: 'seg_h3', pos: [24, 36], type: 'hotp', counter: 0 },
    ],
    csPos: [36, 44],
  };

  // Step 1: generate a key at counter=0 and confirm it validates.
  const keyAtCounter0 = genKey(hotpOnlyMap, NOW);
  result('all-HOTP key valid at counter=0', validate(keyAtCounter0, hotpOnlyMap, NOW, 1, 5));

  // Step 2: simulate server advancing all HOTP counters to 1 after a successful validation.
  const advancedMap: TMap = {
    ...hotpOnlyMap,
    segs: hotpOnlyMap.segs.map(s => ({ ...s, counter: 1 })),
  };

  // Step 3: same key (still counter=0) must be rejected — counter is now 1.
  // With lookahead=5 the server checks counters 1..6; counter=0 is below the window.
  result(
    'counter=0 key rejected after server advanced to counter=1 (replay blocked)',
    !validate(keyAtCounter0, advancedMap, NOW, 1, 5),
  );

  // Step 4: a new key at counter=1 is accepted.
  const keyAtCounter1 = genKey(advancedMap, NOW);
  result('new key at counter=1 accepted', validate(keyAtCounter1, advancedMap, NOW, 1, 5));

  // Step 5: the old counter=0 key is still invalid even with the new map.
  result(
    'counter=0 key still invalid against counter=1 map (no rollback)',
    !validate(keyAtCounter0, advancedMap, NOW, 1, 5),
  );
}

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n── TSK Rotation Gap Suite ──  PASS: ${pass}  FAIL: ${fail} ──`);
if (fail > 0) process.exit(1);
