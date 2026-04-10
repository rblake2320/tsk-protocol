/**
 * TSK Protocol — Live Demo with Real Output
 * Shows actual generated keys, actual rotation, actual validation
 * All Node.js crypto — zero mocks
 */

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

// ── Real crypto primitives ──
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

// ── Types ──
type SegType = 'static' | 'totp' | 'hotp';
interface Seg { id: string; pos: [number, number]; type: SegType; windowSec?: number; counter?: number; }
interface TMap { clientId: string; secret: string; keyLen: number; segs: Seg[]; csPos: [number, number]; }

// ── Derive segment value ──
function deriveSeg(secret: string, seg: Seg, nowMs: number): string {
  const len = seg.pos[1] - seg.pos[0];
  let input: string;
  if (seg.type === 'static') input = `static:${seg.id}`;
  else if (seg.type === 'totp') {
    const T = Math.floor(nowMs / 1000 / (seg.windowSec ?? 60));
    input = `totp:${seg.id}:${T}`;
  } else input = `hotp:${seg.id}:${seg.counter ?? 0}`;
  return padOrTruncate(hmac(secret, input), len);
}

// ── Generate key ──
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

// ── Validate key ──
function validate(key: string, map: TMap, nowMs: number): { ok: boolean; detail: string } {
  if (key.length !== map.keyLen) return { ok: false, detail: 'LENGTH_MISMATCH' };
  const csProvided = key.slice(map.csPos[0], map.csPos[1]);
  const csExpected = hmac(map.secret, `checksum:${key.slice(0, map.csPos[0])}`).slice(0, map.csPos[1] - map.csPos[0]);
  if (!constantTimeEqual(csProvided, csExpected)) return { ok: false, detail: 'CHECKSUM_FAILED' };

  const segDetail: string[] = [];
  for (const seg of map.segs) {
    const provided = key.slice(seg.pos[0], seg.pos[1]);
    let valid = false;
    if (seg.type === 'static') {
      valid = constantTimeEqual(provided, deriveSeg(map.secret, seg, nowMs));
    } else if (seg.type === 'totp') {
      const ws = seg.windowSec ?? 60;
      const T = Math.floor(nowMs / 1000 / ws);
      for (let d = -1; d <= 1; d++) {
        const exp = padOrTruncate(hmac(map.secret, `totp:${seg.id}:${T+d}`), seg.pos[1]-seg.pos[0]);
        if (constantTimeEqual(provided, exp)) { valid = true; break; }
      }
    } else {
      const base = seg.counter ?? 0;
      for (let la = 0; la <= 5; la++) {
        const exp = padOrTruncate(hmac(map.secret, `hotp:${seg.id}:${base+la}`), seg.pos[1]-seg.pos[0]);
        if (constantTimeEqual(provided, exp)) { valid = true; break; }
      }
    }
    segDetail.push(`${seg.id}(${seg.type}): ${valid ? 'PASS' : 'FAIL'}`);
  }
  const allPass = segDetail.every(s => s.includes('PASS'));
  return { ok: allPass, detail: segDetail.join(' | ') };
}

// ══════════════════════════════════════════════════════════════════════════════
// LIVE DEMO
// ══════════════════════════════════════════════════════════════════════════════

const secret = randomBytes(32).toString('hex');
const NOW = Date.now();

console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║         TSK PROTOCOL — LIVE CRYPTOGRAPHIC DEMO             ║');
console.log('║         All output is real. Zero mocks.                    ║');
console.log('╚══════════════════════════════════════════════════════════════╝');

console.log(`\nShared Secret (256-bit, hex): ${secret}`);
console.log(`Current Time: ${new Date(NOW).toISOString()}`);

// ── Build tumbler map ──
const map: TMap = {
  clientId: 'tsk_live_demo',
  secret,
  keyLen: 52,
  segs: [
    { id: 'ID',    pos: [0,  8],  type: 'static' },
    { id: 'T30',   pos: [8,  18], type: 'totp', windowSec: 30 },
    { id: 'T60',   pos: [18, 28], type: 'totp', windowSec: 60 },
    { id: 'HOTP',  pos: [28, 36], type: 'hotp', counter: 0 },
    { id: 'STAT2', pos: [36, 44], type: 'static' },
  ],
  csPos: [44, 52],
};

console.log('\n┌─── TUMBLER MAP (server-side secret — attacker never sees this) ───┐');
console.log(`│ Key Length: ${map.keyLen} chars                                         │`);
for (const seg of map.segs) {
  const len = seg.pos[1] - seg.pos[0];
  const extra = seg.type === 'totp' ? ` (${seg.windowSec}s window)` : seg.type === 'hotp' ? ` (counter: ${seg.counter})` : '';
  console.log(`│ [${String(seg.pos[0]).padStart(2)}-${String(seg.pos[1]).padStart(2)}] ${seg.id.padEnd(6)} ${seg.type.padEnd(6)}${extra.padEnd(20)}│`);
}
console.log(`│ [44-52] CHKSUM                                                │`);
console.log('└─────────────────────────────────────────────────────────────────┘');

// ── Demo 1: Generate a key NOW ──
console.log('\n═══ DEMO 1: Generate key at current time ═══');
const key1 = genKey(map, NOW);
console.log(`Key: ${key1}`);
console.log('     ' + colorMap(key1, map));

const r1 = validate(key1, map, NOW);
console.log(`Validate: ${r1.ok ? '✓ PASS' : '✗ FAIL'} — ${r1.detail}`);

// ── Demo 2: Generate key 31 seconds later (TOTP 30s rotates) ──
console.log('\n═══ DEMO 2: Key 31 seconds later (T30 segment rotates) ═══');
const key2 = genKey(map, NOW + 31_000);
console.log(`Key: ${key2}`);
console.log('     ' + colorMap(key2, map));

// Show which chars changed
const diff = key1.split('').map((c, i) => c === key2[i] ? '·' : '▲').join('');
console.log(`Diff: ${diff}  (▲ = changed, · = same)`);

const r2 = validate(key2, map, NOW + 31_000);
console.log(`Validate at T+31s: ${r2.ok ? '✓ PASS' : '✗ FAIL'} — ${r2.detail}`);

// ── Demo 3: Try key1 at T+5min (should FAIL — TOTP expired) ──
console.log('\n═══ DEMO 3: Replay key1 at T+5min (stolen key attack) ═══');
const r3 = validate(key1, map, NOW + 5 * 60_000);
console.log(`Key:      ${key1}`);
console.log(`Validate: ${r3.ok ? '✓ PASS' : '✗ FAIL'} — ${r3.detail}`);
console.log('          ↑ Static segments still match, TOTP segments expired = STOLEN KEY DETECTED');

// ── Demo 4: Tamper one character ──
console.log('\n═══ DEMO 4: Tamper one character (position 15) ═══');
const tampered = key1.slice(0, 15) + (key1[15] === 'A' ? 'Z' : 'A') + key1.slice(16);
console.log(`Original:  ${key1}`);
console.log(`Tampered:  ${tampered}`);
console.log(`Changed:   ${key1.split('').map((c, i) => c === tampered[i] ? ' ' : '^').join('')}`);
const r4 = validate(tampered, map, NOW);
console.log(`Validate: ${r4.ok ? '✓ PASS' : '✗ FAIL'} — ${r4.detail}`);

// ── Demo 5: Wrong shared secret ──
console.log('\n═══ DEMO 5: Attacker generates key with wrong secret ═══');
const wrongSecret = randomBytes(32).toString('hex');
const wrongMap = { ...map, secret: wrongSecret };
const wrongKey = genKey(wrongMap, NOW);
console.log(`Legit key:  ${key1}`);
console.log(`Wrong key:  ${wrongKey}`);
console.log(`Match:      ${key1 === wrongKey ? 'IDENTICAL (bad!)' : 'DIFFERENT (good!)'}`);
const r5 = validate(wrongKey, map, NOW);
console.log(`Validate: ${r5.ok ? '✓ PASS' : '✗ FAIL'} — ${r5.detail}`);

// ── Demo 6: Position shift (structural secrecy) ──
console.log('\n═══ DEMO 6: Shift key by 1 position (attacker guesses wrong structure) ═══');
const shifted = key1.slice(1) + key1[0];
console.log(`Original: ${key1}`);
console.log(`Shifted:  ${shifted}`);
const r6 = validate(shifted, map, NOW);
console.log(`Validate: ${r6.ok ? '✓ PASS' : '✗ FAIL'} — ${r6.detail}`);

// ── Demo 7: HOTP counter advance ──
console.log('\n═══ DEMO 7: HOTP counter — three sequential keys ═══');
for (let c = 0; c < 3; c++) {
  const hotpMap = { ...map, segs: map.segs.map(s => s.id === 'HOTP' ? { ...s, counter: c } : s) };
  const k = genKey(hotpMap, NOW);
  console.log(`Counter=${c}: ${k}`);
}
const hotpDiff = [];
for (let c = 0; c < 3; c++) {
  const hotpMap = { ...map, segs: map.segs.map(s => s.id === 'HOTP' ? { ...s, counter: c } : s) };
  hotpDiff.push(genKey(hotpMap, NOW).slice(28, 36));
}
console.log(`HOTP segment [28-36] across counters: ${hotpDiff.join(' → ')}`);
console.log(`All different: ${hotpDiff[0] !== hotpDiff[1] && hotpDiff[1] !== hotpDiff[2] ? '✓ YES' : '✗ NO'}`);

// ── Demo 8: Multiple clients, same time — completely different keys ──
console.log('\n═══ DEMO 8: Two clients, same time — structural secrecy ═══');
const secret2 = randomBytes(32).toString('hex');
const map2: TMap = {
  clientId: 'tsk_client_B',
  secret: secret2,
  keyLen: 52,
  segs: [
    // Different positions! This is the per-client secret structure
    { id: 'ID',    pos: [0,  10], type: 'static' },
    { id: 'T120',  pos: [10, 22], type: 'totp', windowSec: 120 },
    { id: 'HOTP',  pos: [22, 34], type: 'hotp', counter: 0 },
    { id: 'STAT2', pos: [34, 44], type: 'static' },
  ],
  csPos: [44, 52],
};
const keyA = genKey(map, NOW);
const keyB = genKey(map2, NOW);
console.log(`Client A: ${keyA}  (5 segments, T30+T60 windows)`);
console.log(`Client B: ${keyB}  (4 segments, T120 window)`);
console.log(`Same length, totally different structure — attacker can't tell which bytes rotate`);

// ── Summary ──
console.log('\n╔══════════════════════════════════════════════════════════════╗');
console.log('║                    RESULTS SUMMARY                         ║');
console.log('╠══════════════════════════════════════════════════════════════╣');
const tests = [
  ['Valid key at current time',           r1.ok,  true],
  ['Key at T+31s (TOTP rotated)',         r2.ok,  true],
  ['Stolen key replay at T+5min',         r3.ok,  false],
  ['Tampered key (1 char)',               r4.ok,  false],
  ['Wrong shared secret',                 r5.ok,  false],
  ['Position-shifted key',                r6.ok,  false],
] as const;

let p = 0;
for (const [name, result, expected] of tests) {
  const ok = result === expected;
  if (ok) p++;
  console.log(`║ ${ok ? '✓' : '✗'} ${name.padEnd(42)} ${(result ? 'PASS' : 'REJECT').padEnd(7)} ${ok ? '(correct)' : '(WRONG!)'}║`);
}
console.log('╠══════════════════════════════════════════════════════════════╣');
console.log(`║ ${p}/${tests.length} tests correct — ALL REAL CRYPTO, ZERO MOCKS              ║`);
console.log('╚══════════════════════════════════════════════════════════════╝');

function colorMap(key: string, m: TMap): string {
  const labels = new Array(key.length).fill(' ');
  for (const seg of m.segs) {
    const label = seg.type === 'static' ? 'S' : seg.type === 'totp' ? 'T' : 'H';
    for (let i = seg.pos[0]; i < seg.pos[1]; i++) labels[i] = label;
  }
  for (let i = m.csPos[0]; i < m.csPos[1]; i++) labels[i] = 'C';
  return labels.join('') + '  (S=static T=totp H=hotp C=checksum)';
}
