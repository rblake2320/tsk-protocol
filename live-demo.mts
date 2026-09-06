/**
 * TSK Protocol — live, redacted core-package demonstration.
 *
 * This file intentionally calls the shipped @tsk/core implementation rather
 * than carrying an independent demo algorithm. It never prints keys or secrets.
 */
import { createHash } from 'node:crypto';
import { generateKeyFromMap } from './packages/core/src/key-gen.js';
import { generateTumblerMap } from './packages/core/src/tumbler-map.js';
import { validateTSKKey } from './packages/core/src/validate.js';
import type { TumblerMap } from './packages/core/src/types.js';

function fingerprint(value: string): string {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 16)}`;
}

function mapWithTotp(): TumblerMap {
  for (let attempts = 0; attempts < 100; attempts++) {
    const map = generateTumblerMap({ keyLength: 64, minTumblers: 3, maxTumblers: 3 });
    if (map.segments.some(segment => segment.type === 'totp')) return map;
  }
  throw new Error('DEMO_MAP_GENERATION_FAILED');
}

const now = Date.now();
const map = mapWithTotp();
const key = generateKeyFromMap(map, now);
const current = validateTSKKey(key, { map, nowMs: now });
const expired = validateTSKKey(key, { map, nowMs: now + 10 * 60_000 });
const tampered = `${key.slice(0, 12)}${key[12] === 'A' ? 'B' : 'A'}${key.slice(13)}`;
const tamperedResult = validateTSKKey(tampered, { map, nowMs: now });
const hotp = map.segments.find(segment => segment.type === 'hotp');
if (!hotp) throw new Error('DEMO_HOTP_MISSING');
const nextMap: TumblerMap = structuredClone(map);
const nextHotp = nextMap.segments.find(segment => segment.segmentId === hotp.segmentId);
if (!nextHotp || nextHotp.type !== 'hotp') throw new Error('DEMO_HOTP_MISSING');
nextHotp.counter = (nextHotp.counter ?? 0) + 1;
const nextKey = generateKeyFromMap(nextMap, now);

const checks = [
  ['valid current credential is accepted', current.ok],
  ['captured credential is rejected after time-window expiry', !expired.ok],
  ['one-character tampering is rejected', !tamperedResult.ok],
  ['next HOTP counter produces a distinct credential', key !== nextKey],
] as const;

console.log('TSK live core-package demonstration (credentials redacted)');
console.log(`credential fingerprint: ${fingerprint(key)}; length=${key.length}`);
console.log(`next-counter fingerprint: ${fingerprint(nextKey)}`);
console.log(`segments: ${map.segments.map(segment => segment.type).join(', ')}`);
for (const [description, passed] of checks) console.log(`${passed ? 'PASS' : 'FAIL'} ${description}`);
if (checks.some(([, passed]) => !passed)) process.exitCode = 1;
