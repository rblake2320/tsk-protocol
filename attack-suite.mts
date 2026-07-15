/**
 * TSK bounded adversarial suite.
 *
 * Every acceptance/rejection case in this file calls the production core
 * implementation. Statistical and throughput observations are reported as
 * diagnostics only; they are not treated as proofs of constant-time behavior,
 * randomness, denial-of-service resistance, or deployment security.
 *
 * Run: npx tsx attack-suite.mts
 */

import { randomBytes } from 'node:crypto';
import {
  computeChecksum,
  generateKeyFromMap,
  generateSharedSecret,
  hmac,
  validateTSKKey,
} from './packages/core/src/index.js';
import type { TumblerMap } from './packages/core/src/index.js';

const NOW = Date.now();
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const map: TumblerMap = {
  clientId: 'tsk_attack_fixture',
  sharedSecret: generateSharedSecret(),
  keyLength: 64,
  segments: [
    { segmentId: 'id_fixture', position: [0, 12], type: 'static' },
    { segmentId: 'totp_30', position: [12, 22], type: 'totp', windowSec: 30 },
    { segmentId: 'totp_60', position: [22, 32], type: 'totp', windowSec: 60 },
    { segmentId: 'hotp_fixture', position: [32, 42], type: 'hotp', counter: 0 },
    { segmentId: 'static_fixture', position: [42, 52], type: 'static' },
  ],
  checksum: { position: [52, 64] },
  createdAt: NOW,
  version: '1',
};

const validKey = generateKeyFromMap(map, NOW);
let totalCases = 0;
let failedCases = 0;

function validate(key: string, target = map, nowMs = NOW): boolean {
  return validateTSKKey(key, { map: target, nowMs }).ok;
}

function randomKey(length = map.keyLength): string {
  const bytes = randomBytes(length);
  let value = '';
  for (let index = 0; index < length; index++) {
    value += ALPHABET[bytes[index] & 63];
  }
  return value;
}

function mutateAt(value: string, position: number): string {
  const replacement = value[position] === 'A' ? 'B' : 'A';
  return value.slice(0, position) + replacement + value.slice(position + 1);
}

function retagBody(body: string): string {
  return body + computeChecksum(map.sharedSecret, body);
}

function testCase(
  name: string,
  run: () => { attempts: number; failed: boolean; detail: string },
): void {
  const started = performance.now();
  const result = run();
  const elapsed = performance.now() - started;
  totalCases++;
  if (result.failed) failedCases++;
  console.log(`\n${result.failed ? 'FAIL' : 'PASS'} ${name}`);
  console.log(`  attempts=${result.attempts.toLocaleString()} elapsed_ms=${elapsed.toFixed(1)}`);
  console.log(`  ${result.detail}`);
}

console.log('TSK bounded adversarial suite (production implementation)');
console.log(`fixture_key_length=${map.keyLength}; secret/key values intentionally not logged`);

testCase('invalid shared-secret encodings fail closed', () => {
  const invalidSecrets = ['not-hex', '00'.repeat(31)];
  let rejected = 0;
  for (const secret of invalidSecrets) {
    try {
      hmac(secret, 'bounded-secret-validation');
    } catch {
      rejected++;
    }
  }
  return {
    attempts: invalidSecrets.length,
    failed: rejected !== invalidSecrets.length,
    detail: `rejected=${rejected}/${invalidSecrets.length}`,
  };
});

testCase('non-finite authentication times fail closed', () => {
  const invalidTimes = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];
  const rejected = invalidTimes.filter(nowMs => {
    const result = validateTSKKey(validKey, { map, nowMs });
    return !result.ok && result.error === 'INVALID_KEY';
  }).length;
  return {
    attempts: invalidTimes.length,
    failed: rejected !== invalidTimes.length,
    detail: `rejected=${rejected}/${invalidTimes.length}`,
  };
});

testCase('random exact-length keys are rejected', () => {
  const attempts = 100_000;
  let accepted = 0;
  for (let index = 0; index < attempts; index++) {
    if (validate(randomKey())) {
      accepted++;
      break;
    }
  }
  return {
    attempts,
    failed: accepted !== 0,
    detail: `unexpected_acceptances=${accepted}; result is bounded to this sample`,
  };
});

testCase('captured key expires outside configured TOTP tolerance', () => {
  const attempts = 600;
  let acceptedAfterTwoMinutes = 0;
  for (let offsetSeconds = 1; offsetSeconds <= attempts; offsetSeconds++) {
    const accepted = validate(validKey, map, NOW + offsetSeconds * 1_000);
    if (offsetSeconds >= 120 && accepted) {
      acceptedAfterTwoMinutes++;
      break;
    }
  }
  return {
    attempts,
    failed: acceptedAfterTwoMinutes !== 0,
    detail: `acceptances_at_or_after_120s=${acceptedAfterTwoMinutes}`,
  };
});

testCase('observed static positions do not enable sampled forgery', () => {
  const observed: string[] = [];
  for (let index = 0; index < 1_000; index++) {
    observed.push(generateKeyFromMap(map, NOW + index * 31_000));
  }
  const rotatingPositions = Array.from({ length: map.keyLength }, (_, position) => position)
    .filter(position => new Set(observed.map(key => key[position])).size > 1);
  let accepted = 0;
  for (let attempt = 0; attempt < 10_000; attempt++) {
    const characters = observed[observed.length - 1].split('');
    for (const position of rotatingPositions) {
      characters[position] = ALPHABET[randomBytes(1)[0] & 63];
    }
    if (validate(characters.join(''), map, NOW + 1_000 * 31_000)) {
      accepted++;
      break;
    }
  }
  return {
    attempts: 11_000,
    failed: accepted !== 0,
    detail: `rotating_positions=${rotatingPositions.length}; unexpected_acceptances=${accepted}`,
  };
});

testCase('sampled alternative 256-bit secrets do not reproduce the key', () => {
  const attempts = 50_000;
  let matches = 0;
  for (let index = 0; index < attempts; index++) {
    const candidate = generateKeyFromMap(
      { ...map, sharedSecret: generateSharedSecret() },
      NOW,
    );
    if (candidate === validKey) {
      matches++;
      break;
    }
  }
  return {
    attempts,
    failed: matches !== 0,
    detail: `unexpected_matches=${matches}; this is a bounded collision/guessing sample`,
  };
});

testCase('random checksum guesses are rejected', () => {
  const attempts = 10_000;
  let accepted = 0;
  const checksumLength = map.checksum.position[1] - map.checksum.position[0];
  for (let index = 0; index < attempts; index++) {
    const body = randomKey(map.checksum.position[0]);
    const candidate = body + randomKey(checksumLength);
    if (validate(candidate)) {
      accepted++;
      break;
    }
  }
  return {
    attempts,
    failed: accepted !== 0,
    detail: `unexpected_acceptances=${accepted}; no extrapolation beyond the sample`,
  };
});

testCase('all single-character substitutions are rejected', () => {
  let attempts = 0;
  let accepted = 0;
  for (let position = 0; position < validKey.length; position++) {
    for (const character of ALPHABET) {
      if (character === validKey[position]) continue;
      attempts++;
      const candidate = validKey.slice(0, position) + character + validKey.slice(position + 1);
      if (validate(candidate)) {
        accepted++;
        break;
      }
    }
    if (accepted) break;
  }
  return {
    attempts,
    failed: accepted !== 0,
    detail: `unexpected_acceptances=${accepted}`,
  };
});

testCase('known static bytes do not enable sampled completion', () => {
  const attempts = 50_000;
  const staticPositions = new Set(
    map.segments
      .filter(segment => segment.type === 'static')
      .flatMap(segment =>
        Array.from(
          { length: segment.position[1] - segment.position[0] },
          (_, offset) => segment.position[0] + offset,
        ),
      ),
  );
  let accepted = 0;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const characters = randomKey().split('');
    for (const position of staticPositions) characters[position] = validKey[position];
    if (validate(characters.join(''))) {
      accepted++;
      break;
    }
  }
  return {
    attempts,
    failed: accepted !== 0,
    detail: `known_static_characters=${staticPositions.size}; unexpected_acceptances=${accepted}`,
  };
});

testCase('TOTP boundary keys reject after three 30-second windows', () => {
  let attempts = 0;
  let failures = 0;
  for (let boundary = 0; boundary < 100; boundary++) {
    const boundaryTime = (Math.floor(NOW / 30_000) + boundary) * 30_000;
    const boundaryKey = generateKeyFromMap(map, boundaryTime);
    attempts += 2;
    if (!validate(boundaryKey, map, boundaryTime)) failures++;
    if (validate(boundaryKey, map, boundaryTime + 90_001)) failures++;
  }
  return {
    attempts,
    failed: failures !== 0,
    detail: `unexpected_boundary_results=${failures}`,
  };
});

// Diagnostic only: local JavaScript timing cannot establish constant-time
// behavior across runtimes, JIT states, operating systems, or hardware.
{
  const iterations = 2_000;
  const body = validKey.slice(0, map.checksum.position[0]);
  const candidates = [
    retagBody(mutateAt(body, 0)),
    retagBody(mutateAt(body, 45)),
    retagBody('A'.repeat(body.length)),
  ];
  const medians = candidates.map(candidate => {
    const samples: number[] = [];
    for (let index = 0; index < iterations; index++) {
      const started = performance.now();
      validate(candidate);
      samples.push(performance.now() - started);
    }
    samples.sort((left, right) => left - right);
    return samples[Math.floor(samples.length / 2)];
  });
  console.log('\nOBSERVATION invalid-input timing sample (not a constant-time proof)');
  console.log(`  median_ms=${medians.map(value => value.toFixed(4)).join(',')}`);
}

// Diagnostic only: this measures the core validator in one process. It is not
// a server load test and says nothing about rate limiting or DoS resistance.
{
  const attempts = 100_000;
  const started = performance.now();
  for (let index = 0; index < attempts; index++) validate(randomKey());
  const elapsed = performance.now() - started;
  console.log('\nOBSERVATION local validator throughput (not a server/DoS claim)');
  console.log(`  attempts=${attempts}; elapsed_ms=${elapsed.toFixed(1)}; validations_per_second=${Math.round(attempts / (elapsed / 1_000))}`);
}

// Diagnostic only: a single chi-squared sample is not evidence that output is
// cryptographically indistinguishable from random.
{
  const keyCount = 10_000;
  const counts = new Map<string, number>();
  for (let index = 0; index < keyCount; index++) {
    const key = generateKeyFromMap({ ...map, sharedSecret: generateSharedSecret() }, NOW);
    for (const character of key) counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  const expected = keyCount * map.keyLength / ALPHABET.length;
  let chiSquared = 0;
  for (const character of ALPHABET) {
    const count = counts.get(character) ?? 0;
    chiSquared += (count - expected) ** 2 / expected;
  }
  console.log('\nOBSERVATION one chi-squared output sample (not an indistinguishability proof)');
  console.log(`  keys=${keyCount}; chi_squared=${chiSquared.toFixed(1)}; degrees_of_freedom=63`);
}

console.log(`\nTSK bounded adversarial results: ${totalCases - failedCases}/${totalCases} passed`);
if (failedCases > 0) process.exit(1);
