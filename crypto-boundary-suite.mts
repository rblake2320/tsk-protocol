import { secureRandomInt } from './packages/core/src/crypto.ts';

let passed = 0;

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed += 1;
    console.log(`  OK ${name}`);
  } catch (error) {
    console.error(`  FAIL ${name}`);
    throw error;
  }
}

function expectRangeError(value: number): void {
  try {
    secureRandomInt(value);
  } catch (error) {
    if (error instanceof RangeError) return;
    throw new Error(`expected RangeError for ${String(value)}, got ${String(error)}`);
  }
  throw new Error(`expected secureRandomInt(${String(value)}) to throw`);
}

console.log('\nTSK crypto boundary suite');

check('accepts the full uint32 sampling domain', () => {
  const value = secureRandomInt(0x100000000);
  if (!Number.isInteger(value) || value < 0 || value >= 0x100000000) {
    throw new Error(`out-of-range result: ${value}`);
  }
});

check('rejects zero and negative bounds', () => {
  expectRangeError(0);
  expectRangeError(-1);
});

check('rejects non-integer and non-finite bounds', () => {
  expectRangeError(1.5);
  expectRangeError(Number.NaN);
  expectRangeError(Number.POSITIVE_INFINITY);
});

check('rejects bounds larger than the uint32 entropy source', () => {
  expectRangeError(0x100000001);
});

console.log(`TSK crypto boundary suite: ${passed}/4 passed`);
