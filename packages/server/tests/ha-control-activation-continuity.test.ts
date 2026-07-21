import { describe, expect, it } from 'vitest';
import { assertConsumedActivationEpochs } from '../src/ha-control-fencing.js';

describe('source activation epoch continuity', () => {
  it('accepts multiple consecutive signed terminal ABORTED epochs', () => {
    expect(() => assertConsumedActivationEpochs(1, 4, [
      { epoch: 2, phase: 'PREPARING' }, { epoch: 2, phase: 'FENCED' }, { epoch: 2, phase: 'ABORTED' },
      { epoch: 3, phase: 'PREPARING' }, { epoch: 3, phase: 'READY' }, { epoch: 3, phase: 'ABORTED' },
    ], [])).not.toThrow();
  });

  it.each([
    ['missing epoch', [{ epoch: 2, phase: 'ABORTED' }], []],
    ['ACTIVE epoch', [{ epoch: 2, phase: 'ACTIVE' }, { epoch: 3, phase: 'ABORTED' }], []],
    ['equivocal terminal epoch', [{ epoch: 2, phase: 'ABORTED' }, { epoch: 2, phase: 'ACTIVE' }, { epoch: 3, phase: 'ABORTED' }], []],
    ['already activated epoch', [{ epoch: 2, phase: 'ABORTED' }, { epoch: 3, phase: 'ABORTED' }], [2]],
  ])('fails closed for %s', (_name, rows, activated) => {
    expect(() => assertConsumedActivationEpochs(1, 4, rows, activated)).toThrow(/quarantine/i);
  });

  it('rejects reuse and rollback', () => {
    expect(() => assertConsumedActivationEpochs(2, 2, [], [])).toThrow(/does not advance/i);
    expect(() => assertConsumedActivationEpochs(2, 1, [], [])).toThrow(/does not advance/i);
  });
});
