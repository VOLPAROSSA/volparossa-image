// Temporary F02 ruleset verification; this branch must never be merged.
import test from 'node:test';
import assert from 'node:assert/strict';

test('F02 required-check recovery probe', () => {
  assert.equal(2 + 2, 4);
});
