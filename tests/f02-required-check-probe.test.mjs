// Temporary F02 ruleset verification; this branch must never be merged.
import test from 'node:test';
import assert from 'node:assert/strict';

test('F02 required-check negative probe (intentional failure)', () => {
  assert.fail('Expected failure to verify the source-contracts merge gate');
});
