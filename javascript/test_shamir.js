/**
 * Tests for shamir.js (ESM) — run with:  node --test test_shamir.js
 * Mirrors the Python test suite, including the cross-language fixed-vector test.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generate, reconstruct, verify, P } from './shamir.js';

test('2-of-3 reconstruction', () => {
  const secret = 1337n;
  const shares = generate(secret, 3, 2);
  assert.equal(reconstruct(shares.slice(0, 2)), secret);
  assert.equal(reconstruct(shares.slice(1)),    secret);
  assert.equal(reconstruct([shares[0], shares[2]]), secret);
});

test('3-of-5 reconstruction', () => {
  const secret = 99_999n;
  const shares = generate(secret, 5, 3);
  assert.equal(reconstruct(shares.slice(0, 3)), secret);
  assert.equal(reconstruct(shares.slice(1, 4)), secret);
  assert.equal(reconstruct(shares.slice(2)),    secret);
});

test('5-of-7 reconstruction', () => {
  const secret = 0xDEADBEEFCAFEn;
  const shares = generate(secret, 7, 5);
  assert.equal(reconstruct(shares.slice(0, 5)), secret);
  assert.equal(reconstruct(shares.slice(2)),    secret);
});

test('max valid secret (P - 1)', () => {
  const secret = P - 1n;
  const shares = generate(secret, 3, 2);
  assert.equal(reconstruct(shares.slice(0, 2)), secret);
});

test('all consecutive subsets agree', () => {
  const secret = 9_876_543n;
  const shares = generate(secret, 7, 3);
  for (let i = 0; i <= 4; i++)
    assert.equal(reconstruct(shares.slice(i, i + 3)), secret, `subset ${i} failed`);
});

test('extra shares still reconstruct correctly', () => {
  const secret = 42n;
  const shares = generate(secret, 5, 2);
  assert.equal(reconstruct(shares), secret);  // all 5 shares
});

test('verify: all shares are valid', () => {
  // k=3 scheme: need at least 3 reference shares to define the degree-2 polynomial
  const shares = generate(12_345n, 5, 3);
  for (let i = 0; i < shares.length; i++) {
    const others = shares.filter((_, j) => j !== i).slice(0, 3);
    assert.ok(verify(shares[i].x, shares[i].y, others), `share ${i + 1} should be valid`);
  }
});

test('verify: off-by-one is rejected', () => {
  const shares = generate(12_345n, 5, 2);
  const { x, y } = shares[2];
  assert.equal(verify(x, (y + 1n) % P, shares.slice(0, 2)), false);
});

test('verify: zero y-value is rejected', () => {
  const shares = generate(777n, 3, 2);
  assert.equal(verify(shares[0].x, 0n, [shares[1], shares[2]]), false);
});

test('tampered share produces wrong secret', () => {
  const secret = 5_000n;
  const shares = generate(secret, 5, 3);
  const tampered = [{ x: shares[0].x, y: (shares[0].y + 1_000n) % P }, ...shares.slice(1, 3)];
  assert.notEqual(reconstruct(tampered), secret);
});

test('validation: secret = 0 throws', () => {
  assert.throws(() => generate(0n, 3, 2), RangeError);
});

test('validation: k > n throws', () => {
  assert.throws(() => generate(1n, 3, 5), RangeError);
});

test('validation: k = 1 throws', () => {
  assert.throws(() => generate(1n, 3, 1), RangeError);
});

test('cross-language fixed vector: f(x) = 1337 + 42x + 7x²', () => {
  // Degree-2 polynomial => need all 3 shares (k=3) to reconstruct f(0)=1337.
  // These exact values must be reproduced by Python, Java, and C#.
  const shares = [
    { x: 1n, y: 1386n },
    { x: 2n, y: 1449n },
    { x: 3n, y: 1526n },
  ];
  assert.equal(reconstruct(shares), 1337n);
});
