/**
 * QVault Threshold Key — Shamir's Secret Sharing over GF(p)
 * ==========================================================
 * Split a private key (secret) into N shares so that:
 *   • Any K shares reconstruct the secret (Lagrange interpolation).
 *   • Fewer than K shares reveal zero information about the secret.
 *
 * Uses BigInt for arbitrary-precision arithmetic.
 * Compatible with browsers (Web Crypto API) and Node.js 18+.
 * Zero external dependencies.
 *
 * @example
 * import { generate, reconstruct, verify } from './shamir.js';
 *
 * const shares = generate(1337n, 5, 3);
 * // [{x:1n,y:…}, {x:2n,y:…}, …, {x:5n,y:…}]
 *
 * const secret = reconstruct(shares.slice(0, 3));
 * console.log(secret === 1337n);  // true
 *
 * const ok  = verify(shares[2].x, shares[2].y, shares.slice(0, 2));
 * const bad = verify(shares[2].x, shares[2].y + 1n, shares.slice(0, 2));
 * console.log(ok, bad);  // true false
 */

// ---------------------------------------------------------------------------
// Field parameters
// ---------------------------------------------------------------------------

/** secp256k1 prime: 2^256 − 2^32 − 977  (256-bit field) */
export const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;

// ---------------------------------------------------------------------------
// Random bytes provider (top-level await — valid in ES modules)
// Prefers Web Crypto (browsers, Node.js 19+); falls back to node:crypto (Node.js 18).
// ---------------------------------------------------------------------------

/** @type {(n: number) => Uint8Array} */
let _randBytes;
if (typeof globalThis.crypto?.getRandomValues === 'function') {
  const _wc = globalThis.crypto;
  _randBytes = (n) => { const a = new Uint8Array(n); _wc.getRandomValues(a); return a; };
} else {
  // Node.js 18 (Web Crypto not exposed as global in worker threads)
  const { randomBytes } = await import('node:crypto');
  _randBytes = (n) => new Uint8Array(randomBytes(n));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Split `secret` into `n` shares with threshold `k`.
 *
 * @param {bigint|number} secret - Integer in (0, P). The private key.
 * @param {number}        n      - Total shares to generate.
 * @param {number}        k      - Minimum shares to reconstruct (2 ≤ k ≤ n).
 * @returns {{ x: bigint, y: bigint }[]} Array of n share objects.
 */
export function generate(secret, n, k) {
  secret = BigInt(secret);
  _validate(secret, n, k);

  // f(x) = secret + a₁·x + … + a_{k-1}·x^{k-1}   (mod P)
  const coeffs = [secret];
  for (let i = 1; i < k; i++) coeffs.push(_randCoeff());

  return Array.from({ length: n }, (_, i) => {
    const x = BigInt(i + 1);
    return { x, y: _evalPoly(coeffs, x) };
  });
}

/**
 * Recover the secret from k or more shares via Lagrange interpolation.
 *
 * @param {{ x: bigint, y: bigint }[]} shares - At least k share objects.
 * @returns {bigint} The reconstructed secret.
 */
export function reconstruct(shares) {
  if (shares.length < 2) throw new RangeError('Need at least 2 shares.');
  _checkUniqueX(shares);
  return _lagrange(shares, 0n);
}

/**
 * Verify whether the claim f(x) = claimedY is consistent with referenceShares.
 *
 * @param {bigint|number}             x               - Share index to verify.
 * @param {bigint|number}             claimedY        - The claimed share value.
 * @param {{ x: bigint, y: bigint }[]} referenceShares - Known-valid shares (≥ k).
 * @returns {boolean}
 */
export function verify(x, claimedY, referenceShares) {
  if (referenceShares.length < 2) throw new RangeError('Need at least 2 reference shares.');
  const expected = _lagrange(referenceShares, BigInt(x));
  return BigInt(claimedY) === expected;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _gfMod(n) { return ((n % P) + P) % P; }

function _gfPow(base, exp) {
  base = _gfMod(base);
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % P;
    exp >>= 1n;
    base = base * base % P;
  }
  return result;
}

/** Modular inverse via Fermat's little theorem: a^(P-2) mod P */
function _gfInv(a) { return _gfPow(_gfMod(a), P - 2n); }

/** Evaluate polynomial at x using Horner's method (mod P). */
function _evalPoly(coeffs, x) {
  let result = 0n;
  for (let i = coeffs.length - 1; i >= 0; i--)
    result = (result * x + coeffs[i]) % P;
  return result;
}

/** Lagrange interpolation over GF(P) at queryX. */
function _lagrange(shares, queryX) {
  let result = 0n;
  for (let i = 0; i < shares.length; i++) {
    let num = 1n, den = 1n;
    for (let j = 0; j < shares.length; j++) {
      if (i !== j) {
        num = _gfMod(num * _gfMod(queryX    - shares[j].x));
        den = _gfMod(den * _gfMod(shares[i].x - shares[j].x));
      }
    }
    const li = _gfMod(num * _gfInv(den));
    result = _gfMod(result + shares[i].y * li);
  }
  return result;
}

/** Generate a uniformly random nonzero element of GF(P). */
function _randCoeff() {
  const bytes = _randBytes(32);
  let c = 0n;
  for (const b of bytes) c = (c << 8n) | BigInt(b);
  return (c % (P - 1n)) + 1n;
}

function _validate(secret, n, k) {
  if (secret <= 0n || secret >= P)
    throw new RangeError(`Secret must be in (0, P). Got ${secret}.`);
  if (k < 2) throw new RangeError(`Threshold k must be >= 2. Got ${k}.`);
  if (n < k) throw new RangeError(`n (${n}) must be >= k (${k}).`);
}

function _checkUniqueX(shares) {
  const xs = new Set(shares.map(s => s.x));
  if (xs.size !== shares.length) throw new Error('Duplicate share x-values detected.');
}
