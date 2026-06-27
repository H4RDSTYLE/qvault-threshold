"""
QVault Threshold Key — Shamir's Secret Sharing over GF(p)
=========================================================
Split a private key (secret) into N shares so that:
  • Any K shares reconstruct the secret exactly (Lagrange interpolation).
  • Fewer than K shares reveal zero information about the secret.

The secret is the constant term f(0) of a random degree-(K-1) polynomial
over the finite field GF(P), where P is the 256-bit secp256k1 prime.
Each share is a point (x, f(x) mod P) on that polynomial.

Quick start
-----------
    from shamir import generate, reconstruct, verify

    secret = 1337
    shares = generate(secret, n=5, k=3)
    # [(1, y1), (2, y2), (3, y3), (4, y4), (5, y5)]

    recovered = reconstruct(shares[:3])
    assert recovered == secret                          # True

    ok  = verify(shares[2][0], shares[2][1], shares[:2])
    bad = verify(shares[2][0], shares[2][1] + 1, shares[:2])
    assert ok and not bad

Zero external dependencies. Requires Python 3.8+.
"""

import secrets
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Field parameters
# ---------------------------------------------------------------------------

# secp256k1 prime:  2^256 − 2^32 − 977
# Handles secrets up to 256 bits (e.g. AES-256 keys, EC private keys).
P: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Public type alias
Share = Tuple[int, int]  # (x, y)  where  y = f(x) mod P


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate(secret: int, n: int, k: int) -> List[Share]:
    """
    Split *secret* into *n* shares with threshold *k*.

    Args:
        secret: Integer in the open interval (0, P).  This is the private key.
        n:      Total number of shares to produce.
        k:      Minimum shares required to reconstruct (2 ≤ k ≤ n).

    Returns:
        A list of *n* ``(x, y)`` tuples where x = 1 … n and y = f(x) mod P.

    Raises:
        ValueError: On invalid inputs.

    Example::

        shares = generate(0xDEADBEEF, n=5, k=3)
        # Any 3 of the 5 shares reconstruct 0xDEADBEEF.
        # Any 2 or fewer reveal nothing.
    """
    _validate(secret, n, k)

    # f(x) = secret + a₁·x + a₂·x² + … + a_{k-1}·x^{k-1}   (mod P)
    # secret = f(0) is never transmitted directly.
    coeffs: List[int] = [secret] + [_rand_coeff() for _ in range(k - 1)]

    return [(x, _eval(coeffs, x)) for x in range(1, n + 1)]


def reconstruct(shares: List[Share]) -> int:
    """
    Recover the secret from *k* or more shares via Lagrange interpolation.

    Args:
        shares: At least k ``(x, y)`` share tuples (extra shares are fine).

    Returns:
        The reconstructed secret integer.

    Raises:
        ValueError: If fewer than 2 shares are provided or x-values repeat.
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct.")
    _check_unique_x(shares)
    return _lagrange(shares, query_x=0)


def verify(x: int, claimed_y: int, reference_shares: List[Share]) -> bool:
    """
    Check whether the claim ``f(x) = claimed_y`` is consistent with the
    polynomial defined by *reference_shares*.

    Uses Lagrange interpolation to evaluate the polynomial at *x* and
    compares the result to *claimed_y* — without revealing the secret.

    Args:
        x:                Share index (the x coordinate to verify).
        claimed_y:        The share value being claimed.
        reference_shares: Known-valid shares (at least k of them).

    Returns:
        ``True`` if ``(x, claimed_y)`` lies on the polynomial, ``False`` otherwise.

    Example::

        # Holder claims f(3) = 6
        ok = verify(3, 6, known_shares)      # True or False
    """
    if len(reference_shares) < 2:
        raise ValueError("Need at least 2 reference shares to verify.")
    _check_unique_x(reference_shares)
    expected = _lagrange(reference_shares, query_x=x)
    return claimed_y == expected


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _rand_coeff() -> int:
    """Uniformly random nonzero element of GF(P)."""
    return secrets.randbelow(P - 1) + 1  # [1, P-1]


def _eval(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial at *x* using Horner's method (mod P)."""
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % P
    return result


def _lagrange(points: List[Share], query_x: int) -> int:
    """Lagrange interpolation over GF(P), evaluated at *query_x*."""
    result = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = num * (query_x - xj) % P
                den = den * (xi - xj) % P
        # Modular inverse via Fermat: a^(P-2) = a^{-1}  (mod P)
        li = num * pow(den, P - 2, P) % P
        result = (result + yi * li) % P
    return result


def _validate(secret: int, n: int, k: int) -> None:
    if not (0 < secret < P):
        raise ValueError(f"Secret must be in (0, P). Got {secret!r}.")
    if k < 2:
        raise ValueError(f"Threshold k must be ≥ 2. Got {k}.")
    if n < k:
        raise ValueError(f"Total shares n ({n}) must be ≥ threshold k ({k}).")


def _check_unique_x(shares: List[Share]) -> None:
    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("Duplicate share x-values detected.")
