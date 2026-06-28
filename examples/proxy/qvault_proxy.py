#!/usr/bin/env python3
"""
QVault Proxy — Quantum-Secured API Wrapper
==========================================
Fetches any HTTP(S) endpoint and wraps the response in a threshold-encrypted
bundle.  The plaintext can only be recovered by a party that holds at least K
of the N key shares.

Encryption scheme
-----------------
  1. A random 256-bit secret  s  is drawn from GF(P)  (secp256k1 prime).
  2. The response body is XOR-encrypted with a SHA-256 counter-mode keystream
     derived from  s  (i.e. a stream cipher — semantically equivalent to OTP).
  3. s  is split into N shares using Shamir's Secret Sharing over GF(P).
     Any K shares reconstruct  s  exactly; fewer than K reveal zero
     information (information-theoretic security — no computational assumptions).
  4. An HMAC-SHA256 authentication tag lets the client verify the key is correct
     before decrypting.

Why "quantum-secure"
---------------------
  • The 256-bit key space resists Grover's quantum search (needs 2^128 ops).
  • Shamir's SSS is information-theoretically secure: quantum computers cannot
    help an attacker who holds fewer than K shares.

Usage
-----
  # Encrypt: fetch an endpoint and produce a bundle
  python qvault_proxy.py encrypt https://jsonplaceholder.typicode.com/posts/1

  # Encrypt: save bundle to a file, custom N/K
  python qvault_proxy.py encrypt https://api.example.com/data -n 7 -k 4 -o bundle.json

  # Decrypt: reconstruct from first K shares (default)
  python qvault_proxy.py decrypt bundle.json

  # Decrypt: choose specific shares (e.g. shares 2, 4, 5)
  python qvault_proxy.py decrypt bundle.json --shares 2 4 5

  # Demonstrate security: fewer than K shares → auth failure + garbled output
  python qvault_proxy.py decrypt bundle.json --shares 1 2 --force

Zero external dependencies.  Requires Python 3.8+ and the shamir.py library
in ../../python/ relative to this file.
"""

import sys
import os
import json
import hashlib
import hmac
import base64
import secrets
import argparse
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Locate and import the Shamir library from python/shamir.py
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "python"))
from shamir import generate, reconstruct, P  # noqa: E402

# ---------------------------------------------------------------------------
# Stream cipher — SHA-256 counter mode (CTR)
# ---------------------------------------------------------------------------

def _keystream(key_int: int, length: int) -> bytes:
    """
    Derive a keystream of exactly ``length`` bytes from a 256-bit integer key.

    Uses SHA-256 in counter mode::

        block_i = SHA-256( key_bytes || i.to_bytes(8, 'big') )
        keystream = block_0 || block_1 || …   (truncated to length bytes)
    """
    key_bytes = key_int.to_bytes(32, "big")
    blocks = []
    counter = 0
    total = 0
    while total < length:
        block = hashlib.sha256(key_bytes + counter.to_bytes(8, "big")).digest()
        blocks.append(block)
        total += len(block)
        counter += 1
    return b"".join(blocks)[:length]


def _xor(data: bytes, key_int: int) -> bytes:
    """XOR ``data`` with the keystream derived from ``key_int``.  Self-inverse."""
    ks = _keystream(key_int, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def _auth_tag(key_int: int, ciphertext: bytes) -> str:
    """HMAC-SHA256 of the ciphertext under ``key_int``.  Hex-encoded."""
    return hmac.new(key_int.to_bytes(32, "big"), ciphertext, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_encrypt(args):
    n, k = args.n, args.k

    if k < 2:
        _die("threshold k must be at least 2.")
    if k > n:
        _die(f"threshold k={k} cannot exceed total shares n={n}.")

    # 1 — Fetch the endpoint
    url = args.url
    _log(f"Fetching  {url} …")
    try:
        req = Request(url, headers={"User-Agent": "qvault-proxy/1.0"})
        with urlopen(req, timeout=15) as resp:
            status       = resp.status
            content_type = resp.headers.get("Content-Type", "application/octet-stream")
            body         = resp.read()
    except HTTPError as e:
        _die(f"HTTP {e.code}: {e.reason}")
    except URLError as e:
        _die(f"Network error: {e.reason}")

    _log(f"Response  HTTP {status} — {len(body)} bytes  ({content_type})")

    # 2 — Generate a random 256-bit encryption key in GF(P)
    key_int = secrets.randbelow(P - 1) + 1

    # 3 — Encrypt (XOR stream cipher)
    ciphertext = _xor(body, key_int)

    # 4 — Compute authentication tag
    tag = _auth_tag(key_int, ciphertext)

    # 5 — Split key into N shares (threshold K) via Shamir's SSS
    shares = generate(key_int, n=n, k=k)
    _log(f"Key split into {n} shares — any {k} reconstruct the plaintext.")

    # 6 — Build the bundle
    #     y-coordinates are 256-bit integers; use hex strings to preserve
    #     full precision when the bundle is consumed by other languages.
    bundle = {
        "version":      "qvault/1",
        "cipher":       "sha256-ctr-xor",
        "endpoint":     url,
        "content_type": content_type,
        "fetched_at":   datetime.now(timezone.utc).isoformat(),
        "n":            n,
        "k":            k,
        "shares":       [{"x": int(x), "y": hex(int(y))} for x, y in shares],
        "auth_tag":     tag,
        "ciphertext":   base64.b64encode(ciphertext).decode(),
    }

    bundle_json = json.dumps(bundle, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(bundle_json)
        _log(f"Bundle    saved to {args.output}")
    else:
        print(bundle_json)

    _log(
        f"Done.     n={n} shares, k={k} threshold, "
        f"ciphertext={len(ciphertext)} B, auth_tag={tag[:16]}…"
    )


def cmd_decrypt(args):
    # 1 — Load bundle
    with open(args.bundle) as f:
        bundle = json.load(f)

    n, k = bundle["n"], bundle["k"]
    all_shares = [(s["x"], int(s["y"], 16)) for s in bundle["shares"]]

    # 2 — Select which shares to use
    if args.shares:
        want     = {int(i) for i in args.shares}
        selected = [(x, y) for x, y in all_shares if x in want]
        missing  = want - {x for x, _ in selected}
        if missing:
            _log(f"Warning   share indices not found in bundle: {sorted(missing)}")
        if len(selected) < 2:
            _die("need at least 2 shares to call reconstruct().")
        if len(selected) < k and not args.force:
            _die(
                f"selected {len(selected)} share(s) but threshold is k={k}.\n"
                f"         Decryption would produce garbage.\n"
                f"         Pass --force to decrypt anyway (demonstrates the security property)."
            )
    else:
        selected = all_shares[:k]

    share_ids = [x for x, _ in selected]
    _log(f"Shares    using {share_ids} ({len(selected)} of {n}, threshold={k})")

    # 3 — Reconstruct the key via Lagrange interpolation
    key_int = reconstruct(selected)

    # 4 — Verify authentication tag
    ciphertext = base64.b64decode(bundle["ciphertext"])
    if "auth_tag" in bundle:
        computed = _auth_tag(key_int, ciphertext)
        if computed == bundle["auth_tag"]:
            _log("Auth      OK — key verified, shares are correct.")
        else:
            _log("Auth      FAILED — reconstructed key is wrong (too few or wrong shares).")
            if not args.force:
                _die("aborting. Pass --force to decrypt anyway.")
            _log("          --force set: decrypting anyway (output will be garbled).")

    # 5 — Decrypt
    plaintext = _xor(ciphertext, key_int)
    _log(f"Decrypted {len(plaintext)} bytes from  {bundle['endpoint']}")
    sys.stderr.flush()

    print()  # blank line before payload

    # 6 — Output (pretty-print if JSON, raw bytes otherwise)
    try:
        data = json.loads(plaintext)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception:
        sys.stdout.buffer.write(plaintext)
        sys.stdout.buffer.write(b"\n")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    print(f"[qvault] {msg}", file=sys.stderr)

def _die(msg: str) -> None:
    print(f"[qvault] Error: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="qvault_proxy",
        description="QVault Proxy — quantum-secure API wrapper using Shamir's Secret Sharing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s encrypt https://jsonplaceholder.typicode.com/posts/1
  %(prog)s encrypt https://api.example.com/data -n 7 -k 4 -o bundle.json
  %(prog)s decrypt bundle.json
  %(prog)s decrypt bundle.json --shares 2 4 5
  %(prog)s decrypt bundle.json --shares 1 2 --force
""",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # -- encrypt -------------------------------------------------------
    enc = sub.add_parser(
        "encrypt",
        help="Fetch an endpoint and produce a threshold-encrypted bundle",
    )
    enc.add_argument("url", help="HTTP(S) endpoint to fetch")
    enc.add_argument(
        "-n", type=int, default=5, dest="n", metavar="N",
        help="Total key shares to generate (default: 5)",
    )
    enc.add_argument(
        "-k", type=int, default=3, dest="k", metavar="K",
        help="Minimum shares needed to decrypt (default: 3)",
    )
    enc.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write bundle to FILE instead of stdout",
    )

    # -- decrypt -------------------------------------------------------
    dec = sub.add_parser(
        "decrypt",
        help="Reconstruct and decrypt a bundle produced by encrypt",
    )
    dec.add_argument("bundle", help="Path to the bundle JSON file")
    dec.add_argument(
        "--shares", nargs="+", metavar="X",
        help=(
            "Space-separated share x-indices to use (e.g. --shares 1 3 5). "
            "Default: first k shares."
        ),
    )
    dec.add_argument(
        "--force", action="store_true",
        help="Decrypt even if authentication fails or fewer than k shares supplied",
    )

    args = parser.parse_args()
    {"encrypt": cmd_encrypt, "decrypt": cmd_decrypt}[args.cmd](args)


if __name__ == "__main__":
    main()
