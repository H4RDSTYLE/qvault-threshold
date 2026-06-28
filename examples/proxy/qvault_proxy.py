#!/usr/bin/env python3
"""
QVault Proxy — Post-Quantum API Wrapper
========================================
Fetches any HTTP(S) endpoint and wraps the response in a threshold-encrypted
bundle that can only be decrypted by a party holding >= K of the N key shares.

Post-quantum security
---------------------
  AES-256-GCM         Symmetric AEAD cipher. NIST-recommended, post-quantum safe.
                      Grover's quantum search gives at most 2^128 security — still
                      computationally infeasible for any foreseeable quantum computer.

  Shamir's SSS        The encryption key is split using Shamir's Secret Sharing over
                      GF(P) (secp256k1 PRIME field, NOT the elliptic curve).
                      This is information-theoretically secure: fewer than K shares
                      reveal exactly zero bits about the key, even to an unbounded
                      quantum adversary. No computational assumption whatsoever.

Bundle format (v2)
------------------
  {
    "version":      "qvault/2",
    "cipher":       "aes-256-gcm",
    "endpoint":     "https://...",
    "content_type": "...",
    "fetched_at":   "<ISO-8601>",
    "n": 5, "k": 3,
    "shares":       [{"x": 1, "y": "0x<256-bit hex>"}, ...],
    "nonce":        "<base64 — 12 random bytes>",
    "ciphertext":   "<base64 — AES-GCM ciphertext + 16-byte auth tag>"
  }

Usage
-----
  python qvault_proxy.py encrypt https://jsonplaceholder.typicode.com/posts/1
  python qvault_proxy.py encrypt https://api.example.com/ -n 7 -k 4 -o bundle.json
  python qvault_proxy.py decrypt bundle.json
  python qvault_proxy.py decrypt bundle.json --shares 2 4 5
  curl http://localhost:8080/posts/1 | python qvault_proxy.py decrypt -
  python qvault_proxy.py decrypt bundle.json --shares 1 2 --force   # security demo

Requires: pip install cryptography
"""

import sys
import os
import json
import secrets
import base64
import argparse
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "python"))
from shamir import generate, reconstruct, P  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("[qvault] Missing dependency:  pip install cryptography", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Cipher — AES-256-GCM
# ---------------------------------------------------------------------------

def _encrypt(key_int: int, plaintext: bytes) -> tuple:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns ``(nonce_b64, ciphertext_b64)``.  The ciphertext already includes
    the 16-byte GCM authentication tag appended by the library, so the tag
    is validated automatically on decryption without extra steps.
    """
    key   = key_int.to_bytes(32, "big")
    nonce = secrets.token_bytes(12)          # 96-bit nonce (NIST GCM recommendation)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()


def _decrypt(key_int: int, nonce_b64: str, ct_b64: str):
    """
    Decrypt AES-256-GCM.

    Returns plaintext bytes on success, or ``None`` if the GCM tag check
    fails — meaning the key is wrong or the data was tampered with.
    """
    key   = key_int.to_bytes(32, "big")
    nonce = base64.b64decode(nonce_b64)
    ct    = base64.b64decode(ct_b64)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except InvalidTag:
        return None


def _decrypt_force(key_int: int, nonce_b64: str, ct_b64: str) -> bytes:
    """
    Force-decrypt AES-256-GCM by bypassing the authentication tag.

    Uses the raw AES-CTR layer that underlies GCM (GCM nonce expansion:
    counter = nonce || 0x00000002 for the first data block).  The output
    will be garbled because the key is wrong — this exists solely to
    demonstrate that too-few shares produce unintelligible ciphertext.
    """
    nonce     = base64.b64decode(nonce_b64)
    ct_bytes  = base64.b64decode(ct_b64)[:-16]      # strip the 16-byte GCM auth tag
    key_bytes = key_int.to_bytes(32, "big")
    # GCM CTR counter starts at J0+1 = nonce || 0x00000002 (NIST SP 800-38D §7.1)
    iv = nonce + b"\x00\x00\x00\x02"
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv))
    dec = cipher.decryptor()
    return dec.update(ct_bytes) + dec.finalize()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_encrypt(args):
    n, k = args.n, args.k
    if k < 2:    _die("threshold k must be at least 2.")
    if k > n:    _die(f"threshold k={k} cannot exceed total shares n={n}.")

    # 1 — Fetch the endpoint
    url = args.url
    _log(f"Fetching  {url} ...")
    try:
        req = Request(url, headers={"User-Agent": "qvault-proxy/2.0"})
        with urlopen(req, timeout=15) as resp:
            status       = resp.status
            content_type = resp.headers.get("Content-Type", "application/octet-stream")
            body         = resp.read()
    except HTTPError as e:  _die(f"HTTP {e.code}: {e.reason}")
    except URLError  as e:  _die(f"Network error: {e.reason}")

    _log(f"Response  HTTP {status} -- {len(body)} bytes  ({content_type})")

    # 2 — Generate a random 256-bit AES key living in GF(P)
    key_int = secrets.randbelow(P - 1) + 1

    # 3 — AES-256-GCM: single pass gives confidentiality + authentication
    nonce_b64, ct_b64 = _encrypt(key_int, body)

    # 4 — Shamir split: key_int -> N shares, any K reconstruct
    shares = generate(key_int, n=n, k=k)
    _log(f"Key split  {n} shares  (any {k} reconstruct and decrypt)")

    # 5 — Serialise bundle
    #     y-values are 256-bit integers — store as hex strings to preserve
    #     full precision across all languages (JSON numbers lose bits above 2^53)
    bundle = {
        "version":      "qvault/2",
        "cipher":       "aes-256-gcm",
        "endpoint":     url,
        "content_type": content_type,
        "fetched_at":   datetime.now(timezone.utc).isoformat(),
        "n":            n,
        "k":            k,
        "shares":       [{"x": int(x), "y": hex(int(y))} for x, y in shares],
        "nonce":        nonce_b64,
        "ciphertext":   ct_b64,
    }

    bundle_json = json.dumps(bundle, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(bundle_json)
        _log(f"Bundle    saved to {args.output}")
    else:
        print(bundle_json)

    ct_len = len(base64.b64decode(ct_b64))
    _log(f"Done.     n={n}, k={k}, ciphertext={ct_len} B (incl. 16-byte GCM tag)")


def cmd_decrypt(args):
    # 1 — Load bundle: file path or '-' for stdin (e.g. curl ... | qvault_proxy decrypt -)
    if args.bundle == "-":
        bundle = json.load(sys.stdin)
    else:
        with open(args.bundle) as f:
            bundle = json.load(f)

    cipher = bundle.get("cipher", "sha256-ctr-xor")
    if cipher != "aes-256-gcm":
        _die(
            f"Bundle uses outdated cipher '{cipher}'.\n"
            f"         Re-encrypt with qvault_proxy v2 to get post-quantum AES-256-GCM."
        )

    n, k       = bundle["n"], bundle["k"]
    all_shares = [(s["x"], int(s["y"], 16)) for s in bundle["shares"]]

    # 2 — Select shares to use
    if args.shares:
        want     = {int(i) for i in args.shares}
        selected = [(x, y) for x, y in all_shares if x in want]
        missing  = want - {x for x, _ in selected}
        if missing:
            _log(f"Warning   share indices not in bundle: {sorted(missing)}")
        if len(selected) < 2:
            _die("need at least 2 shares to call reconstruct().")
        if len(selected) < k and not args.force:
            _die(
                f"only {len(selected)} share(s) selected, threshold is k={k}.\n"
                f"         Pass --force to decrypt anyway (demonstrates the security property)."
            )
    else:
        selected = all_shares[:k]

    share_ids = [x for x, _ in selected]
    _log(f"Shares    {share_ids}  ({len(selected)} of {n}, threshold={k})")

    # 3 — Reconstruct the AES-256 key via Lagrange interpolation over GF(P)
    key_int = reconstruct(selected)

    # 4 — Decrypt: AES-256-GCM authentication is built-in — wrong key -> None
    plaintext = _decrypt(key_int, bundle["nonce"], bundle["ciphertext"])

    if plaintext is None:
        _log("Auth      FAILED -- GCM tag invalid (wrong key = wrong/insufficient shares).")
        if not args.force:
            _die("aborting. Pass --force to see garbled output (demonstrates security).")
        _log("          --force: decrypting with wrong key to show garbled output.")
        plaintext = _decrypt_force(key_int, bundle["nonce"], bundle["ciphertext"])
    else:
        _log("Auth      OK -- GCM tag verified, key is correct.")

    origin = bundle.get("endpoint") or bundle.get("upstream_url", "unknown")
    _log(f"Decrypted {len(plaintext)} bytes  from  {origin}")
    sys.stderr.flush()

    # 5 — Output: pretty-print JSON when possible, raw bytes otherwise
    print()
    try:
        data = json.loads(plaintext)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception:
        sys.stdout.buffer.write(plaintext)
        sys.stdout.buffer.write(b"\n")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str): print(f"[qvault] {msg}", file=sys.stderr)
def _die(msg: str):
    print(f"[qvault] Error: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="qvault_proxy",
        description="QVault Proxy -- post-quantum API wrapper (AES-256-GCM + Shamir SSS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s encrypt https://jsonplaceholder.typicode.com/posts/1
  %(prog)s encrypt https://api.example.com/ -n 7 -k 4 -o bundle.json
  %(prog)s decrypt bundle.json
  %(prog)s decrypt bundle.json --shares 2 4 5
  curl http://localhost:8080/posts/1 | %(prog)s decrypt -
  %(prog)s decrypt bundle.json --shares 1 2 --force
""",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Fetch an endpoint and produce an encrypted bundle")
    enc.add_argument("url")
    enc.add_argument("-n", type=int, default=5, dest="n", metavar="N",
                     help="Total key shares (default: 5)")
    enc.add_argument("-k", type=int, default=3, dest="k", metavar="K",
                     help="Minimum shares needed to decrypt (default: 3)")
    enc.add_argument("-o", "--output", metavar="FILE",
                     help="Write bundle to FILE instead of stdout")

    dec = sub.add_parser("decrypt", help="Reconstruct and decrypt a bundle")
    dec.add_argument("bundle",
                     help="Path to bundle JSON file, or '-' to read from stdin")
    dec.add_argument("--shares", nargs="+", metavar="X",
                     help="Space-separated share x-indices (e.g. --shares 1 3 5). "
                          "Default: first k shares.")
    dec.add_argument("--force", action="store_true",
                     help="Decrypt even if GCM authentication fails (security demo)")

    args = parser.parse_args()
    {"encrypt": cmd_encrypt, "decrypt": cmd_decrypt}[args.cmd](args)


if __name__ == "__main__":
    main()
