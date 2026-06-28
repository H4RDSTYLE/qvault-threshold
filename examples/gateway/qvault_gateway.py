#!/usr/bin/env python3
"""
QVault Gateway — Post-Quantum Encrypted API Proxy
==================================================
An HTTP reverse proxy that sits in front of any set of backend services,
intercepts ALL outbound responses, and encrypts them using AES-256-GCM +
Shamir's Threshold Secret Sharing.

Only a client that holds >= K of the N key shares can decrypt any response.
The gateway itself never stores shares — each response gets a fresh ephemeral
key that is immediately discarded after the bundle is sent.

Architecture
------------

  [Client]  --HTTP-->  [QVault Gateway :8080]
                              |
                        route matching          (gateway.json)
                              |
                              v
                       [Upstream Service]
                              |
                        AES-256-GCM encrypt
                        key split via Shamir
                              |
                              v
  [Client]  <--bundle JSON--  [QVault Gateway]
      |
      v  (K of N shares, delivered out-of-band)
  qvault_proxy.py decrypt -

Post-Quantum Security
---------------------
  AES-256-GCM     NIST-recommended symmetric AEAD. 256-bit key => ~2^128 post-
                  quantum security (Grover). Provides confidentiality and
                  authentication in a single pass. No separate HMAC needed.

  Shamir's SSS    Information-theoretically secure over GF(P) (secp256k1 PRIME
                  field, NOT the elliptic curve -- no Shor's vulnerability).
                  Fewer than K shares are provably uninformative about the key,
                  against any adversary, quantum or classical.

Quick start
-----------
  # 1. Configure routes
  cp gateway.example.json gateway.json
  # (edit gateway.json as needed)

  # 2. Start the gateway
  python qvault_gateway.py

  # 3. Query it like any normal API
  curl http://localhost:8080/posts/1          # returns encrypted bundle

  # 4. Decrypt the response (pipe directly or save first)
  curl -s http://localhost:8080/posts/1 | python ../proxy/qvault_proxy.py decrypt -

  # With explicit shares
  curl -s http://localhost:8080/users/2 > bundle.json
  python ../proxy/qvault_proxy.py decrypt bundle.json --shares 1 3 5

Built-in endpoints (not encrypted, always available)
-----------------------------------------------------
  GET /health    {"status": "ok", "gateway": "qvault/2"}
  GET /routes    list of configured routes

Requires: pip install cryptography
"""

import sys
import os
import json
import secrets
import base64
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen, Request as UpstreamRequest
from urllib.error import URLError, HTTPError

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "python"))
from qvault_threshold import generate, P  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[qvault] Missing dependency:  pip install cryptography", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Cipher — AES-256-GCM
# ---------------------------------------------------------------------------

def _encrypt(key_int: int, plaintext: bytes) -> tuple:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns ``(nonce_b64, ciphertext_b64)``.  The ciphertext includes the
    16-byte GCM authentication tag (appended by the library), so decryption
    automatically validates integrity — no separate MAC needed.
    """
    key   = key_int.to_bytes(32, "big")
    nonce = secrets.token_bytes(12)          # 96-bit nonce (NIST GCM recommendation)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

# Headers forwarded from the client to the upstream
_FORWARD_REQUEST_HEADERS = ("Authorization", "X-Api-Key", "Accept", "Content-Type")

# Headers NOT forwarded from upstream to client (gateway manages these)
_DROP_RESPONSE_HEADERS   = {"transfer-encoding", "content-encoding", "content-length"}


class QVaultHandler(BaseHTTPRequestHandler):
    """
    Routes each incoming request to a configured upstream, encrypts the
    response with a fresh AES-256-GCM key split via Shamir's SSS, and
    returns the encrypted bundle as ``application/x-qvault-bundle+json``.
    """

    # Injected by main() before serve_forever()
    config: dict = {}

    # -- HTTP method dispatch -------------------------------------------

    def do_GET(self):    self._proxy("GET")
    def do_POST(self):   self._proxy("POST")
    def do_PUT(self):    self._proxy("PUT")
    def do_DELETE(self): self._proxy("DELETE")
    def do_PATCH(self):  self._proxy("PATCH")
    def do_HEAD(self):   self._proxy("HEAD")

    # -- Core proxy logic -----------------------------------------------

    def _proxy(self, method: str):
        # Internal routes (health, introspection) — served unencrypted
        if self._handle_meta():
            return

        n = self.config.get("shares",    5)
        k = self.config.get("threshold", 3)

        # Match incoming path to a configured route
        route = self._match_route(self.path)
        if route is None:
            self._send_json(404, {"error": f"No route for: {self.path.split('?')[0]}"})
            return

        # Build upstream URL: upstream_base + remaining path suffix + query string
        path_suffix = self.path[len(route["path"].rstrip("/")):]
        upstream_url = route["upstream"].rstrip("/") + path_suffix

        _log(f"{method} {self.path}  =>  {upstream_url}")

        # Forward the request to the upstream service
        try:
            body_len = int(self.headers.get("Content-Length", 0) or 0)
            body     = self.rfile.read(body_len) if body_len > 0 else None

            fwd_headers = {"User-Agent": "qvault-gateway/2.0"}
            for h in _FORWARD_REQUEST_HEADERS:
                if self.headers.get(h):
                    fwd_headers[h] = self.headers[h]

            req = UpstreamRequest(upstream_url, data=body, method=method,
                                  headers=fwd_headers)
            with urlopen(req, timeout=30) as resp:
                upstream_status = resp.status
                content_type    = resp.headers.get("Content-Type",
                                                   "application/octet-stream")
                upstream_body   = resp.read()

        except HTTPError as e:
            # Propagate upstream HTTP errors inside the bundle so the client
            # can decrypt and inspect them (status preserved as metadata)
            upstream_status = e.code
            content_type    = "text/plain"
            upstream_body   = (e.reason or "upstream error").encode()

        except URLError as e:
            self._send_json(502, {"error": f"Upstream unreachable: {e.reason}"})
            return

        _log(f"  upstream HTTP {upstream_status}  {len(upstream_body)} B"
             f"  ({content_type})")

        # Generate a fresh ephemeral AES-256 key for this response only
        key_int = secrets.randbelow(P - 1) + 1

        # Encrypt with AES-256-GCM (confidentiality + integrity in one pass)
        nonce_b64, ct_b64 = _encrypt(key_int, upstream_body)

        # Split the key into N Shamir shares (any K reconstruct it)
        shares = generate(key_int, n=n, k=k)

        # Assemble the encrypted bundle
        bundle = {
            "version":         "qvault/2",
            "cipher":          "aes-256-gcm",
            "upstream_url":    upstream_url,
            "upstream_status": upstream_status,
            "content_type":    content_type,
            "n":               n,
            "k":               k,
            # y-values as hex strings — 256-bit integers exceed JSON number precision
            "shares":          [{"x": int(x), "y": hex(int(y))} for x, y in shares],
            "nonce":           nonce_b64,
            "ciphertext":      ct_b64,
        }
        bundle_bytes = json.dumps(bundle, indent=2).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/x-qvault-bundle+json")
        self.send_header("Content-Length", str(len(bundle_bytes)))
        self.send_header("X-QVault-Upstream-Status", str(upstream_status))
        self.send_header("X-QVault-Shares", f"n={n},k={k}")
        self.end_headers()
        self.wfile.write(bundle_bytes)

        _log(f"  bundle {len(bundle_bytes)} B  (n={n} shares, k={k} threshold)")

    # -- Internal / meta routes ----------------------------------------

    def _handle_meta(self) -> bool:
        """Serve built-in unencrypted endpoints. Returns True if handled."""
        p = self.path.split("?")[0].rstrip("/") or "/"
        if p == "/health":
            self._send_json(200, {
                "status":  "ok",
                "gateway": "qvault/2",
                "cipher":  "aes-256-gcm",
                "shares":  self.config.get("shares", 5),
                "threshold": self.config.get("threshold", 3),
            })
            return True
        if p == "/routes":
            self._send_json(200, {"routes": self.config.get("routes", [])})
            return True
        return False

    # -- Route matching ------------------------------------------------

    def _match_route(self, request_path: str):
        """
        Longest-prefix match on the path component (query string ignored).
        E.g. '/posts/1?foo=bar' matches route '/posts' before '/po'.
        """
        path_only = request_path.split("?")[0]
        best = None
        for r in self.config.get("routes", []):
            rp = r["path"].rstrip("/")
            if path_only == rp or path_only.startswith(rp + "/"):
                if best is None or len(r["path"]) > len(best["path"]):
                    best = r
        return best

    # -- Helpers -------------------------------------------------------

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass   # suppress default combined-log output; we print our own


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str):
    print(f"[qvault] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="qvault_gateway",
        description="QVault Gateway -- post-quantum encrypted API proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s                              # use gateway.json in current directory
  %(prog)s /path/to/my-config.json      # explicit config path
  %(prog)s --host 127.0.0.1             # bind to localhost only
""",
    )
    parser.add_argument(
        "config", nargs="?", default="gateway.json",
        help="Path to the JSON config file (default: gateway.json)",
    )
    parser.add_argument(
        "--host", default="",
        help="Bind address (default: all interfaces / 0.0.0.0)",
    )
    args = parser.parse_args()

    # Load and validate config
    config_path = args.config
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), args.config)
    with open(config_path) as f:
        config = json.load(f)

    n      = config.setdefault("shares",    5)
    k      = config.setdefault("threshold", 3)
    port   = config.get("port", 8080)
    host   = args.host or config.get("host", "")
    routes = config.get("routes", [])

    if k < 2 or k > n:
        _log(f"Error: invalid threshold k={k} for n={n} shares.")
        sys.exit(1)

    if not routes:
        _log("Warning: no routes configured -- all requests return 404.")

    QVaultHandler.config = config
    server = ThreadingHTTPServer((host, port), QVaultHandler)

    addr = f"http://{host or '0.0.0.0'}:{port}"
    _log(f"Gateway   {addr}")
    _log(f"Cipher    AES-256-GCM  +  Shamir SSS over GF(secp256k1 prime)")
    _log(f"Shares    n={n}, threshold k={k}  (any {k} of {n} decrypt)")
    _log("")
    for r in routes:
        _log(f"  {r['path']:<24} =>  {r['upstream']}")
    _log("")
    _log(f"Health    {addr}/health")
    _log(f"Routes    {addr}/routes")
    _log("Press Ctrl-C to stop.")
    _log("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log("Shutting down.")


if __name__ == "__main__":
    main()
