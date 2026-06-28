#!/usr/bin/env python3
"""
QVault Gateway — Post-Quantum Encrypted API Proxy
==================================================
A bidirectional HTTP reverse proxy with AES-256-GCM + Shamir SSS encryption.

  EGRESS  — outbound requests: gateway fetches upstream APIs and returns
             encrypted bundles.  Any client holding >= K shares can decrypt.

  INGRESS — inbound requests: external partners encrypt their HTTP request
             bodies as qvault bundles.  The gateway holds all N ingress-key
             shares, decrypts the body, and forwards plaintext to internal
             services.  Responses are returned in plaintext (or re-encrypted
             when encrypt_response: true on the route).

Architecture
------------

  EGRESS (outbound):
    [Internal client]  --GET /posts/1-->  [QVault Gateway]
                                                  |
                                           fetch upstream
                                           AES-256-GCM encrypt + Shamir split
                                                  |
    [Internal client]  <--bundle JSON--  [QVault Gateway]
        |
        v  (K of N shares, pre-distributed)
    qvault_proxy.py decrypt -

  INGRESS (inbound):
    [External partner]  --POST /api/orders (qvault bundle)-->  [QVault Gateway]
                                                                       |
                                                                AES-256-GCM decrypt
                                                                (using all N ingress shares)
                                                                       |
                                                                forward plaintext
                                                                       |
                                                                [Internal service]

Quick start
-----------
  # 1. Generate an ingress key (shares for inbound encrypted requests)
  python qvault_gateway.py keygen -n 5 -k 3 > ingress-key.json

  # 2. Copy example config and edit routes
  cp gateway.example.json gateway.json

  # 3. Start the gateway
  python qvault_gateway.py serve gateway.json

  # 4. Egress: query upstream APIs, get encrypted responses
  curl -s http://localhost:8080/posts/1 | python ../proxy/qvault_proxy.py decrypt -

  # 5. Ingress: send an encrypted request
  python ../proxy/qvault_proxy.py encrypt https://internal/api/orders -o req.json
  curl -s http://localhost:8080/api/orders -d @req.json \\
       -H "Content-Type: application/x-qvault-bundle+json"

Built-in endpoints (always unencrypted)
----------------------------------------
  GET /health    gateway status
  GET /routes    egress and ingress route listing

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
from qvault_threshold import generate, reconstruct, P  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("[qvault] Missing dependency:  pip install cryptography", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Cipher — AES-256-GCM
# ---------------------------------------------------------------------------

def _encrypt(key_int: int, plaintext: bytes) -> tuple:
    key   = key_int.to_bytes(32, "big")
    nonce = secrets.token_bytes(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()


def _decrypt(key_int: int, nonce_b64: str, ct_b64: str):
    """Returns plaintext bytes, or None if the GCM authentication tag fails."""
    key   = key_int.to_bytes(32, "big")
    nonce = base64.b64decode(nonce_b64)
    ct    = base64.b64decode(ct_b64)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except InvalidTag:
        return None


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

_FORWARD_REQUEST_HEADERS = ("Authorization", "X-Api-Key", "Accept", "Content-Type")


class QVaultHandler(BaseHTTPRequestHandler):
    """Bidirectional encrypted reverse proxy handler."""

    config: dict = {}   # injected by serve()

    # HTTP method dispatch
    def do_GET(self):    self._proxy("GET")
    def do_POST(self):   self._proxy("POST")
    def do_PUT(self):    self._proxy("PUT")
    def do_DELETE(self): self._proxy("DELETE")
    def do_PATCH(self):  self._proxy("PATCH")
    def do_HEAD(self):   self._proxy("HEAD")

    # -----------------------------------------------------------------------

    def _proxy(self, method: str):
        if self._handle_meta():
            return

        # Ingress check: client sent an encrypted bundle to us
        ingress_cfg = self.config.get("ingress", {})
        ingress_route = _match(self.path, ingress_cfg.get("routes", []))
        if ingress_route:
            self._handle_ingress(method, ingress_route, ingress_cfg)
            return

        # Egress check: client wants us to fetch an upstream API and encrypt
        n = self.config.get("shares",    5)
        k = self.config.get("threshold", 3)
        egress_route = _match(self.path, self.config.get("routes", []))
        if egress_route:
            self._handle_egress(method, egress_route, n, k)
            return

        self._send_json(404, {"error": f"No route for: {self.path.split('?')[0]}"})

    # -----------------------------------------------------------------------
    # EGRESS — fetch upstream, encrypt response
    # -----------------------------------------------------------------------

    def _handle_egress(self, method: str, route: dict, n: int, k: int):
        path_suffix  = self.path[len(route["path"].rstrip("/")):]
        upstream_url = route["upstream"].rstrip("/") + path_suffix

        _log(f"EGRESS  {method} {self.path}  =>  {upstream_url}")

        try:
            body_len = int(self.headers.get("Content-Length", 0) or 0)
            body     = self.rfile.read(body_len) if body_len > 0 else None

            fwd = {"User-Agent": "qvault-gateway/2.0"}
            for h in _FORWARD_REQUEST_HEADERS:
                if self.headers.get(h):
                    fwd[h] = self.headers[h]

            req = UpstreamRequest(upstream_url, data=body, method=method, headers=fwd)
            with urlopen(req, timeout=30) as resp:
                status = resp.status
                ct     = resp.headers.get("Content-Type", "application/octet-stream")
                body   = resp.read()

        except HTTPError as e:
            status = e.code
            ct     = "text/plain"
            body   = (e.reason or "upstream error").encode()
        except URLError as e:
            self._send_json(502, {"error": f"Upstream unreachable: {e.reason}"})
            return

        _log(f"        upstream HTTP {status}  {len(body)} B  ({ct})")

        key_int          = secrets.randbelow(P - 1) + 1
        nonce_b64, ct_b64 = _encrypt(key_int, body)
        shares           = generate(key_int, n=n, k=k)

        bundle = {
            "version":         "qvault/2",
            "cipher":          "aes-256-gcm",
            "upstream_url":    upstream_url,
            "upstream_status": status,
            "content_type":    ct,
            "n": n, "k": k,
            "shares": [{"x": int(x), "y": hex(int(y))} for x, y in shares],
            "nonce":      nonce_b64,
            "ciphertext": ct_b64,
        }
        bundle_bytes = json.dumps(bundle, indent=2).encode()

        self.send_response(200)
        self.send_header("Content-Type",              "application/x-qvault-bundle+json")
        self.send_header("Content-Length",            str(len(bundle_bytes)))
        self.send_header("X-QVault-Upstream-Status",  str(status))
        self.send_header("X-QVault-Shares",           f"n={n},k={k}")
        self.end_headers()
        self.wfile.write(bundle_bytes)
        _log(f"        bundle {len(bundle_bytes)} B  (n={n}, k={k})")

    # -----------------------------------------------------------------------
    # INGRESS — decrypt incoming bundle, forward plaintext to internal service
    # -----------------------------------------------------------------------

    def _handle_ingress(self, method: str, route: dict, ingress_cfg: dict):
        path_suffix  = self.path[len(route["path"].rstrip("/")):]
        upstream_url = route["upstream"].rstrip("/") + path_suffix

        _log(f"INGRESS {method} {self.path}  =>  {upstream_url}")

        # Read the incoming encrypted bundle
        body_len   = int(self.headers.get("Content-Length", 0) or 0)
        body_bytes = self.rfile.read(body_len) if body_len > 0 else b""

        if not body_bytes:
            self._send_json(400, {"error": "Empty request body — expected a qvault bundle."})
            return

        try:
            bundle = json.loads(body_bytes)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Request body is not valid JSON."})
            return

        if bundle.get("version") != "qvault/2" or bundle.get("cipher") != "aes-256-gcm":
            self._send_json(400, {
                "error": "Unsupported bundle version/cipher. Expected qvault/2 + aes-256-gcm."
            })
            return

        # Reconstruct the decryption key from the configured ingress shares
        raw_shares = ingress_cfg.get("key_shares", [])
        if len(raw_shares) < 2:
            self._send_json(500, {"error": "Ingress key_shares not configured or insufficient."})
            return

        try:
            key_shares = [(s["x"], int(s["y"], 16)) for s in raw_shares]
            key_int    = reconstruct(key_shares)
        except Exception as e:
            _log(f"        key reconstruction failed: {e}")
            self._send_json(500, {"error": "Failed to reconstruct ingress key."})
            return

        plaintext = _decrypt(key_int, bundle["nonce"], bundle["ciphertext"])
        if plaintext is None:
            _log("        AES-GCM auth FAILED — wrong ingress key shares or tampered bundle")
            self._send_json(403, {
                "error": "AES-GCM authentication failed. "
                         "Wrong ingress key shares or the bundle was tampered with."
            })
            return

        _log(f"        decrypted {len(plaintext)} B — forwarding to upstream")

        # Forward the decrypted body to the internal upstream
        fwd_ct = bundle.get("content_type", "application/octet-stream")
        fwd = {
            "User-Agent":     "qvault-gateway/2.0",
            "Content-Type":   fwd_ct,
            "Content-Length": str(len(plaintext)),
        }
        for h in _FORWARD_REQUEST_HEADERS:
            v = self.headers.get(h)
            if v and h.lower() not in ("content-type", "content-length"):
                fwd[h] = v

        try:
            req = UpstreamRequest(upstream_url, data=plaintext, method=method, headers=fwd)
            with urlopen(req, timeout=30) as resp:
                up_status = resp.status
                up_ct     = resp.headers.get("Content-Type", "application/octet-stream")
                up_body   = resp.read()
        except HTTPError as e:
            up_status = e.code
            up_ct     = "text/plain"
            up_body   = (e.reason or "upstream error").encode()
        except URLError as e:
            self._send_json(502, {"error": f"Upstream unreachable: {e.reason}"})
            return

        _log(f"        upstream HTTP {up_status}  {len(up_body)} B")

        # Return the upstream response.
        # If the route has "encrypt_response": true, wrap it in a bundle.
        if route.get("encrypt_response", False):
            n           = self.config.get("shares", 5)
            k           = self.config.get("threshold", 3)
            resp_key    = secrets.randbelow(P - 1) + 1
            nonce_b64, resp_ct_b64 = _encrypt(resp_key, up_body)
            resp_shares = generate(resp_key, n=n, k=k)
            resp_bundle = {
                "version":         "qvault/2",
                "cipher":          "aes-256-gcm",
                "upstream_status": up_status,
                "content_type":    up_ct,
                "n": n, "k": k,
                "shares": [{"x": int(x), "y": hex(int(y))} for x, y in resp_shares],
                "nonce":      nonce_b64,
                "ciphertext": resp_ct_b64,
            }
            up_body = json.dumps(resp_bundle, indent=2).encode()
            up_ct   = "application/x-qvault-bundle+json"

        self.send_response(up_status)
        self.send_header("Content-Type",    up_ct)
        self.send_header("Content-Length",  str(len(up_body)))
        self.send_header("X-QVault-Ingress", "decrypted")
        self.end_headers()
        self.wfile.write(up_body)

    # -----------------------------------------------------------------------
    # Meta / built-in endpoints
    # -----------------------------------------------------------------------

    def _handle_meta(self) -> bool:
        p = self.path.split("?")[0].rstrip("/") or "/"
        if p == "/health":
            n = self.config.get("shares", 5)
            k = self.config.get("threshold", 3)
            self._send_json(200, {
                "status":    "ok",
                "gateway":   "qvault/2",
                "cipher":    "aes-256-gcm",
                "egress":    {"shares": n, "threshold": k},
                "ingress":   "configured" if self.config.get("ingress", {}).get("key_shares") else "not configured",
            })
            return True
        if p == "/routes":
            ingress_cfg = self.config.get("ingress", {})
            self._send_json(200, {
                "egress":  self.config.get("routes", []),
                "ingress": ingress_cfg.get("routes", []),
            })
            return True
        return False

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass  # suppress default combined-log; we print our own


# ---------------------------------------------------------------------------
# Route matching
# ---------------------------------------------------------------------------

def _match(request_path: str, routes: list):
    """Longest-prefix match (query string stripped for matching)."""
    path_only = request_path.split("?")[0]
    best = None
    for r in routes:
        rp = r["path"].rstrip("/")
        if path_only == rp or path_only.startswith(rp + "/"):
            if best is None or len(r["path"]) > len(best["path"]):
                best = r
    return best


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _log(msg: str):
    print(f"[qvault] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_keygen(args):
    """
    Generate a static ingress key and print:
      - The full key_shares block (all N shares) for gateway.json
      - K per-client share sets to distribute to trusted external clients
    """
    n, k = args.n, args.k
    if k < 2 or k > n:
        print(f"[keygen] Error: invalid threshold k={k} for n={n} shares.", file=sys.stderr)
        sys.exit(1)

    key_int = secrets.randbelow(P - 1) + 1
    shares  = generate(key_int, n=n, k=k)

    all_shares_json = [{"x": int(x), "y": hex(int(y))} for x, y in shares]

    print("# ================================================================")
    print("# QVault Gateway — Ingress Key Generation")
    print("# ================================================================")
    print("#")
    print("# 1. Add the block below to your gateway.json under 'ingress':")
    print("#")
    print(json.dumps({"key_shares": all_shares_json, "routes": []}, indent=2))
    print()
    print("# ================================================================")
    print(f"# 2. Distribute any {k} of the following {n} shares to trusted")
    print("#    external clients (different K shares per client is recommended):")
    print("#")
    for x, y in shares:
        print(f'#    Share {x}: {{"x": {x}, "y": "{hex(int(y))}"}}"')
    print("#")
    print("# Clients use qvault_proxy to encrypt their requests:")
    print("#   python qvault_proxy.py encrypt <url> --shares <K shares>")
    print("# ================================================================")


def cmd_serve(args):
    """Start the gateway HTTP server."""
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
    ingress_cfg = config.get("ingress", {})

    if k < 2 or k > n:
        _log(f"Error: invalid egress threshold k={k} for n={n} shares.")
        sys.exit(1)
    if not routes and not ingress_cfg.get("routes"):
        _log("Warning: no routes configured — all requests return 404.")

    QVaultHandler.config = config
    server = ThreadingHTTPServer((host, port), QVaultHandler)

    addr = f"http://{host or '0.0.0.0'}:{port}"
    _log(f"Gateway   {addr}")
    _log(f"Cipher    AES-256-GCM  +  Shamir SSS over GF(secp256k1 prime)")
    _log(f"Egress    n={n}, threshold k={k}  (any {k} of {n} decrypt)")

    if routes:
        _log("")
        _log("  EGRESS routes:")
        for r in routes:
            _log(f"    {r['path']:<24} =>  {r['upstream']}")

    if ingress_cfg.get("routes"):
        shares_count = len(ingress_cfg.get("key_shares", []))
        _log("")
        _log(f"  INGRESS routes  (key: {shares_count} shares configured):")
        for r in ingress_cfg["routes"]:
            enc = "  [encrypt_response]" if r.get("encrypt_response") else ""
            _log(f"    {r['path']:<24} =>  {r['upstream']}{enc}")
    else:
        _log("")
        _log("  INGRESS: not configured (no ingress.routes in config)")

    _log("")
    _log(f"Health    {addr}/health")
    _log(f"Routes    {addr}/routes")
    _log("Press Ctrl-C to stop.")
    _log("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log("Shutting down.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="qvault_gateway",
        description="QVault Gateway — post-quantum encrypted bidirectional API proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
subcommands:
  serve    Start the HTTP gateway server (default)
  keygen   Generate a static ingress key and print shares

examples:
  %(prog)s serve gateway.json
  %(prog)s serve gateway.json --host 127.0.0.1
  %(prog)s keygen -n 5 -k 3 > ingress-key.json
""",
    )
    sub = parser.add_subparsers(dest="cmd")

    # --- serve ---
    srv = sub.add_parser("serve", help="Start the gateway")
    srv.add_argument(
        "config", nargs="?", default="gateway.json",
        help="Path to gateway JSON config (default: gateway.json)",
    )
    srv.add_argument(
        "--host", default="",
        help="Bind address (default: all interfaces)",
    )

    # --- keygen ---
    kg = sub.add_parser("keygen", help="Generate a static ingress key")
    kg.add_argument("-n", type=int, default=5, metavar="N",
                    help="Total key shares (default: 5)")
    kg.add_argument("-k", type=int, default=3, metavar="K",
                    help="Minimum shares to decrypt (default: 3)")

    args = parser.parse_args()

    if args.cmd == "keygen":
        cmd_keygen(args)
    else:
        # 'serve' is the default if no subcommand given
        if args.cmd is None:
            # Re-parse treating the first positional as the config file
            args = parser.parse_args(["serve"] + sys.argv[1:])
        cmd_serve(args)


if __name__ == "__main__":
    main()
