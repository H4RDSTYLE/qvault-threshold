# qvault-threshold

Shamir's Secret Sharing over GF(p) — implemented in **Python, JavaScript, Java, and C#** with a consistent API and guaranteed cross-language compatibility.

Used by [QVault](https://h4rdstyle.github.io/qvault) to split quantum-resistant private keys into threshold shares.

---

## What it does

A secret (e.g. a 256-bit private key) is encoded as the constant term `f(0)` of a random degree-(k-1) polynomial over a finite field GF(P). Any k of the n generated shares reconstruct the secret exactly via Lagrange interpolation; fewer than k shares reveal **zero information** about the secret (information-theoretic security).

## Field prime

All four implementations use the **secp256k1 prime**:

```
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  = 2²⁵⁶ − 2³² − 977
```

This handles secrets up to 256 bits — AES-256 keys, EC private keys, BIP-39 seeds, etc.

## API

All four languages expose the same three functions:

| Function | Description |
|---|---|
| `generate(secret, n, k)` | Split `secret` into `n` shares, threshold `k` |
| `reconstruct(shares)` | Recover the secret from k or more shares |
| `verify(x, claimedY, referenceShares)` | Check if a share lies on the polynomial |

- Secrets are integers in the open interval `(0, P)`
- Share x-coordinates are 1-indexed integers (public); y-coordinates are the secret values (private)
- Shares are tuples/records `(x, y)` or `{x, y}` depending on the language

---

## Cross-language test vector

The fixed polynomial `f(x) = 1337 + 42·x + 7·x²` over GF(P) gives:

| x | f(x) |
|---|------|
| 1 | 1386 |
| 2 | 1449 |
| 3 | 1526 |

All three shares are required to reconstruct `f(0) = 1337` (the polynomial is degree-2, so k=3 shares are needed). Every implementation in this repo passes this test, proving they produce identical results regardless of language.

---

## Python

**Requires:** Python 3.8+. Zero dependencies.

```python
from shamir import generate, reconstruct, verify

secret = 0xDEADBEEF
shares = generate(secret, n=5, k=3)
# [(1, y1), (2, y2), (3, y3), (4, y4), (5, y5)]

recovered = reconstruct(shares[:3])
assert recovered == secret

ok  = verify(shares[2][0], shares[2][1], shares[:2])      # True
bad = verify(shares[2][0], shares[2][1] + 1, shares[:2])  # False
```

**Run tests:**

```bash
cd python
python test_shamir.py
```

---

## JavaScript

**Requires:** Node.js 18+ or any modern browser. Zero dependencies.

```javascript
// ES modules
import { generate, reconstruct, verify } from './shamir.js';

// CommonJS
const { generate, reconstruct, verify } = require('./shamir.cjs');

const shares = generate(0xDEADBEEFn, 5, 3);
// [{x: 1n, y: …}, {x: 2n, y: …}, … {x: 5n, y: …}]

const secret = reconstruct(shares.slice(0, 3));
console.log(secret === 0xDEADBEEFn);  // true

const ok  = verify(shares[2].x, shares[2].y,      shares.slice(0, 2));  // true
const bad = verify(shares[2].x, shares[2].y + 1n, shares.slice(0, 2));  // false
```

**Run tests:**

```bash
cd javascript
node --test test_shamir.js
```

---

## Java

**Requires:** Java 11+. Zero dependencies.

```java
import io.qvault.threshold.Share;
import io.qvault.threshold.ThresholdKey;
import java.math.BigInteger;

var secret = new BigInteger("DEADBEEF", 16);
var shares = ThresholdKey.generate(secret, 5, 3);
// List<Share> with x = 1…5

var recovered = ThresholdKey.reconstruct(shares.subList(0, 3));
assert recovered.equals(secret);

boolean ok  = ThresholdKey.verify(shares.get(2).x(), shares.get(2).y(),
                                  shares.subList(0, 2));  // true
boolean bad = ThresholdKey.verify(shares.get(2).x(),
                                  shares.get(2).y().add(BigInteger.ONE),
                                  shares.subList(0, 2));  // false
```

**Compile and run tests:**

```bash
cd java
javac io/qvault/threshold/Share.java io/qvault/threshold/ThresholdKey.java ThresholdKeyTest.java
java -ea ThresholdKeyTest
```

---

## C#

**Requires:** .NET 8+. Zero dependencies.

```csharp
using QVault.Threshold;
using System.Numerics;

var secret = new BigInteger(0xDEADBEEF);
var shares = ThresholdKey.Generate(secret, 5, 3);
// Share[] with X = 1…5

var recovered = ThresholdKey.Reconstruct(shares[..3]);
Debug.Assert(recovered == secret);

bool ok  = ThresholdKey.Verify(shares[2].X, shares[2].Y,     shares[..2]);  // true
bool bad = ThresholdKey.Verify(shares[2].X, shares[2].Y + 1, shares[..2]);  // false
```

**Run tests:**

```bash
cd csharp
dotnet run --project ThresholdKey.csproj
```

---

## Examples

### QVault Proxy — quantum-secured API wrapper

`examples/proxy/qvault_proxy.py` is a command-line tool that fetches any HTTP endpoint,
encrypts the response body with **AES-256-GCM** using a randomly generated 256-bit key,
and splits that key into N shares via Shamir's SSS — so only a party holding at least K
shares can decrypt.

**Requires:** `pip install cryptography`

```
examples/proxy/qvault_proxy.py  encrypt <url>  [-n N] [-k K] [-o FILE]
examples/proxy/qvault_proxy.py  decrypt <bundle.json|->  [--shares X…]  [--force]
```

**Full walkthrough:**

```bash
# 1. Fetch a public API, encrypt it, save the bundle (5 shares, need 3 to decrypt)
python examples/proxy/qvault_proxy.py encrypt \
    https://jsonplaceholder.typicode.com/posts/1 \
    -o bundle.json

# 2. Decrypt using the first 3 shares (default)
python examples/proxy/qvault_proxy.py decrypt bundle.json

# 3. Decrypt using any specific 3 shares (e.g. 2, 4, 5)
python examples/proxy/qvault_proxy.py decrypt bundle.json --shares 2 4 5

# 4. Pipe directly from curl
curl -s https://jsonplaceholder.typicode.com/posts/1 \
    | python examples/proxy/qvault_proxy.py decrypt -

# 5. Demonstrate information-theoretic security: 2 shares → auth failure + garbage
python examples/proxy/qvault_proxy.py decrypt bundle.json --shares 1 2 --force
```

The bundle is a portable JSON file (v2 format):

```json
{
  "version":      "qvault/2",
  "cipher":       "aes-256-gcm",
  "endpoint":     "https://jsonplaceholder.typicode.com/posts/1",
  "content_type": "application/json; charset=utf-8",
  "fetched_at":   "2026-01-01T12:00:00+00:00",
  "n": 5,
  "k": 3,
  "shares": [
    {"x": 1, "y": "0x3f2a..."},
    {"x": 2, "y": "0x9b1c..."}
  ],
  "nonce":      "base64-encoded 12-byte GCM nonce",
  "ciphertext": "base64-encoded AES-GCM ciphertext (includes 16-byte auth tag)"
}
```

AES-256-GCM provides authenticated encryption — a wrong key (or fewer than k shares)
causes an authentication failure before any output is produced.

---

### QVault Gateway — persistent encrypted reverse proxy

`examples/gateway/qvault_gateway.py` is an HTTP server that sits in front of any set of
backend APIs. Every response is transparently encrypted with a fresh AES-256-GCM key and
returned as a bundle — clients decrypt with `qvault_proxy.py decrypt -`.

**Requires:** `pip install cryptography`

```bash
# 1. Copy and edit the example config
cp examples/gateway/gateway.example.json examples/gateway/gateway.json

# 2. Start the gateway (default: port 8080)
python examples/gateway/qvault_gateway.py examples/gateway/gateway.json

# 3. Query it like any normal API — response is an encrypted bundle
curl http://localhost:8080/posts/1

# 4. Decrypt inline
curl -s http://localhost:8080/posts/1 \
    | python examples/proxy/qvault_proxy.py decrypt -

# 5. Save then decrypt
curl -s http://localhost:8080/users/2 > bundle.json
python examples/proxy/qvault_proxy.py decrypt bundle.json --shares 1 3 5
```

**`gateway.example.json`:**

```json
{
  "port":      8080,
  "shares":    5,
  "threshold": 3,
  "routes": [
    {"path": "/posts",  "upstream": "https://jsonplaceholder.typicode.com/posts"},
    {"path": "/users",  "upstream": "https://jsonplaceholder.typicode.com/users"},
    {"path": "/todos",  "upstream": "https://jsonplaceholder.typicode.com/todos"},
    {"path": "/albums", "upstream": "https://jsonplaceholder.typicode.com/albums"}
  ]
}
```

Routes use longest-prefix matching. Built-in unencrypted endpoints:
- `GET /health` — gateway status
- `GET /routes` — list of configured routes

---

## Security notes

- **CSPRNG everywhere** — random coefficients are generated with `secrets.randbelow` (Python), `crypto.getRandomValues` (JS), `SecureRandom` (Java), and `RandomNumberGenerator.Fill` (C#).
- **Information-theoretic security** — reconstruction from fewer than k shares is mathematically impossible, not just computationally hard. No cryptographic assumptions required.
- **Secret bounds** — secrets must be in the open interval `(0, P)`. Secrets ≥ P or ≤ 0 are rejected with an error.
- **Share x-coordinates are public** — only the y-coordinates must be kept private.
- **No padding or encoding** — the secret is treated as a raw integer. Callers are responsible for serialising keys to/from integers before calling `generate`.

## License

MIT
