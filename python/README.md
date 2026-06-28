# qvault-threshold (Python)

Shamir's Secret Sharing over GF(secp256k1 prime) — post-quantum key splitting.

Zero external dependencies. Requires Python 3.8+.

## Install

```bash
pip install qvault-threshold
```

## Quick start

```python
from qvault_threshold import generate, reconstruct, verify

secret = 0xDEADBEEF
shares = generate(secret, n=5, k=3)
# [(1, y1), (2, y2), (3, y3), (4, y4), (5, y5)]

# Any 3 of the 5 shares reconstruct the secret
recovered = reconstruct(shares[:3])
assert recovered == secret

# verify: does share (x=3, y=?) lie on the polynomial?
ok  = verify(shares[2][0], shares[2][1],     shares[:2])  # True
bad = verify(shares[2][0], shares[2][1] + 1, shares[:2])  # False
```

## API

| Function | Description |
|---|---|
| `generate(secret, n, k)` | Split `secret` into `n` shares, threshold `k` |
| `reconstruct(shares)` | Recover the secret from k or more `(x, y)` tuples |
| `verify(x, y, reference_shares)` | Check if a share lies on the polynomial |

- **`secret`** — integer in the open interval `(0, P)` where `P` is the secp256k1 prime (2²⁵⁶ − 2³² − 977)
- **Shares** — list of `(x: int, y: int)` tuples; x-values are 1-indexed and public, y-values are private

## Security

- **CSPRNG** — random coefficients via `secrets.randbelow` (OS entropy)
- **Information-theoretic** — fewer than `k` shares are provably uninformative, against any adversary including quantum computers
- **No computational assumptions** — security does not depend on any hard problem

## Full documentation

See the [main README](https://github.com/H4RDSTYLE/qvault-threshold) for cross-language compatibility, test vectors, and the QVault Gateway/Proxy tools.

## License

MIT
