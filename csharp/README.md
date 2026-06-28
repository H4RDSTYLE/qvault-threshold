# QVault.Threshold (C#)

Shamir's Secret Sharing over GF(secp256k1 prime) — post-quantum key splitting for .NET.

Zero external dependencies. Requires .NET 6+.

## Install

```bash
dotnet add package QVault.Threshold
```

## Quick start

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

## API

| Method | Description |
|---|---|
| `ThresholdKey.Generate(secret, n, k)` | Split `secret` into `n` shares, threshold `k` |
| `ThresholdKey.Reconstruct(shares)` | Recover the secret from k or more shares |
| `ThresholdKey.Verify(x, y, referenceShares)` | Check if a share lies on the polynomial |

## License

MIT — see [main README](https://github.com/H4RDSTYLE/qvault-threshold) for full documentation.
