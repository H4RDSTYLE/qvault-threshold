namespace QVault.Threshold;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

/// <summary>
/// QVault Threshold Key — Shamir's Secret Sharing over GF(p).
///
/// <para>Split a private key (secret) into N shares so that:
/// <list type="bullet">
///   <item>Any K shares reconstruct the secret exactly (Lagrange interpolation).</item>
///   <item>Fewer than K shares reveal zero information about the secret.</item>
/// </list></para>
///
/// <para>The field prime is the secp256k1 prime: 2^256 − 2^32 − 977.
/// This handles secrets up to 256 bits (AES-256 keys, EC private keys, etc.).</para>
///
/// <para>Zero external dependencies. Requires .NET 8+.</para>
/// </summary>
/// <example>
/// <code>
/// var secret = new BigInteger(1337);
/// var shares = ThresholdKey.Generate(secret, 5, 3);
///
/// var recovered = ThresholdKey.Reconstruct(shares[..3]);
/// Debug.Assert(recovered == secret);
///
/// bool ok  = ThresholdKey.Verify(shares[2].X, shares[2].Y,     shares[..2]);
/// bool bad = ThresholdKey.Verify(shares[2].X, shares[2].Y + 1, shares[..2]);
/// </code>
/// </example>
public static class ThresholdKey
{
    /// <summary>secp256k1 prime: 2^256 − 2^32 − 977.</summary>
    public static readonly BigInteger P =
        BigInteger.Parse("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
                         NumberStyles.HexNumber);

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// <summary>
    /// Split <paramref name="secret"/> into <paramref name="n"/> shares
    /// with threshold <paramref name="k"/>.
    /// </summary>
    /// <param name="secret">Integer in (0, P) — the private key.</param>
    /// <param name="n">Total shares to generate.</param>
    /// <param name="k">Minimum shares required to reconstruct (2 ≤ k ≤ n).</param>
    /// <returns>Array of <paramref name="n"/> <see cref="Share"/> objects (X = 1 … n).</returns>
    /// <exception cref="ArgumentException">On invalid inputs.</exception>
    public static Share[] Generate(BigInteger secret, int n, int k)
    {
        Validate(secret, n, k);

        // f(x) = secret + a₁·x + … + a_{k-1}·x^{k-1}   (mod P)
        var coeffs = new BigInteger[k];
        coeffs[0] = secret;
        for (int i = 1; i < k; i++) coeffs[i] = RandCoeff();

        var shares = new Share[n];
        for (int i = 0; i < n; i++)
        {
            var x = new BigInteger(i + 1);
            shares[i] = new Share(x, EvalPoly(coeffs, x));
        }
        return shares;
    }

    /// <summary>
    /// Recover the secret from <paramref name="shares"/> via Lagrange interpolation.
    /// </summary>
    /// <param name="shares">At least k <see cref="Share"/> objects (extra shares are fine).</param>
    /// <returns>The reconstructed secret integer.</returns>
    /// <exception cref="ArgumentException">If fewer than 2 shares are provided or X-values repeat.</exception>
    public static BigInteger Reconstruct(IReadOnlyList<Share> shares)
    {
        if (shares.Count < 2) throw new ArgumentException("Need at least 2 shares.");
        CheckUniqueX(shares);
        return Lagrange(shares, BigInteger.Zero);
    }

    /// <summary>
    /// Verify whether <c>f(x) = claimedY</c> is consistent with <paramref name="referenceShares"/>.
    /// </summary>
    /// <param name="x">Share index to verify.</param>
    /// <param name="claimedY">Claimed share value.</param>
    /// <param name="referenceShares">Known-valid shares (at least k of them).</param>
    /// <returns><c>true</c> if the share lies on the polynomial.</returns>
    public static bool Verify(BigInteger x, BigInteger claimedY, IReadOnlyList<Share> referenceShares)
    {
        if (referenceShares.Count < 2) throw new ArgumentException("Need at least 2 reference shares.");
        CheckUniqueX(referenceShares);
        return Lagrange(referenceShares, x) == claimedY;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// <summary>Reduce n into [0, P-1], handling negatives correctly.</summary>
    private static BigInteger GfMod(BigInteger n) => ((n % P) + P) % P;

    /// <summary>Evaluate polynomial at x using Horner's method (mod P).</summary>
    private static BigInteger EvalPoly(BigInteger[] coeffs, BigInteger x)
    {
        var result = BigInteger.Zero;
        for (int i = coeffs.Length - 1; i >= 0; i--)
            result = (result * x + coeffs[i]) % P;
        return result;
    }

    /// <summary>Lagrange interpolation over GF(P) at queryX.</summary>
    private static BigInteger Lagrange(IReadOnlyList<Share> shares, BigInteger queryX)
    {
        var result = BigInteger.Zero;
        for (int i = 0; i < shares.Count; i++)
        {
            var num = BigInteger.One;
            var den = BigInteger.One;
            for (int j = 0; j < shares.Count; j++)
            {
                if (i != j)
                {
                    num = GfMod(num * GfMod(queryX       - shares[j].X));
                    den = GfMod(den * GfMod(shares[i].X  - shares[j].X));
                }
            }
            // Modular inverse via Fermat's little theorem: a^(P-2) mod P
            var li = GfMod(num * BigInteger.ModPow(den, P - 2, P));
            result = GfMod(result + shares[i].Y * li);
        }
        return result;
    }

    /// <summary>Generate a uniformly random nonzero element of GF(P).</summary>
    private static BigInteger RandCoeff()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        // Parse as unsigned big-endian 256-bit integer, then reduce into [1, P-1]
        var c = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        return c % (P - 1) + 1;
    }

    private static void Validate(BigInteger secret, int n, int k)
    {
        if (secret <= 0 || secret >= P)
            throw new ArgumentException("Secret must be in (0, P).");
        if (k < 2)
            throw new ArgumentException($"Threshold k must be >= 2. Got {k}.");
        if (n < k)
            throw new ArgumentException($"n ({n}) must be >= k ({k}).");
    }

    private static void CheckUniqueX(IReadOnlyList<Share> shares)
    {
        var xs = new HashSet<BigInteger>();
        foreach (var s in shares)
            if (!xs.Add(s.X))
                throw new ArgumentException("Duplicate share X-values detected.");
    }
}
