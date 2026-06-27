package io.qvault.threshold;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * QVault Threshold Key — Shamir's Secret Sharing over GF(p).
 *
 * <p>Split a private key (secret) into N shares so that:
 * <ul>
 *   <li>Any K shares reconstruct the secret exactly (Lagrange interpolation).</li>
 *   <li>Fewer than K shares reveal zero information about the secret.</li>
 * </ul>
 *
 * <p>The secret is the constant term f(0) of a random degree-(k-1) polynomial
 * over the finite field GF(P), where P is the 256-bit secp256k1 prime.
 * Each share is a point {@code (x, f(x) mod P)} on that polynomial.
 *
 * <p>Zero external dependencies. Requires Java 16+.
 *
 * <pre>{@code
 *   var secret = BigInteger.valueOf(1337);
 *   var shares = ThresholdKey.generate(secret, 5, 3);
 *   // Any 3 of the 5 shares reconstruct the secret.
 *
 *   var recovered = ThresholdKey.reconstruct(shares.subList(0, 3));
 *   assert recovered.equals(secret);
 *
 *   boolean ok  = ThresholdKey.verify(shares.get(2).x(), shares.get(2).y(), shares.subList(0, 2));
 *   boolean bad = ThresholdKey.verify(shares.get(2).x(), shares.get(2).y().add(BigInteger.ONE), shares.subList(0, 2));
 * }</pre>
 */
public final class ThresholdKey {

    /** secp256k1 prime: 2^256 − 2^32 − 977. */
    public static final BigInteger P =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

    private static final SecureRandom RANDOM = new SecureRandom();

    private ThresholdKey() {}

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Split {@code secret} into {@code n} shares with threshold {@code k}.
     *
     * @param secret integer in the open interval (0, P) — the private key
     * @param n      total shares to generate
     * @param k      minimum shares required to reconstruct (2 ≤ k ≤ n)
     * @return immutable list of {@code n} {@link Share} objects (x = 1 … n)
     * @throws IllegalArgumentException on invalid inputs
     */
    public static List<Share> generate(BigInteger secret, int n, int k) {
        validate(secret, n, k);

        // f(x) = secret + a_1*x + ... + a_{k-1}*x^{k-1}   (mod P)
        List<BigInteger> coeffs = new ArrayList<>(k);
        coeffs.add(secret);
        for (int i = 1; i < k; i++) coeffs.add(randCoeff());

        List<Share> shares = new ArrayList<>(n);
        for (int i = 1; i <= n; i++) {
            BigInteger x = BigInteger.valueOf(i);
            shares.add(new Share(x, evalPoly(coeffs, x)));
        }
        return List.copyOf(shares);
    }

    /**
     * Recover the secret from {@code k} or more shares via Lagrange interpolation.
     *
     * @param shares at least k {@link Share} objects (extra shares are fine)
     * @return the reconstructed secret integer
     * @throws IllegalArgumentException if fewer than 2 shares are provided or x-values repeat
     */
    public static BigInteger reconstruct(List<Share> shares) {
        if (shares.size() < 2) throw new IllegalArgumentException("Need at least 2 shares.");
        checkUniqueX(shares);
        return lagrange(shares, BigInteger.ZERO);
    }

    /**
     * Verify whether {@code f(x) = claimedY} is consistent with {@code referenceShares}.
     *
     * <p>Uses Lagrange interpolation to evaluate the polynomial at {@code x} and
     * compares the result to {@code claimedY} — without revealing the secret.
     *
     * @param x               share index to verify
     * @param claimedY        claimed share value
     * @param referenceShares known-valid shares (at least k of them)
     * @return {@code true} if the share lies on the polynomial
     */
    public static boolean verify(BigInteger x, BigInteger claimedY, List<Share> referenceShares) {
        if (referenceShares.size() < 2)
            throw new IllegalArgumentException("Need at least 2 reference shares.");
        checkUniqueX(referenceShares);
        return lagrange(referenceShares, x).equals(claimedY);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /** Evaluate polynomial at {@code x} using Horner's method (mod P). */
    private static BigInteger evalPoly(List<BigInteger> coeffs, BigInteger x) {
        BigInteger result = BigInteger.ZERO;
        for (int i = coeffs.size() - 1; i >= 0; i--)
            result = result.multiply(x).add(coeffs.get(i)).mod(P);
        return result;
    }

    /** Lagrange interpolation over GF(P), evaluated at {@code queryX}. */
    private static BigInteger lagrange(List<Share> shares, BigInteger queryX) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < shares.size(); i++) {
            BigInteger xi = shares.get(i).x();
            BigInteger yi = shares.get(i).y();
            BigInteger num = BigInteger.ONE;
            BigInteger den = BigInteger.ONE;
            for (int j = 0; j < shares.size(); j++) {
                if (i != j) {
                    BigInteger xj = shares.get(j).x();
                    num = num.multiply(queryX.subtract(xj)).mod(P);
                    den = den.multiply(xi.subtract(xj)).mod(P);
                }
            }
            // den is non-zero mod P because all x_i are distinct and < P
            BigInteger li = num.multiply(den.modInverse(P)).mod(P);
            result = result.add(yi.multiply(li)).mod(P);
        }
        return result;
    }

    /** Generate a uniformly random nonzero element of GF(P). */
    private static BigInteger randCoeff() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        // Treat as unsigned big-endian 256-bit integer, then reduce into [1, P-1]
        return new BigInteger(1, bytes).mod(P.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    private static void validate(BigInteger secret, int n, int k) {
        if (secret.compareTo(BigInteger.ZERO) <= 0 || secret.compareTo(P) >= 0)
            throw new IllegalArgumentException("Secret must be in (0, P).");
        if (k < 2)
            throw new IllegalArgumentException("Threshold k must be >= 2. Got " + k + ".");
        if (n < k)
            throw new IllegalArgumentException("n (" + n + ") must be >= k (" + k + ").");
    }

    private static void checkUniqueX(List<Share> shares) {
        Set<BigInteger> xs = new HashSet<>();
        for (Share s : shares)
            if (!xs.add(s.x()))
                throw new IllegalArgumentException("Duplicate share x-values detected.");
    }
}
