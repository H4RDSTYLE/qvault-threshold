package io.qvault.threshold;

import java.math.BigInteger;
import java.util.Objects;

/**
 * An (x, y) share point on the secret polynomial f(x) over GF(P).
 *
 * <p>The {@code x} coordinate is the share index (1-indexed, public).
 * The {@code y} coordinate is the secret share value (must be kept private).
 */
public final class Share {
    private final BigInteger x;
    private final BigInteger y;

    public Share(BigInteger x, BigInteger y) {
        this.x = Objects.requireNonNull(x, "x");
        this.y = Objects.requireNonNull(y, "y");
    }

    /** Convenience constructor accepting long values. */
    public Share(long x, long y) {
        this(BigInteger.valueOf(x), BigInteger.valueOf(y));
    }

    public BigInteger x() { return x; }
    public BigInteger y() { return y; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Share)) return false;
        Share s = (Share) o;
        return x.equals(s.x) && y.equals(s.y);
    }

    @Override
    public int hashCode() { return Objects.hash(x, y); }

    @Override
    public String toString() { return "Share{x=" + x + ", y=" + y + "}"; }
}
