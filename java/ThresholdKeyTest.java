import io.qvault.threshold.Share;
import io.qvault.threshold.ThresholdKey;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight test suite for ThresholdKey.java
 *
 * Compile and run:
 *   javac io/qvault/threshold/Share.java io/qvault/threshold/ThresholdKey.java ThresholdKeyTest.java
 *   java -ea ThresholdKeyTest
 */
public class ThresholdKeyTest {

    static final BigInteger P = ThresholdKey.P;
    static int passed = 0, failed = 0;

    public static void main(String[] args) {
        run("test2of3",                ThresholdKeyTest::test2of3);
        run("test3of5",                ThresholdKeyTest::test3of5);
        run("test5of7",                ThresholdKeyTest::test5of7);
        run("testLargeSecret",         ThresholdKeyTest::testLargeSecret);
        run("testAllSubsetsAgree",     ThresholdKeyTest::testAllSubsetsAgree);
        run("testExtraShares",         ThresholdKeyTest::testExtraShares);
        run("testVerifyValid",         ThresholdKeyTest::testVerifyValid);
        run("testVerifyInvalidOffBy1", ThresholdKeyTest::testVerifyInvalidOffBy1);
        run("testVerifyInvalidZero",   ThresholdKeyTest::testVerifyInvalidZero);
        run("testTamperedShare",       ThresholdKeyTest::testTamperedShare);
        run("testValidationSecretZero",ThresholdKeyTest::testValidationSecretZero);
        run("testValidationKTooLarge", ThresholdKeyTest::testValidationKTooLarge);
        run("testValidationKOne",      ThresholdKeyTest::testValidationKOne);
        run("testCrossLanguageVector", ThresholdKeyTest::testCrossLanguageVector);

        System.out.println("\n" + passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void run(String name, Runnable fn) {
        try {
            fn.run();
            System.out.println("  \u2713 " + name);
            passed++;
        } catch (Throwable e) {
            System.out.println("  \u2717 " + name + ": " + e.getMessage());
            failed++;
        }
    }

    static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    // -----------------------------------------------------------------------

    static void test2of3() {
        var secret = BigInteger.valueOf(1337);
        var shares = ThresholdKey.generate(secret, 3, 2);
        check(ThresholdKey.reconstruct(shares.subList(0, 2)).equals(secret), "first 2");
        check(ThresholdKey.reconstruct(shares.subList(1, 3)).equals(secret), "last 2");
        check(ThresholdKey.reconstruct(List.of(shares.get(0), shares.get(2))).equals(secret), "0+2");
    }

    static void test3of5() {
        var secret = BigInteger.valueOf(99_999);
        var shares = ThresholdKey.generate(secret, 5, 3);
        check(ThresholdKey.reconstruct(shares.subList(0, 3)).equals(secret), "0-2");
        check(ThresholdKey.reconstruct(shares.subList(1, 4)).equals(secret), "1-3");
        check(ThresholdKey.reconstruct(shares.subList(2, 5)).equals(secret), "2-4");
    }

    static void test5of7() {
        var secret = new BigInteger("DEADBEEFCAFE", 16);
        var shares = ThresholdKey.generate(secret, 7, 5);
        check(ThresholdKey.reconstruct(shares.subList(0, 5)).equals(secret), "first 5");
        check(ThresholdKey.reconstruct(shares.subList(2, 7)).equals(secret), "last 5");
    }

    static void testLargeSecret() {
        var secret = P.subtract(BigInteger.ONE);
        var shares = ThresholdKey.generate(secret, 3, 2);
        check(ThresholdKey.reconstruct(shares.subList(0, 2)).equals(secret), "P-1");
    }

    static void testAllSubsetsAgree() {
        var secret = BigInteger.valueOf(9_876_543);
        var shares = ThresholdKey.generate(secret, 7, 3);
        for (int i = 0; i <= 4; i++)
            check(ThresholdKey.reconstruct(shares.subList(i, i + 3)).equals(secret),
                  "subset " + i + " failed");
    }

    static void testExtraShares() {
        var secret = BigInteger.valueOf(42);
        var shares = ThresholdKey.generate(secret, 5, 2);
        check(ThresholdKey.reconstruct(shares).equals(secret), "all 5 shares");
    }

    static void testVerifyValid() {
        var shares = ThresholdKey.generate(BigInteger.valueOf(12_345), 5, 3);
        for (int i = 0; i < shares.size(); i++) {
            List<Share> others = new ArrayList<>();
            for (int j = 0; j < shares.size(); j++) if (j != i) others.add(shares.get(j));
            // k=3 scheme: need at least 3 reference shares to define the degree-2 polynomial
            check(ThresholdKey.verify(shares.get(i).x(), shares.get(i).y(), others.subList(0, 3)),
                  "share " + (i + 1) + " should be valid");
        }
    }

    static void testVerifyInvalidOffBy1() {
        var shares = ThresholdKey.generate(BigInteger.valueOf(12_345), 5, 2);
        var s = shares.get(2);
        check(!ThresholdKey.verify(s.x(), s.y().add(BigInteger.ONE).mod(P), shares.subList(0, 2)),
              "off-by-one should be invalid");
    }

    static void testVerifyInvalidZero() {
        var shares = ThresholdKey.generate(BigInteger.valueOf(777), 3, 2);
        check(!ThresholdKey.verify(shares.get(0).x(), BigInteger.ZERO,
              List.of(shares.get(1), shares.get(2))),
              "y=0 should be invalid");
    }

    static void testTamperedShare() {
        var secret = BigInteger.valueOf(5_000);
        var shares = ThresholdKey.generate(secret, 5, 3);
        List<Share> tampered = List.of(
                new Share(shares.get(0).x(), shares.get(0).y().add(BigInteger.valueOf(1_000)).mod(P)),
                shares.get(1), shares.get(2)
        );
        check(!ThresholdKey.reconstruct(tampered).equals(secret), "tampered should fail");
    }

    static void testValidationSecretZero() {
        try {
            ThresholdKey.generate(BigInteger.ZERO, 3, 2);
            throw new AssertionError("Should have thrown");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    static void testValidationKTooLarge() {
        try {
            ThresholdKey.generate(BigInteger.ONE, 3, 5);
            throw new AssertionError("Should have thrown");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    static void testValidationKOne() {
        try {
            ThresholdKey.generate(BigInteger.ONE, 3, 1);
            throw new AssertionError("Should have thrown");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    static void testCrossLanguageVector() {
        // Fixed polynomial: f(x) = 1337 + 42*x + 7*x^2  over GF(P)
        // Degree-2 polynomial => k=3: need all 3 shares to reconstruct f(0).
        // Must match Python, JavaScript, and C# exactly.
        var s1 = new Share(BigInteger.ONE,          BigInteger.valueOf(1386));
        var s2 = new Share(BigInteger.TWO,          BigInteger.valueOf(1449));
        var s3 = new Share(BigInteger.valueOf(3),   BigInteger.valueOf(1526));
        check(ThresholdKey.reconstruct(List.of(s1, s2, s3)).equals(BigInteger.valueOf(1337)), "all 3 shares");
    }
}
