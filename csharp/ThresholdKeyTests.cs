using QVault.Threshold;
using System;
using System.Collections.Generic;
using System.Numerics;

/// <summary>
/// Lightweight test suite for ThresholdKey.cs
///
/// Run with:  dotnet run --project ThresholdKey.csproj
/// </summary>
static class ThresholdKeyTests
{
    static readonly BigInteger P = ThresholdKey.P;
    static int _passed = 0, _failed = 0;

    static int Main()
    {
        Run("Test2of3",                  Test2of3);
        Run("Test3of5",                  Test3of5);
        Run("Test5of7",                  Test5of7);
        Run("TestLargeSecret",           TestLargeSecret);
        Run("TestAllSubsetsAgree",       TestAllSubsetsAgree);
        Run("TestExtraShares",           TestExtraShares);
        Run("TestVerifyValid",           TestVerifyValid);
        Run("TestVerifyInvalidOffBy1",   TestVerifyInvalidOffBy1);
        Run("TestVerifyInvalidZero",     TestVerifyInvalidZero);
        Run("TestTamperedShare",         TestTamperedShare);
        Run("TestValidationSecretZero",  TestValidationSecretZero);
        Run("TestValidationKTooLarge",   TestValidationKTooLarge);
        Run("TestValidationKOne",        TestValidationKOne);
        Run("TestCrossLanguageVector",   TestCrossLanguageVector);

        Console.WriteLine($"\n{_passed} passed, {_failed} failed");
        return _failed == 0 ? 0 : 1;
    }

    static void Run(string name, Action fn)
    {
        try
        {
            fn();
            Console.WriteLine($"  \u2713 {name}");
            _passed++;
        }
        catch (Exception e)
        {
            Console.WriteLine($"  \u2717 {name}: {e.Message}");
            _failed++;
        }
    }

    static void Check(bool condition, string message = "Assertion failed") =>
        _ = condition ? true : throw new Exception(message);

    // -----------------------------------------------------------------------

    static void Test2of3()
    {
        var secret = new BigInteger(1337);
        var shares = ThresholdKey.Generate(secret, 3, 2);
        Check(ThresholdKey.Reconstruct(shares[..2]) == secret, "first 2");
        Check(ThresholdKey.Reconstruct(shares[1..]) == secret, "last 2");
        Check(ThresholdKey.Reconstruct(new[] { shares[0], shares[2] }) == secret, "0+2");
    }

    static void Test3of5()
    {
        var secret = new BigInteger(99_999);
        var shares = ThresholdKey.Generate(secret, 5, 3);
        Check(ThresholdKey.Reconstruct(shares[..3]) == secret, "0-2");
        Check(ThresholdKey.Reconstruct(shares[1..4]) == secret, "1-3");
        Check(ThresholdKey.Reconstruct(shares[2..]) == secret, "2-4");
    }

    static void Test5of7()
    {
        var secret = new BigInteger(0xDEADBEEFCAFEL);
        var shares = ThresholdKey.Generate(secret, 7, 5);
        Check(ThresholdKey.Reconstruct(shares[..5]) == secret, "first 5");
        Check(ThresholdKey.Reconstruct(shares[2..]) == secret, "last 5");
    }

    static void TestLargeSecret()
    {
        var secret = P - 1;
        var shares = ThresholdKey.Generate(secret, 3, 2);
        Check(ThresholdKey.Reconstruct(shares[..2]) == secret, "P-1");
    }

    static void TestAllSubsetsAgree()
    {
        var secret = new BigInteger(9_876_543);
        var shares = ThresholdKey.Generate(secret, 7, 3);
        for (int i = 0; i <= 4; i++)
            Check(ThresholdKey.Reconstruct(shares[i..(i + 3)]) == secret, $"subset {i}");
    }

    static void TestExtraShares()
    {
        var secret = new BigInteger(42);
        var shares = ThresholdKey.Generate(secret, 5, 2);
        Check(ThresholdKey.Reconstruct(shares) == secret, "all 5 shares");
    }

    static void TestVerifyValid()
    {
        var shares = ThresholdKey.Generate(new BigInteger(12_345), 5, 3);
        for (int i = 0; i < shares.Length; i++)
        {
            var others = new List<Share>();
            for (int j = 0; j < shares.Length; j++) if (j != i) others.Add(shares[j]);
            // k=3 scheme: need at least 3 reference shares to define the degree-2 polynomial
            Check(ThresholdKey.Verify(shares[i].X, shares[i].Y, others.GetRange(0, 3)),
                  $"share {i + 1} should be valid");
        }
    }

    static void TestVerifyInvalidOffBy1()
    {
        var shares = ThresholdKey.Generate(new BigInteger(12_345), 5, 2);
        var s = shares[2];
        Check(!ThresholdKey.Verify(s.X, (s.Y + 1) % P, shares[..2]), "off-by-one should be invalid");
    }

    static void TestVerifyInvalidZero()
    {
        var shares = ThresholdKey.Generate(new BigInteger(777), 3, 2);
        Check(!ThresholdKey.Verify(shares[0].X, BigInteger.Zero, shares[1..]), "y=0 should be invalid");
    }

    static void TestTamperedShare()
    {
        var secret = new BigInteger(5_000);
        var shares = ThresholdKey.Generate(secret, 5, 3);
        Share[] tampered =
        {
            new Share(shares[0].X, (shares[0].Y + 1_000) % P),
            shares[1], shares[2]
        };
        Check(ThresholdKey.Reconstruct(tampered) != secret, "tampered should fail");
    }

    static void TestValidationSecretZero()
    {
        try
        {
            ThresholdKey.Generate(BigInteger.Zero, 3, 2);
            throw new Exception("Should have thrown");
        }
        catch (ArgumentException) { /* expected */ }
    }

    static void TestValidationKTooLarge()
    {
        try
        {
            ThresholdKey.Generate(BigInteger.One, 3, 5);
            throw new Exception("Should have thrown");
        }
        catch (ArgumentException) { /* expected */ }
    }

    static void TestValidationKOne()
    {
        try
        {
            ThresholdKey.Generate(BigInteger.One, 3, 1);
            throw new Exception("Should have thrown");
        }
        catch (ArgumentException) { /* expected */ }
    }

    static void TestCrossLanguageVector()
    {
        // Fixed polynomial: f(x) = 1337 + 42*x + 7*x^2  over GF(P)
        // Degree-2 polynomial => k=3: need all 3 shares to reconstruct f(0).
        // Must match Python, JavaScript, and Java exactly.
        Share[] shares =
        {
            new Share(1, 1386),
            new Share(2, 1449),
            new Share(3, 1526),
        };
        Check(ThresholdKey.Reconstruct(shares) == new BigInteger(1337), "all 3 shares");
    }
}
