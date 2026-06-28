"""Unit tests for python/qvault_threshold.py — run with:  python test_shamir.py"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from qvault_threshold import generate, reconstruct, verify, P

_passed = 0
_failed = 0

def _run(name, fn):
    global _passed, _failed
    try:
        fn()
        print(f"  [PASS] {name}")
        _passed += 1
    except Exception as e:
        print(f"  [FAIL] {name}: {e}")
        _failed += 1


# ---------------------------------------------------------------------------

def test_2of3():
    s = 1337
    sh = generate(s, n=3, k=2)
    assert reconstruct(sh[:2]) == s
    assert reconstruct(sh[1:])  == s
    assert reconstruct([sh[0], sh[2]]) == s

def test_3of5():
    s = 99_999
    sh = generate(s, n=5, k=3)
    assert reconstruct(sh[:3])  == s
    assert reconstruct(sh[1:4]) == s
    assert reconstruct(sh[2:])  == s

def test_5of7():
    s = 0xDEADBEEFCAFE
    sh = generate(s, n=7, k=5)
    assert reconstruct(sh[:5]) == s
    assert reconstruct(sh[2:]) == s

def test_large_secret():
    s = P - 1  # Maximum valid secret (256-bit)
    sh = generate(s, n=3, k=2)
    assert reconstruct(sh[:2]) == s

def test_all_subsets_agree():
    s = 9_876_543
    sh = generate(s, n=7, k=3)
    for i in range(5):
        assert reconstruct(sh[i:i+3]) == s, f"Subset {i} failed"

def test_extra_shares_still_work():
    s = 42
    sh = generate(s, n=5, k=2)
    assert reconstruct(sh) == s  # Using all 5 shares still gives 42

def test_verify_valid():
    # k=3 scheme: need at least 3 reference shares to define the polynomial
    sh = generate(12_345, n=5, k=3)
    for i in range(len(sh)):
        others = [s for j, s in enumerate(sh) if j != i][:3]
        assert verify(sh[i][0], sh[i][1], others), f"Share {i+1} should be valid"

def test_verify_invalid_off_by_one():
    sh = generate(12_345, n=5, k=2)
    x, y = sh[2]
    assert not verify(x, (y + 1) % P, sh[:2])

def test_verify_invalid_zero():
    sh = generate(777, n=3, k=2)
    assert not verify(sh[0][0], 0, [sh[1], sh[2]])

def test_tampered_share_wrong_key():
    s = 5_000
    sh = generate(s, n=5, k=3)
    tampered = [(sh[0][0], (sh[0][1] + 1_000) % P)] + sh[1:3]
    assert reconstruct(tampered) != s

def test_input_validation_secret_zero():
    try:
        generate(0, 3, 2)
        assert False, "Should raise"
    except ValueError:
        pass

def test_input_validation_k_too_large():
    try:
        generate(1, 3, 5)
        assert False, "Should raise"
    except ValueError:
        pass

def test_input_validation_k_one():
    try:
        generate(1, 3, 1)
        assert False, "Should raise"
    except ValueError:
        pass

def test_cross_language_vector():
    # Fixed polynomial: f(x) = 1337 + 42*x + 7*x^2  over GF(P)
    # Degree-2 polynomial => k=3: need all 3 shares to reconstruct f(0).
    # These exact values must be reproduced by the JavaScript, Java, and C# implementations.
    coeffs = [1337, 42, 7]
    from qvault_threshold import _eval
    y1 = _eval(coeffs, 1)   # 1337 + 42  + 7   = 1386
    y2 = _eval(coeffs, 2)   # 1337 + 84  + 28  = 1449
    y3 = _eval(coeffs, 3)   # 1337 + 126 + 63  = 1526
    assert y1 == 1386
    assert y2 == 1449
    assert y3 == 1526
    shares = [(1, y1), (2, y2), (3, y3)]
    assert reconstruct(shares) == 1337  # all 3 shares reconstruct the secret

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    for name, fn in tests:
        _run(name, fn)
    print(f"\n{_passed} passed, {_failed} failed")
    sys.exit(0 if _failed == 0 else 1)
