namespace QVault.Threshold;

using System.Numerics;

/// <summary>
/// An (X, Y) share point on the secret polynomial f(X) over GF(P).
///
/// <para>The <c>X</c> coordinate is the share index (1-indexed, public).
/// The <c>Y</c> coordinate is the secret share value (must be kept private).</para>
/// </summary>
public readonly record struct Share(BigInteger X, BigInteger Y);
