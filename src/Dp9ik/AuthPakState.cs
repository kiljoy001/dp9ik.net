using Org.BouncyCastle.Security;

namespace Dp9ik;

/// <summary>
/// 9front's PAKpriv: the side, the secret scalar x and the public value y. authpak_new and
/// authpak_finish clear it after use.
/// </summary>
public sealed class AuthPakState
{
    private static readonly SecureRandom Random = new();
    private bool _isClient;
    private (byte[] Scalar, byte[] PublicValue)? _pending;

    /// <summary>authpak_new: y = decaf(x*G + PM) for a client, or + PN for a server.</summary>
    public byte[] CreatePublicValue(AuthKey key, bool isClient) => CreatePublicValue(key, isClient, AuthPakCurve.RandomScalar(Random));

    /// <summary>
    /// authpak_new from a chosen 56-byte big-endian scalar below p. The state takes ownership of
    /// <paramref name="scalar"/> and zeroes it when it finishes.
    /// </summary>
    internal byte[] CreatePublicValue(AuthKey key, bool isClient, byte[] scalar)
    {
        ArgumentNullException.ThrowIfNull(key);
        _isClient = isClient;
        byte[] publicValue = AuthPakCurve.PublicValue(scalar, Blinding(key, ownPoint: true));
        _pending = (scalar, publicValue);
        return publicValue.ToArray();
    }

    /// <summary>
    /// authpak_finish: z = decaf(x*(Y - peer point)); the PAK key is HKDF-SHA256 of z salted with
    /// SHA-256 of the client's then the server's public value. The state can finish only once.
    /// </summary>
    public void Finish(AuthKey key, ReadOnlySpan<byte> publicValue)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (publicValue.Length != Dp9ikConstants.PakPublicValueLength)
        {
            throw new ArgumentException("Invalid public value length.", nameof(publicValue));
        }

        (byte[] pendingScalar, byte[] own) = _pending ?? throw new InvalidOperationException("No AuthPAK public value has been created.");
        _pending = null;
        using var scalar = new SecretBytes(pendingScalar);
        using var z = new SecretBytes(AuthPakCurve.SharedValue(scalar.Bytes, publicValue, Blinding(key, ownPoint: false))
            ?? throw new InvalidOperationException("AuthPAK public value rejected."));
        byte[] peer = publicValue.ToArray();
        byte[] salt = Plan9Kdf.Sha256(_isClient ? own : peer, _isClient ? peer : own);
        key.SetSharedKey(Plan9Kdf.HkdfSha256(salt, "Plan 9 AuthPAK key", z.Bytes, Dp9ikConstants.PakKeyLength));
    }

    /// <summary>authpak_new uses PM for a client and PN for a server; authpak_finish removes the other.</summary>
    private AuthPakCurve.Point Blinding(AuthKey key, bool ownPoint)
    {
        bool useFirst = _isClient == ownPoint;
        return AuthPakCurve.Point.FromBigEndian(key.PakHashSpan.Slice(useFirst ? 0 : Dp9ikConstants.PakPointLength, Dp9ikConstants.PakPointLength));
    }
}
