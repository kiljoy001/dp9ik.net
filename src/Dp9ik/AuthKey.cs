using System.Text;

namespace Dp9ik;

/// <summary>
/// 9front's Authkey in its native layout: DES key (7), AES key (16), PAK key (32) and the AuthPAK
/// hash (448, the PM and PN points).
/// </summary>
public sealed class AuthKey
{
    private const int AesOffset = Dp9ikConstants.DesKeyLength;
    private const int PakKeyOffset = AesOffset + Dp9ikConstants.AesKeyLength;
    private const int PakHashOffset = PakKeyOffset + Dp9ikConstants.PakKeyLength;
    private byte[] _raw;

    private AuthKey(byte[] raw) => _raw = raw;

    /// <summary>Gets the 16-byte AES key passtokey derives.</summary>
    public byte[] AesKey => Slice(AesOffset, Dp9ikConstants.AesKeyLength);

    /// <summary>Gets the 32-byte key the last finished AuthPAK exchange derived.</summary>
    public byte[] SharedKey => Slice(PakKeyOffset, Dp9ikConstants.PakKeyLength);

    /// <summary>Gets the 7-byte DES key passtokey derives.</summary>
    public byte[] DesKey => Slice(0, Dp9ikConstants.DesKeyLength);

    /// <summary>Gets the 448-byte AuthPAK hash: the PM and PN points <see cref="ApplyAuthPakHash"/> derives.</summary>
    public byte[] PakHash => Slice(PakHashOffset, Dp9ikConstants.PakHashLength);

    internal ReadOnlySpan<byte> PakHashSpan => _raw.AsSpan(PakHashOffset, Dp9ikConstants.PakHashLength);

    /// <summary>
    /// An Authkey from stored DES and AES keys, as keyfs holds them; apply
    /// <see cref="ApplyAuthPakHash"/> to derive its PAK hash for a user.
    /// </summary>
    public static AuthKey FromKeys(ReadOnlySpan<byte> desKey, ReadOnlySpan<byte> aesKey)
    {
        if (desKey.Length != Dp9ikConstants.DesKeyLength) throw new ArgumentException("A DES key is 7 bytes.", nameof(desKey));
        if (aesKey.Length != Dp9ikConstants.AesKeyLength) throw new ArgumentException("An AES key is 16 bytes.", nameof(aesKey));
        var raw = new byte[Dp9ikConstants.AuthKeySize];
        desKey.CopyTo(raw);
        aesKey.CopyTo(raw.AsSpan(AesOffset));
        return new AuthKey(raw);
    }

    /// <summary>passtokey: passtodeskey and passtoaeskey over the password's UTF-8 bytes.</summary>
    public static AuthKey FromPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var raw = new byte[Dp9ikConstants.AuthKeySize];
        byte[] bytes = Encoding.UTF8.GetBytes(password);
        PasswordToDesKey(bytes).CopyTo(raw, 0);
        Plan9Kdf.Pbkdf2Sha1(bytes, "Plan 9 key derivation", 9001, Dp9ikConstants.AesKeyLength).CopyTo(raw, AesOffset);
        return new AuthKey(raw);
    }

    /// <summary>authpak_hash: derives the PM and PN points from the AES key and the user name.</summary>
    public void ApplyAuthPakHash(string user)
    {
        ArgumentNullException.ThrowIfNull(user);
        byte[] salt = Plan9Kdf.Sha256(Encoding.UTF8.GetBytes(user));
        byte[] hash = Plan9Kdf.HkdfSha256(salt, "Plan 9 AuthPAK hash", AesKey, 2 * Dp9ikConstants.PakScalarLength);
        byte[] pm = AuthPakCurve.HashToPoint(hash.AsSpan(0, Dp9ikConstants.PakScalarLength)).ToBigEndian();
        byte[] pn = AuthPakCurve.HashToPoint(hash.AsSpan(Dp9ikConstants.PakScalarLength)).ToBigEndian();
        pm.CopyTo(_raw, PakHashOffset);
        pn.CopyTo(_raw, PakHashOffset + Dp9ikConstants.PakPointLength);
    }

    internal string RawHex => HexEncoding.ToHex(_raw);

    internal void Replace(byte[] raw)
    {
        if (raw.Length != Dp9ikConstants.AuthKeySize) throw new ArgumentException("An Authkey is 503 bytes.", nameof(raw));
        _raw = raw;
    }

    internal void SetSharedKey(ReadOnlySpan<byte> key) => key.CopyTo(_raw.AsSpan(PakKeyOffset, Dp9ikConstants.PakKeyLength));

    /// <summary>passtodeskey: the password, space-padded to 8, folded through DES 8 bytes at a time.</summary>
    private static byte[] PasswordToDesKey(byte[] password)
    {
        var buffer = new byte[Dp9ikConstants.PasswordLength];
        buffer.AsSpan(0, 8).Fill((byte)' ');
        int length = Math.Min(password.Length, buffer.Length - 1);
        password.AsSpan(0, length).CopyTo(buffer);
        buffer[length] = 0;
        var key = new byte[Dp9ikConstants.DesKeyLength];
        int t = 0;
        while (true)
        {
            for (int i = 0; i < Dp9ikConstants.DesKeyLength; i++)
                key[i] = (byte)((buffer[t + i] / (1 << i)) + (buffer[t + i + 1] << (8 - (i + 1))));
            if (t + 8 >= length) return key;
            // The next 8-byte group, or the last 8 bytes of the password when fewer than 8 remain.
            t = Math.Min(t + 8, length - 8);
            Plan9Des.Encrypt(key, buffer.AsSpan(t, 8));
        }
    }

    private byte[] Slice(int offset, int length) => _raw.AsSpan(offset, length).ToArray();
}
