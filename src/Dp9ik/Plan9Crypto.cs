using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Dp9ik;

/// <summary>Plan 9 DES as libc crypt.c and libsec des.c define it, with 7-byte keys.</summary>
internal static class Plan9Des
{
    /// <summary>libc encrypt: DES over 8-byte windows advancing 7 bytes, the last window ending at n.</summary>
    internal static void Encrypt(ReadOnlySpan<byte> key, Span<byte> buffer) => Apply(key, buffer, encrypting: true);

    /// <summary>libc decrypt: the inverse of <see cref="Encrypt"/>.</summary>
    internal static void Decrypt(ReadOnlySpan<byte> key, Span<byte> buffer) => Apply(key, buffer, encrypting: false);

    /// <summary>
    /// des56to64: each output byte carries the next 7 key bits above a parity bit. DES ignores the
    /// parity bits the 9front table adds, so they are left clear.
    /// </summary>
    internal static byte[] Expand(ReadOnlySpan<byte> key56)
    {
        ulong bits = BinaryPrimitives.ReadUInt64BigEndian([.. key56, 0]);
        return Enumerable.Range(0, 8).Select(index => (byte)(bits / (1UL << (57 - (7 * index))) % 128 * 2)).ToArray();
    }

    private static void Apply(ReadOnlySpan<byte> key, Span<byte> buffer, bool encrypting)
    {
        if (buffer.Length < 8) throw new ArgumentException("Plan 9 DES needs at least 8 bytes.", nameof(buffer));
        var engine = new DesEngine();
        engine.Init(encrypting, new KeyParameter(Expand(key)));
        int steps = (buffer.Length - 1) / 7;
        int remainder = (buffer.Length - 1) % 7;
        var offsets = Enumerable.Range(0, steps).Select(step => step * 7).ToList();
        if (remainder != 0) offsets.Add((steps * 7) - 7 + remainder);
        if (!encrypting) offsets.Reverse();
        var block = new byte[8];
        foreach (int offset in offsets)
        {
            buffer.Slice(offset, 8).CopyTo(block);
            engine.ProcessBlock(block, 0, block, 0);
            block.CopyTo(buffer.Slice(offset, 8));
        }
    }
}

/// <summary>The key derivations of 9front passtokey.c, authpak.c and factotum p9sk1.c.</summary>
internal static class Plan9Kdf
{
    internal static byte[] Pbkdf2Sha1(ReadOnlySpan<byte> password, string salt, int iterations, int length)
    {
        var generator = new Pkcs5S2ParametersGenerator(new Sha1Digest());
        generator.Init(password.ToArray(), Encoding.ASCII.GetBytes(salt), iterations);
        return ((KeyParameter)generator.GenerateDerivedMacParameters(length * 8)).GetKey();
    }

    /// <summary>hkdf_x with hmac_sha2_256.</summary>
    internal static byte[] HkdfSha256(ReadOnlySpan<byte> salt, string info, ReadOnlySpan<byte> key, int length)
    {
        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(key.ToArray(), salt.ToArray(), Encoding.ASCII.GetBytes(info)));
        var output = new byte[length];
        hkdf.GenerateBytes(output, 0, length);
        return output;
    }

    internal static byte[] Sha256(params byte[][] parts)
    {
        var digest = new Sha256Digest();
        foreach (byte[] part in parts) digest.BlockUpdate(part, 0, part.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }
}

/// <summary>
/// 9front form1.c: a message's type byte is replaced by an 8-byte signature and a 4-byte
/// little-endian counter forming the ChaCha20-Poly1305 nonce, with a 16-byte tag appended.
/// </summary>
internal static class Form1
{
    internal const int Overhead = 12 + 16;
    private static readonly (AuthMessageType Type, byte[] Signature)[] Signatures =
    [
        (AuthMessageType.AuthPass, "form1 PR"u8.ToArray()),
        (AuthMessageType.AuthTs, "form1 Ts"u8.ToArray()),
        (AuthMessageType.AuthTc, "form1 Tc"u8.ToArray()),
        (AuthMessageType.AuthAs, "form1 As"u8.ToArray()),
        (AuthMessageType.AuthAc, "form1 Ac"u8.ToArray()),
        (AuthMessageType.AuthTp, "form1 Tp"u8.ToArray()),
        (AuthMessageType.AuthHr, "form1 Hr"u8.ToArray()),
    ];

    private static int counter;

    /// <summary>form1check: the message type for a known signature, or null.</summary>
    internal static AuthMessageType? Check(ReadOnlySpan<byte> message)
    {
        if (message.Length < 8) return null;
        foreach ((AuthMessageType type, byte[] signature) in Signatures)
            if (message[..8].SequenceEqual(signature)) return type;
        return null;
    }

    /// <summary>form1B2M: seals a message whose first byte is its type.</summary>
    internal static byte[] Seal(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        var type = (AuthMessageType)message[0];
        byte[] signature = Signatures.FirstOrDefault(entry => entry.Type == type).Signature
            ?? throw new ArgumentException($"Message type {type} has no form1 signature.", nameof(message));
        var nonce = new byte[12];
        signature.CopyTo(nonce, 0);
        // 9front's counter only has to be unique per process and key; it is not part of the wire contract.
        BinaryPrimitives.WriteUInt32LittleEndian(nonce.AsSpan(8), (uint)Interlocked.Increment(ref counter));
        var cipher = new ChaCha20Poly1305();
        cipher.Init(true, new AeadParameters(new KeyParameter(key.ToArray()), 128, nonce));
        var output = new byte[12 + cipher.GetOutputSize(message.Length - 1)];
        nonce.CopyTo(output, 0);
        int written = cipher.ProcessBytes(message[1..].ToArray(), 0, message.Length - 1, output, 12);
        cipher.DoFinal(output, 12 + written);
        return output;
    }

    /// <summary>form1M2B: opens a sealed message, or returns null when it is not authentic.</summary>
    internal static byte[]? Open(ReadOnlySpan<byte> sealedMessage, ReadOnlySpan<byte> key)
    {
        if (Check(sealedMessage) is not AuthMessageType type || sealedMessage.Length <= Overhead) return null;
        var cipher = new ChaCha20Poly1305();
        cipher.Init(false, new AeadParameters(new KeyParameter(key.ToArray()), 128, sealedMessage[..12].ToArray()));
        byte[] body = sealedMessage[12..].ToArray();
        var plain = new byte[1 + cipher.GetOutputSize(body.Length)];
        try
        {
            int written = cipher.ProcessBytes(body, 0, body.Length, plain, 1);
            cipher.DoFinal(plain, 1 + written);
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
        {
            return null;
        }

        plain[0] = (byte)type;
        return plain;
    }
}

/// <summary>The dp9ik session secret that factotum hands to tlsclient and tlssrv as their PSK.</summary>
public static class SessionSecret
{
    /// <summary>The secret length, ai->nsecret.</summary>
    public const int Length = 256;

    /// <summary>
    /// HKDF-SHA256 with the client and server nonces as salt, info "Plan 9 session secret" and the
    /// ticket key as input, as factotum p9sk1.c establish() derives it for dp9ik.
    /// </summary>
    public static byte[] Derive(ReadOnlySpan<byte> clientRandom, ReadOnlySpan<byte> serverRandom, ReadOnlySpan<byte> ticketKey)
    {
        if (clientRandom.Length != Dp9ikConstants.NonceLength || serverRandom.Length != Dp9ikConstants.NonceLength)
            throw new ArgumentException("Each nonce is 32 bytes.");
        if (ticketKey.Length != Dp9ikConstants.NonceLength) throw new ArgumentException("The ticket key is 32 bytes.", nameof(ticketKey));
        return Plan9Kdf.HkdfSha256([.. clientRandom, .. serverRandom], "Plan 9 session secret", ticketKey, Length);
    }
}
