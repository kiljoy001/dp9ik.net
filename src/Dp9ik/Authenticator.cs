namespace Dp9ik;

/// <summary>9front's Authenticator; marshalled as convA2M and convM2A define it.</summary>
public sealed class Authenticator
{
    private const int Form0Length = 1 + Dp9ikConstants.ChallengeLength + 4;
    private const int Form1Length = Dp9ikConstants.ChallengeLength + Dp9ikConstants.NonceLength + Form1.Overhead;

    /// <summary>Creates an empty authenticator of the given type.</summary>
    public Authenticator(AuthMessageType type)
    {
        Type = type;
        Challenge = FixedField.Create(Dp9ikConstants.ChallengeLength);
        Random = FixedField.Create(Dp9ikConstants.NonceLength);
    }

    /// <summary>Gets the message type, AuthAc or AuthAs.</summary>
    public AuthMessageType Type { get; private set; }

    /// <summary>Gets the 8-byte challenge.</summary>
    public byte[] Challenge { get; }

    /// <summary>Gets the 32-byte random nonce; form 1 only.</summary>
    public byte[] Random { get; }

    /// <summary>convA2M: form 0 is Plan 9 DES under the ticket's DES key, form 1 is form1 under the ticket key.</summary>
    public byte[] Marshal(Ticket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        if (ticket.Form == TicketEncryptionForm.Form0)
        {
            var plain = new byte[Form0Length];
            plain[0] = (byte)Type;
            Challenge.CopyTo(plain, 1);
            Plan9Des.Encrypt(ticket.SessionKey.AsSpan(0, Dp9ikConstants.DesKeyLength), plain);
            return plain;
        }

        return Form1.Seal(ToNativeLayout(), ticket.SessionKey);
    }

    /// <summary>Sets the 8-byte challenge.</summary>
    public void SetChallenge(ReadOnlySpan<byte> value) => FixedField.SetExact(value, Challenge);

    /// <summary>Sets the 32-byte random nonce.</summary>
    public void SetRandom(ReadOnlySpan<byte> value) => FixedField.SetExact(value, Random);

    /// <summary>convM2A: rejects a message that does not decrypt or is not an authenticator type.</summary>
    public static bool TryUnmarshal(Ticket ticket, ReadOnlySpan<byte> buffer, out Authenticator? authenticator, out int consumed)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        authenticator = null;
        consumed = 0;
        byte[]? plain;
        int length;
        if (ticket.Form == TicketEncryptionForm.Form0)
        {
            length = Form0Length;
            if (buffer.Length < length) return false;
            plain = buffer[..length].ToArray();
            Plan9Des.Decrypt(ticket.SessionKey.AsSpan(0, Dp9ikConstants.DesKeyLength), plain);
        }
        else
        {
            length = Form1Length;
            if (buffer.Length < length) return false;
            plain = Form1.Open(buffer[..length], ticket.SessionKey);
        }

        if (plain is null || !AuthMessageClassifier.IsKnownAuthenticatorType((AuthMessageType)plain[0])) return false;
        var result = new Authenticator((AuthMessageType)plain[0]);
        plain.AsSpan(1, Dp9ikConstants.ChallengeLength).CopyTo(result.Challenge);
        if (ticket.Form == TicketEncryptionForm.Form1)
            plain.AsSpan(1 + Dp9ikConstants.ChallengeLength, Dp9ikConstants.NonceLength).CopyTo(result.Random);
        authenticator = result;
        consumed = length;
        return true;
    }

    /// <summary>The native Authenticator struct: num, chal, rand[32].</summary>
    internal byte[] ToNativeLayout()
    {
        var bytes = new byte[Dp9ikConstants.AuthenticatorSize];
        bytes[0] = (byte)Type;
        Challenge.CopyTo(bytes, 1);
        Random.CopyTo(bytes, 1 + Dp9ikConstants.ChallengeLength);
        return bytes;
    }
}
