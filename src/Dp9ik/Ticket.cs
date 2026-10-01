namespace Dp9ik;

/// <summary>9front's Ticket; marshalled as convT2M and convM2T define it.</summary>
public sealed class Ticket
{
    private const int Form0Length = 1 + Dp9ikConstants.ChallengeLength + (2 * Dp9ikConstants.NameLength) + Dp9ikConstants.DesKeyLength;
    private const int Form1PlainLength = 1 + Dp9ikConstants.ChallengeLength + (2 * Dp9ikConstants.NameLength) + Dp9ikConstants.NonceLength;

    public Ticket(AuthMessageType type, TicketEncryptionForm form)
    {
        Type = type;
        Form = form;
        Challenge = FixedField.Create(Dp9ikConstants.ChallengeLength);
        ClientUser = FixedField.Create(Dp9ikConstants.NameLength);
        ServerUser = FixedField.Create(Dp9ikConstants.NameLength);
        SessionKey = FixedField.Create(Dp9ikConstants.NonceLength);
    }

    public AuthMessageType Type { get; private set; }

    public TicketEncryptionForm Form { get; private set; }

    public byte[] Challenge { get; }

    public byte[] ClientUser { get; }

    public byte[] ServerUser { get; }

    public byte[] SessionKey { get; }

    public string ClientUserText => FixedField.ReadText(ClientUser);

    public string ServerUserText => FixedField.ReadText(ServerUser);

    /// <summary>convT2M: form 0 is Plan 9 DES under the DES key, form 1 is form1 under the PAK key.</summary>
    public byte[] Marshal(AuthKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        byte[] plain = Plain();
        if (Form == TicketEncryptionForm.Form0)
        {
            Plan9Des.Encrypt(key.DesKey, plain);
            return plain;
        }

        return Form1.Seal(plain, key.SharedKey);
    }

    public void SetChallenge(ReadOnlySpan<byte> value) => FixedField.SetExact(value, Challenge);

    public void SetClientUser(string value) => FixedField.SetText(value, ClientUser);

    public void SetServerUser(string value) => FixedField.SetText(value, ServerUser);

    public void SetSessionKey(ReadOnlySpan<byte> value) => FixedField.SetExact(value, SessionKey);

    /// <summary>
    /// convM2T: a buffer without a form1 signature is a form 0 ticket. A message that does not
    /// decrypt, or is not a ticket type, is rejected.
    /// </summary>
    public static bool TryUnmarshal(AuthKey key, ReadOnlySpan<byte> buffer, out Ticket? ticket, out int consumed)
    {
        ArgumentNullException.ThrowIfNull(key);
        ticket = null;
        consumed = 0;
        byte[]? plain;
        TicketEncryptionForm form;
        int length;
        if (Form1.Check(buffer) is null)
        {
            length = Form0Length;
            if (buffer.Length < length) return false;
            plain = buffer[..length].ToArray();
            Plan9Des.Decrypt(key.DesKey, plain);
            form = TicketEncryptionForm.Form0;
        }
        else
        {
            length = Form1PlainLength - 1 + Form1.Overhead;
            if (buffer.Length < length) return false;
            plain = Form1.Open(buffer[..length], key.SharedKey);
            form = TicketEncryptionForm.Form1;
        }

        if (plain is null || !AuthMessageClassifier.IsKnownTicketType((AuthMessageType)plain[0])) return false;
        ticket = FromPlain(plain, form);
        consumed = length;
        return true;
    }

    /// <summary>The native Ticket struct: num, chal, cuid, suid, key[32], form.</summary>
    internal byte[] ToNativeLayout()
    {
        var bytes = new byte[Dp9ikConstants.TicketSize];
        bytes[0] = (byte)Type;
        Challenge.CopyTo(bytes, 1);
        ClientUser.CopyTo(bytes, 1 + Dp9ikConstants.ChallengeLength);
        ServerUser.CopyTo(bytes, 1 + Dp9ikConstants.ChallengeLength + Dp9ikConstants.NameLength);
        SessionKey.CopyTo(bytes, 1 + Dp9ikConstants.ChallengeLength + (2 * Dp9ikConstants.NameLength));
        bytes[^1] = (byte)Form;
        return bytes;
    }

    private byte[] Plain()
    {
        int keyLength = Form == TicketEncryptionForm.Form0 ? Dp9ikConstants.DesKeyLength : Dp9ikConstants.NonceLength;
        return ToNativeLayout().AsSpan(0, 1 + Dp9ikConstants.ChallengeLength + (2 * Dp9ikConstants.NameLength) + keyLength).ToArray();
    }

    private static Ticket FromPlain(byte[] plain, TicketEncryptionForm form)
    {
        var ticket = new Ticket((AuthMessageType)plain[0], form);
        int offset = 1;
        plain.AsSpan(offset, Dp9ikConstants.ChallengeLength).CopyTo(ticket.Challenge);
        offset += Dp9ikConstants.ChallengeLength;
        plain.AsSpan(offset, Dp9ikConstants.NameLength).CopyTo(ticket.ClientUser);
        offset += Dp9ikConstants.NameLength;
        plain.AsSpan(offset, Dp9ikConstants.NameLength).CopyTo(ticket.ServerUser);
        offset += Dp9ikConstants.NameLength;
        plain.AsSpan(offset, plain.Length - offset).CopyTo(ticket.SessionKey);
        // convM2T terminates both names.
        FixedField.Terminate(ticket.ClientUser);
        FixedField.Terminate(ticket.ServerUser);
        return ticket;
    }
}
