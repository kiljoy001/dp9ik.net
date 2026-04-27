namespace Dp9ik;

public sealed class Ticket
{
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

    public byte[] Marshal(AuthKey key) => HexEncoding.FromHex(NativeTool.Execute("ticket_marshal", key.RawHex, HexEncoding.ToHex(ToNativeBytes()))[0]);

    public void SetChallenge(ReadOnlySpan<byte> value) => FixedField.SetExact(value, Challenge);

    public void SetClientUser(string value) => FixedField.SetText(value, ClientUser);

    public void SetServerUser(string value) => FixedField.SetText(value, ServerUser);

    public void SetSessionKey(ReadOnlySpan<byte> value) => FixedField.SetExact(value, SessionKey);

    public static bool TryUnmarshal(AuthKey key, ReadOnlySpan<byte> buffer, out Ticket? ticket, out int consumed)
    {
        var lines = NativeTool.Execute("ticket_unmarshal", key.RawHex, HexEncoding.ToHex(buffer));
        if (lines[0] == "0")
        {
            ticket = null;
            consumed = 0;
            return false;
        }

        consumed = int.Parse(lines[0], System.Globalization.CultureInfo.InvariantCulture);
        ticket = FromNativeBytes(HexEncoding.FromHex(lines[1]));
        if (!IsKnownTicketType(ticket.Type))
        {
            ticket = null;
            consumed = 0;
            return false;
        }

        return true;
    }

    private static Ticket FromNativeBytes(byte[] bytes)
    {
        var ticket = new Ticket((AuthMessageType)bytes[0], (TicketEncryptionForm)bytes[^1]);
        bytes.AsSpan(1, Dp9ikConstants.ChallengeLength).CopyTo(ticket.Challenge);
        bytes.AsSpan(1 + Dp9ikConstants.ChallengeLength, Dp9ikConstants.NameLength).CopyTo(ticket.ClientUser);
        bytes.AsSpan(1 + Dp9ikConstants.ChallengeLength + Dp9ikConstants.NameLength, Dp9ikConstants.NameLength).CopyTo(ticket.ServerUser);
        bytes.AsSpan(1 + Dp9ikConstants.ChallengeLength + (2 * Dp9ikConstants.NameLength), Dp9ikConstants.NonceLength).CopyTo(ticket.SessionKey);
        return ticket;
    }

    private byte[] ToNativeBytes()
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

    private static bool IsKnownTicketType(AuthMessageType type) => type is AuthMessageType.AuthTs or AuthMessageType.AuthTc or AuthMessageType.AuthTp;
}
