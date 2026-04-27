namespace Dp9ik;

public sealed class Authenticator
{
    public Authenticator(AuthMessageType type)
    {
        Type = type;
        Challenge = FixedField.Create(Dp9ikConstants.ChallengeLength);
        Random = FixedField.Create(Dp9ikConstants.NonceLength);
    }

    public AuthMessageType Type { get; private set; }

    public byte[] Challenge { get; }

    public byte[] Random { get; }

    public byte[] Marshal(Ticket ticket) => HexEncoding.FromHex(NativeTool.Execute("authenticator_marshal", HexEncoding.ToHex(ticketToBytes(ticket)), HexEncoding.ToHex(ToNativeBytes()))[0]);

    public void SetChallenge(ReadOnlySpan<byte> value) => FixedField.SetExact(value, Challenge);

    public void SetRandom(ReadOnlySpan<byte> value) => FixedField.SetExact(value, Random);

    public static bool TryUnmarshal(Ticket ticket, ReadOnlySpan<byte> buffer, out Authenticator? authenticator, out int consumed)
    {
        var lines = NativeTool.Execute("authenticator_unmarshal", HexEncoding.ToHex(ticketToBytes(ticket)), HexEncoding.ToHex(buffer));
        if (lines[0] == "0")
        {
            authenticator = null;
            consumed = 0;
            return false;
        }

        consumed = int.Parse(lines[0], System.Globalization.CultureInfo.InvariantCulture);
        authenticator = FromNativeBytes(HexEncoding.FromHex(lines[1]));
        if (!IsKnownAuthenticatorType(authenticator.Type))
        {
            authenticator = null;
            consumed = 0;
            return false;
        }

        return true;
    }

    private static Authenticator FromNativeBytes(byte[] bytes)
    {
        var authenticator = new Authenticator((AuthMessageType)bytes[0]);
        bytes.AsSpan(1, Dp9ikConstants.ChallengeLength).CopyTo(authenticator.Challenge);
        bytes.AsSpan(1 + Dp9ikConstants.ChallengeLength, Dp9ikConstants.NonceLength).CopyTo(authenticator.Random);
        return authenticator;
    }

    private byte[] ToNativeBytes()
    {
        var bytes = new byte[Dp9ikConstants.AuthenticatorSize];
        bytes[0] = (byte)Type;
        Challenge.CopyTo(bytes, 1);
        Random.CopyTo(bytes, 1 + Dp9ikConstants.ChallengeLength);
        return bytes;
    }

    private static byte[] ticketToBytes(Ticket ticket)
    {
        var bytes = new byte[Dp9ikConstants.TicketSize];
        bytes[0] = (byte)ticket.Type;
        ticket.Challenge.CopyTo(bytes, 1);
        ticket.ClientUser.CopyTo(bytes, 1 + Dp9ikConstants.ChallengeLength);
        ticket.ServerUser.CopyTo(bytes, 1 + Dp9ikConstants.ChallengeLength + Dp9ikConstants.NameLength);
        ticket.SessionKey.CopyTo(bytes, 1 + Dp9ikConstants.ChallengeLength + (2 * Dp9ikConstants.NameLength));
        bytes[^1] = (byte)ticket.Form;
        return bytes;
    }

    private static bool IsKnownAuthenticatorType(AuthMessageType type) => type is AuthMessageType.AuthAs or AuthMessageType.AuthAc;
}
