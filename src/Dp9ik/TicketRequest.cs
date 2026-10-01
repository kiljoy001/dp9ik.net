namespace Dp9ik;

public sealed class TicketRequest
{
    public TicketRequest(AuthMessageType type)
    {
        Type = type;
        AuthId = FixedField.Create(Dp9ikConstants.NameLength);
        AuthDomain = FixedField.Create(Dp9ikConstants.DomainLength);
        Challenge = FixedField.Create(Dp9ikConstants.ChallengeLength);
        HostId = FixedField.Create(Dp9ikConstants.NameLength);
        UserId = FixedField.Create(Dp9ikConstants.NameLength);
    }

    public AuthMessageType Type { get; }

    public byte[] AuthId { get; }

    public byte[] AuthDomain { get; }

    public byte[] Challenge { get; }

    public byte[] HostId { get; }

    public byte[] UserId { get; }

    public string AuthIdText => FixedField.ReadText(AuthId);

    public string AuthDomainText => FixedField.ReadText(AuthDomain);

    public string HostIdText => FixedField.ReadText(HostId);

    public string UserIdText => FixedField.ReadText(UserId);

    public byte[] Marshal()
    {
        var buffer = new byte[Dp9ikConstants.TicketRequestLength];
        buffer[0] = (byte)Type;
        AuthId.CopyTo(buffer, 1);
        AuthDomain.CopyTo(buffer, 1 + Dp9ikConstants.NameLength);
        Challenge.CopyTo(buffer, 1 + Dp9ikConstants.NameLength + Dp9ikConstants.DomainLength);
        HostId.CopyTo(buffer, 1 + Dp9ikConstants.NameLength + Dp9ikConstants.DomainLength + Dp9ikConstants.ChallengeLength);
        UserId.CopyTo(buffer, 1 + (2 * Dp9ikConstants.NameLength) + Dp9ikConstants.DomainLength + Dp9ikConstants.ChallengeLength);
        return buffer;
    }

    public void SetAuthId(string value) => FixedField.SetText(value, AuthId);

    public void SetAuthDomain(string value) => FixedField.SetText(value, AuthDomain);

    public void SetChallenge(ReadOnlySpan<byte> value) => FixedField.SetExact(value, Challenge);

    public void SetHostId(string value) => FixedField.SetText(value, HostId);

    public void SetUserId(string value) => FixedField.SetText(value, UserId);

    public static bool TryUnmarshal(ReadOnlySpan<byte> buffer, out TicketRequest? request, out int consumed)
    {
        if (buffer.Length < Dp9ikConstants.TicketRequestLength)
        {
            request = null;
            consumed = 0;
            return false;
        }

        request = new TicketRequest((AuthMessageType)buffer[0]);
        buffer.Slice(1, Dp9ikConstants.NameLength).CopyTo(request.AuthId);
        buffer.Slice(1 + Dp9ikConstants.NameLength, Dp9ikConstants.DomainLength).CopyTo(request.AuthDomain);
        buffer.Slice(1 + Dp9ikConstants.NameLength + Dp9ikConstants.DomainLength, Dp9ikConstants.ChallengeLength).CopyTo(request.Challenge);
        buffer.Slice(1 + Dp9ikConstants.NameLength + Dp9ikConstants.DomainLength + Dp9ikConstants.ChallengeLength, Dp9ikConstants.NameLength).CopyTo(request.HostId);
        buffer.Slice(1 + (2 * Dp9ikConstants.NameLength) + Dp9ikConstants.DomainLength + Dp9ikConstants.ChallengeLength, Dp9ikConstants.NameLength).CopyTo(request.UserId);
        // convM2TR terminates every text field.
        FixedField.Terminate(request.AuthId);
        FixedField.Terminate(request.AuthDomain);
        FixedField.Terminate(request.HostId);
        FixedField.Terminate(request.UserId);
        consumed = Dp9ikConstants.TicketRequestLength;
        return true;
    }
}
