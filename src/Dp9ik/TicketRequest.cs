namespace Dp9ik;

/// <summary>9front's Ticketreq, marshalled as convTR2M and convM2TR define it.</summary>
public sealed class TicketRequest
{
    /// <summary>Creates an empty ticket request of the given type.</summary>
    public TicketRequest(AuthMessageType type)
    {
        Type = type;
        AuthId = FixedField.Create(Dp9ikConstants.NameLength);
        AuthDomain = FixedField.Create(Dp9ikConstants.DomainLength);
        Challenge = FixedField.Create(Dp9ikConstants.ChallengeLength);
        HostId = FixedField.Create(Dp9ikConstants.NameLength);
        UserId = FixedField.Create(Dp9ikConstants.NameLength);
    }

    /// <summary>Gets the request type.</summary>
    public AuthMessageType Type { get; }

    /// <summary>Gets the NUL-terminated field naming the server's authentication identity.</summary>
    public byte[] AuthId { get; }

    /// <summary>Gets the NUL-terminated authentication domain field.</summary>
    public byte[] AuthDomain { get; }

    /// <summary>Gets the 8-byte server challenge.</summary>
    public byte[] Challenge { get; }

    /// <summary>Gets the NUL-terminated field naming the user requesting the ticket.</summary>
    public byte[] HostId { get; }

    /// <summary>Gets the NUL-terminated field naming the user the ticket is for.</summary>
    public byte[] UserId { get; }

    /// <summary>Gets the authentication identity as text.</summary>
    public string AuthIdText => FixedField.ReadText(AuthId);

    /// <summary>Gets the authentication domain as text.</summary>
    public string AuthDomainText => FixedField.ReadText(AuthDomain);

    /// <summary>Gets the host identity as text.</summary>
    public string HostIdText => FixedField.ReadText(HostId);

    /// <summary>Gets the user identity as text.</summary>
    public string UserIdText => FixedField.ReadText(UserId);

    /// <summary>convTR2M: the 141-byte wire form.</summary>
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

    /// <summary>Sets the authentication identity. Holds at most 27 bytes of UTF-8; longer names are refused.</summary>
    public void SetAuthId(string value) => FixedField.SetText(value, AuthId);

    /// <summary>Sets the authentication domain. Holds at most 47 bytes of UTF-8; longer domains are refused.</summary>
    public void SetAuthDomain(string value) => FixedField.SetText(value, AuthDomain);

    /// <summary>Sets the 8-byte challenge.</summary>
    public void SetChallenge(ReadOnlySpan<byte> value) => FixedField.SetExact(value, Challenge);

    /// <summary>Sets the host identity. Holds at most 27 bytes of UTF-8; longer names are refused.</summary>
    public void SetHostId(string value) => FixedField.SetText(value, HostId);

    /// <summary>Sets the user identity. Holds at most 27 bytes of UTF-8; longer names are refused.</summary>
    public void SetUserId(string value) => FixedField.SetText(value, UserId);

    /// <summary>convM2TR: reads a ticket request, terminating its text fields; false when the buffer is too short.</summary>
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
