using System.Security.Cryptography;
using System.Text;

namespace Dp9ik.P9Auth;

/// <summary>
/// The client side of p9any negotiating dp9ik, as drawterm's p9any (cpu.c) runs it without
/// factotum: the offer's dp9ik chosen, the client's challenge written, the tickets got from the auth
/// server for the server's ticket request, the server's ticket and the client's authenticator sent,
/// and the server's authenticator checked.
/// </summary>
public static class P9AuthClient
{
    // drawterm's buf, which holds the offer and OK.
    private const int StringLength = 1024;

    private const string Botch = "AS protocol botch";

    /// <summary>Authenticates to a server and returns the ticket's users and the session secret.</summary>
    public static async Task<P9AuthClientResult> AuthenticateAsync(Stream stream, P9AuthClientConfig config, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(config);
        config.Validate();

        string offer = await ReadStringAsync(stream, "cannot read p9any negotiation", cancellationToken);
        bool v2 = offer.StartsWith("v.2 ", StringComparison.Ordinal);
        string domain = Choose(v2 ? offer[4..] : offer);
        await CStringEncoding.WriteAsync(stream, $"dp9ik {domain}", cancellationToken);
        if (v2)
        {
            string ok = await ReadStringAsync(stream, "cannot read OK in p9any", cancellationToken);
            if (ok != "OK")
            {
                throw Fail($"did not get OK in p9any: got {ok}");
            }
        }

        byte[] clientRandom = RandomNumberGenerator.GetBytes(Dp9ikConstants.NonceLength);
        byte[] clientChallenge = RandomNumberGenerator.GetBytes(Dp9ikConstants.ChallengeLength);
        await stream.WriteAsync(clientChallenge, cancellationToken);

        byte[] offered = await ReadAsync(stream, Dp9ikConstants.TicketRequestLength + Dp9ikConstants.PakPublicValueLength, cancellationToken);
        if (offered.Length != Dp9ikConstants.TicketRequestLength + Dp9ikConstants.PakPublicValueLength
            || !TicketRequest.TryUnmarshal(offered, out TicketRequest? request, out _))
        {
            throw Fail("cannot read ticket request");
        }

        request!.SetHostId(config.User);
        request.SetUserId(config.User);
        (Ticket ticket, byte[] serverY, byte[] serverTicket) = await TicketsAsync(config, request, offered[Dp9ikConstants.TicketRequestLength..], cancellationToken);

        var authenticator = new Authenticator(AuthMessageType.AuthAc);
        authenticator.SetRandom(clientRandom);
        authenticator.SetChallenge(request.Challenge);
        byte[] proof = authenticator.Marshal(ticket);
        await stream.WriteAsync(serverY, cancellationToken);
        await stream.WriteAsync((byte[])[.. serverTicket, .. proof], cancellationToken);

        Authenticator reply = await ReadReplyAsync(stream, ticket, proof.Length, cancellationToken);
        if (reply.Type != AuthMessageType.AuthAs || !CryptographicOperations.FixedTimeEquals(reply.Challenge, clientChallenge))
        {
            throw Fail("server lies");
        }

        return new P9AuthClientResult(ticket.ClientUserText, ticket.ServerUserText, SessionSecret.Derive(clientRandom, reply.Random, ticket.SessionKey));
    }

    // The offer's dp9ik and its domain; each offer before it must have a domain.
    private static string Choose(string offer)
    {
        foreach (string entry in offer.Split(' '))
        {
            int at = entry.IndexOf('@', StringComparison.Ordinal);
            if (at < 0)
            {
                throw Fail("bad p9any domain");
            }

            if (entry[..at] == "dp9ik")
            {
                return entry[(at + 1)..];
            }
        }

        throw Fail("server did not offer dp9ik");
    }

    // The client's ticket, the auth server's value for the server and the server's ticket, the
    // password asked for again while the client's ticket does not open with it.
    private static async Task<(Ticket Ticket, byte[] ServerY, byte[] ServerTicket)> TicketsAsync(
        P9AuthClientConfig config, TicketRequest request, byte[] offeredY, CancellationToken cancellationToken)
    {
        for (bool mismatch = false; ; mismatch = true)
        {
            string password = await config.Password(new PasswordPrompt(config.User, request.AuthDomainText, mismatch), cancellationToken)
                ?? throw Fail("no password");
            AuthKey key = AuthKey.FromPassword(password);
            key.ApplyAuthPakHash(config.User);
            byte[] y = [.. offeredY];
            (byte[]? tickets, string? why) = await GetTicketsAsync(config, key, request, y, cancellationToken);
            if (tickets is null)
            {
                throw Fail($"cannot get auth tickets: {why}");
            }

            if (Ticket.TryUnmarshal(key, tickets, out Ticket? ticket, out int length) && ticket!.Type == AuthMessageType.AuthTc)
            {
                return (ticket, y, tickets[length..]);
            }
        }
    }

    // gettickets: the auth server's tickets, or, when it cannot give them, ones made up for the
    // server's own authid.
    private static async Task<(byte[]? Tickets, string? Why)> GetTicketsAsync(
        P9AuthClientConfig config, AuthKey key, TicketRequest request, byte[] y, CancellationToken cancellationToken)
    {
        (byte[]? tickets, string? why) = await GetAuthServerTicketsAsync(config, key, request, y, cancellationToken);
        return tickets is not null ? (tickets, null) : (MakeServerTickets(key, request, y), why);
    }

    // getastickets: AuthPAK with the server's value and the client's own, the server's value from
    // the auth server put in y, and then AuthTreq.
    private static async Task<(byte[]? Tickets, string? Why)> GetAuthServerTicketsAsync(
        P9AuthClientConfig config, AuthKey key, TicketRequest request, byte[] y, CancellationToken cancellationToken)
    {
        Stream call;
        try
        {
            call = await config.DialAuthServer(request.AuthDomainText, cancellationToken);
        }
        catch (IOException error)
        {
            return (null, error.Message);
        }

        await using Stream owned = call;
        try
        {
            await call.WriteAsync(Retyped(request, AuthMessageType.AuthPak), cancellationToken);
            await call.WriteAsync(y, cancellationToken);
            var state = new AuthPakState();
            await call.WriteAsync(state.CreatePublicValue(key, isClient: true), cancellationToken);
            (byte[]? values, string? why) = await ReadResponseAsync(call, 2 * Dp9ikConstants.PakPublicValueLength, cancellationToken);
            if (values is null)
            {
                return (null, why);
            }

            values.AsSpan(0, Dp9ikConstants.PakPublicValueLength).CopyTo(y);
            try
            {
                state.Finish(key, values.AsSpan(Dp9ikConstants.PakPublicValueLength));
            }
            catch (InvalidOperationException error)
            {
                return (null, error.Message);
            }

            return await GetTicketAsync(call, Retyped(request, AuthMessageType.AuthTreq), cancellationToken);
        }
        catch (IOException error)
        {
            return (null, error.Message);
        }
    }

    // mkservertickets: for the server's own authid, the tickets the auth server would give, under
    // the key from the user's password, and the value the auth server would send the server.
    private static byte[]? MakeServerTickets(AuthKey key, TicketRequest request, byte[] y)
    {
        if (request.AuthIdText != request.HostIdText)
        {
            return null;
        }

        var state = new AuthPakState();
        byte[] serverY = [.. y];
        state.CreatePublicValue(key, isClient: false).CopyTo(y, 0);
        state.Finish(key, serverY);
        byte[] sessionKey = RandomNumberGenerator.GetBytes(Dp9ikConstants.NonceLength);
        return [.. MakeTicket(AuthMessageType.AuthTc, request, sessionKey).Marshal(key), .. MakeTicket(AuthMessageType.AuthTs, request, sessionKey).Marshal(key)];
    }

    // mkservertickets' ticket, the uid's for the request's challenge.
    private static Ticket MakeTicket(AuthMessageType type, TicketRequest request, byte[] sessionKey)
    {
        var ticket = new Ticket(type, TicketEncryptionForm.Form1);
        ticket.SetChallenge(request.Challenge);
        ticket.SetClientUser(request.UserIdText);
        ticket.SetServerUser(request.UserIdText);
        ticket.SetSessionKey(sessionKey);
        return ticket;
    }

    // _asgetticket: the request, AuthOK, and two tickets read as convM2T measures them.
    private static async Task<(byte[]? Tickets, string? Why)> GetTicketAsync(Stream call, byte[] request, CancellationToken cancellationToken)
    {
        await call.WriteAsync(request, cancellationToken);
        (byte[]? ok, string? why) = await ReadResponseAsync(call, 0, cancellationToken);
        if (ok is null)
        {
            return (null, why);
        }

        // convM2T always asks for more than it has, and two tickets always fit drawterm's tbuf, so
        // _asgetticket's bounds on what it asks for are never met.
        var tickets = new List<byte>();
        for (int i = 0; i < 2; i++)
        {
            byte[] ticket = [];
            for (int m; ticket.Length < (m = Ticket.MessageLength(ticket));)
            {
                byte[] more = await ReadAsync(call, m - ticket.Length, cancellationToken);
                if (more.Length != m - ticket.Length)
                {
                    return (null, Botch);
                }

                ticket = [.. ticket, .. more];
            }

            tickets.AddRange(ticket);
        }

        return ([.. tickets], null);
    }

    // _asrdresp: length bytes after AuthOK, or as many as AuthOKvar says, no more than length; the
    // auth server's error after AuthErr.
    private static async Task<(byte[]? Response, string? Why)> ReadResponseAsync(Stream call, int length, CancellationToken cancellationToken)
    {
        byte[] status = await ReadAsync(call, 1, cancellationToken);
        if (status.Length != 1)
        {
            return (null, Botch);
        }

        switch ((AuthMessageType)status[0])
        {
            case AuthMessageType.AuthOk:
                byte[] response = await ReadAsync(call, length, cancellationToken);
                return response.Length == length ? (response, null) : (null, Botch);
            case AuthMessageType.AuthErr:
                byte[] error = await ReadAsync(call, 64, cancellationToken);
                if (error.Length != 64)
                {
                    return (null, Botch);
                }

                error[^1] = 0;
                return (null, $"remote: {Encoding.UTF8.GetString(error, 0, Array.IndexOf(error, (byte)0))}");
            case AuthMessageType.AuthOkVar:
                byte[] count = await ReadAsync(call, 5, cancellationToken);
                int n = Atoi(count);
                if (count.Length != 5 || n <= 0 || n > length)
                {
                    return (null, Botch);
                }

                byte[] some = await ReadAsync(call, n, cancellationToken);
                return some.Length == n ? ([.. some, .. new byte[length - n]], null) : (null, Botch);
            default:
                return (null, Botch);
        }
    }

    // The server's authenticator, or the error a server sends in its place, which starts "cpu:".
    private static async Task<Authenticator> ReadReplyAsync(Stream stream, Ticket ticket, int length, CancellationToken cancellationToken)
    {
        byte[] reply = await ReadAsync(stream, length, cancellationToken);
        if (reply.Length != length || reply.AsSpan().StartsWith("cpu:"u8))
        {
            if (reply.Length <= 4)
            {
                throw Fail("cannot read authenticator");
            }

            byte[] rest = await ReadAsync(stream, StringLength - reply.Length - 1, cancellationToken);
            throw Fail($"server says: {Encoding.UTF8.GetString([.. reply, .. rest])}");
        }

        return Authenticator.TryUnmarshal(ticket, reply, out Authenticator? authenticator, out _) ? authenticator! : throw Fail("server lies");
    }

    // atoi: leading blanks, a sign, and the digits that follow.
    private static int Atoi(byte[] text)
    {
        int i = 0;
        while (i < text.Length && (text[i] == ' ' || text[i] == '\t'))
        {
            i++;
        }

        bool negative = i < text.Length && text[i] == '-';
        if (i < text.Length && (text[i] == '-' || text[i] == '+'))
        {
            i++;
        }

        int n = 0;
        for (; i < text.Length && text[i] is >= (byte)'0' and <= (byte)'9'; i++)
        {
            n = (n * 10) + (text[i] - '0');
        }

        return negative ? -n : n;
    }

    private static byte[] Retyped(TicketRequest request, AuthMessageType type)
    {
        var retyped = new TicketRequest(type);
        retyped.SetAuthId(request.AuthIdText);
        retyped.SetAuthDomain(request.AuthDomainText);
        retyped.SetChallenge(request.Challenge);
        retyped.SetHostId(request.HostIdText);
        retyped.SetUserId(request.UserIdText);
        return retyped.Marshal();
    }

    // readstr: a string up to its NUL, of fewer than StringLength bytes.
    private static async Task<string> ReadStringAsync(Stream stream, string what, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>();
        while (bytes.Count < StringLength)
        {
            byte[] next = await ReadAsync(stream, 1, cancellationToken);
            if (next.Length == 0)
            {
                throw Fail($"{what}: hung up");
            }

            if (next[0] == 0)
            {
                return Encoding.UTF8.GetString([.. bytes]);
            }

            bytes.Add(next[0]);
        }

        throw Fail($"{what}: too long");
    }

    // readn: as many as length bytes, fewer only at the end of the stream.
    private static async Task<byte[]> ReadAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[length];
        int read = await stream.ReadAtLeastAsync(buffer, length, throwOnEndOfStream: false, cancellationToken);
        return buffer[..read];
    }

    private static InvalidOperationException Fail(string message) => new(message);
}
