using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Dp9ik.P9Auth;

namespace Dp9ik.Tests.Support;

/// <summary>
/// 9front authsrv's AuthPAK and AuthTreq (cmd/auth/authsrv.c: pak, pak1, ticketrequest, mkticket)
/// for the users it is given, on loopback calls the client dials. A user it does not know gets a
/// key made up, as authsrv's mkkey makes one, so a wrong password is told only by the ticket.
/// </summary>
internal sealed class TestAuthServer(IReadOnlyDictionary<string, string> passwords)
{
    private readonly List<Task> calls = [];

    /// <summary>The requests read, in order, over every call.</summary>
    internal List<TicketRequest> Requests { get; } = [];

    /// <summary>The domains the client dialled.</summary>
    internal List<string> Dialled { get; } = [];

    /// <summary>When set, AuthTreq is answered with AuthErr and this error, as replyerror answers it.</summary>
    internal string? Refusal { get; set; }

    /// <summary>When set, the call is hung up once AuthTreq is read, before its answer.</summary>
    internal bool HangUpOnTicketRequest { get; set; }

    /// <summary>When set, the call is hung up halfway through the AuthPAK values.</summary>
    internal bool HangUpInPak { get; set; }

    /// <summary>When set, the call is hung up halfway through the second ticket.</summary>
    internal bool HangUpInTickets { get; set; }

    /// <summary>When set, AuthPAK is answered with AuthOKvar, this count, and as many bytes of the values as OkVarSent.</summary>
    internal string? OkVarCount { get; set; }

    /// <summary>How many bytes of the values follow OkVarCount; the call is hung up after fewer than the count says.</summary>
    internal int OkVarSent { get; set; }

    /// <summary>When set, a dial fails as a refused connection does.</summary>
    internal bool Undialable { get; set; }

    internal async ValueTask<Stream> DialAsync(string domain, CancellationToken cancellationToken)
    {
        if (Undialable)
        {
            throw new IOException("connection refused");
        }

        Dialled.Add(domain);
        (TcpClient client, TcpClient server) = await Loopback.PairAsync(cancellationToken);
        calls.Add(ServeAsync(server, cancellationToken));
        return client.GetStream();
    }

    /// <summary>Waits for every call to end.</summary>
    internal Task EndedAsync() => Task.WhenAll(calls);

    private async Task ServeAsync(TcpClient socket, CancellationToken cancellationToken)
    {
        using TcpClient owned = socket;
        Stream stream = socket.GetStream();
        AuthKey? authidKey = null, hostKey = null;
        while (true)
        {
            byte[] encoded = new byte[Dp9ikConstants.TicketRequestLength];
            try
            {
                await stream.ReadExactlyAsync(encoded, cancellationToken);
            }
            catch (EndOfStreamException)
            {
                return;
            }

            TicketRequest.TryUnmarshal(encoded, out TicketRequest? request, out _);
            Requests.Add(request!);
            if (request!.Type == AuthMessageType.AuthPak)
            {
                (authidKey, byte[] authidY) = await Pak1Async(stream, request.AuthIdText, cancellationToken);
                (hostKey, byte[] hostY) = await Pak1Async(stream, request.HostIdText, cancellationToken);
                byte[] values = [.. authidY, .. hostY];
                if (OkVarCount is not null)
                {
                    await stream.WriteAsync((byte[])[(byte)AuthMessageType.AuthOkVar, .. System.Text.Encoding.ASCII.GetBytes(OkVarCount), .. values[..OkVarSent]], cancellationToken);
                    if (OkVarSent < (int.TryParse(OkVarCount, out int count) ? count : 0))
                    {
                        return;
                    }

                    continue;
                }

                await stream.WriteAsync((byte[])[(byte)AuthMessageType.AuthOk, .. values[..(HangUpInPak ? values.Length / 4 : values.Length)]], cancellationToken);
                if (HangUpInPak)
                {
                    return;
                }
            }
            else if (request.Type == AuthMessageType.AuthTreq)
            {
                if (HangUpOnTicketRequest)
                {
                    return;
                }

                if (Refusal is not null)
                {
                    var error = new byte[64];
                    System.Text.Encoding.UTF8.GetBytes(Refusal).CopyTo(error, 0);
                    await stream.WriteAsync((byte[])[(byte)AuthMessageType.AuthErr, .. error], cancellationToken);
                    return;
                }

                byte[] tickets = Tickets(request, authidKey!, hostKey!);
                await stream.WriteAsync(tickets[..(HangUpInTickets ? tickets.Length - 10 : tickets.Length)], cancellationToken);
                if (HangUpInTickets)
                {
                    return;
                }
            }
        }
    }

    // pak1: the caller's value read, the key finished with it, and the server's value to send. The
    // client writes both values before it reads, so authsrv's order of writes and reads is kept
    // only in what each side sees.
    private async Task<(AuthKey Key, byte[] Y)> Pak1Async(Stream stream, string user, CancellationToken cancellationToken)
    {
        AuthKey key = passwords.TryGetValue(user, out string? password) ? AuthKey.FromPassword(password) : AuthKey.CreateRandom();
        key.ApplyAuthPakHash(user);
        var state = new AuthPakState();
        byte[] own = state.CreatePublicValue(key, isClient: false);
        byte[] y = new byte[Dp9ikConstants.PakPublicValueLength];
        await stream.ReadExactlyAsync(y, cancellationToken);
        state.Finish(key, y);
        return (key, own);
    }

    // ticketrequest: the client's ticket under the host's key and the server's under the authid's,
    // both for the uid; keys made up when the host does not speak for the uid.
    private static byte[] Tickets(TicketRequest request, AuthKey authidKey, AuthKey hostKey)
    {
        if (request.HostIdText != request.UserIdText)
        {
            (authidKey, hostKey) = (AuthKey.CreateRandom(), AuthKey.CreateRandom());
        }

        var ticket = new Ticket(AuthMessageType.AuthTc, TicketEncryptionForm.Form1);
        ticket.SetChallenge(request.Challenge);
        ticket.SetClientUser(request.UserIdText);
        ticket.SetServerUser(request.UserIdText);
        ticket.SetSessionKey(RandomNumberGenerator.GetBytes(Dp9ikConstants.NonceLength));
        byte[] client = ticket.Marshal(hostKey);
        var server = new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1);
        server.SetChallenge(ticket.Challenge);
        server.SetClientUser(ticket.ClientUserText);
        server.SetServerUser(ticket.ServerUserText);
        server.SetSessionKey(ticket.SessionKey);
        return [(byte)AuthMessageType.AuthOk, .. client, .. server.Marshal(authidKey)];
    }
}

/// <summary>Both ends of a loopback TCP connection.</summary>
internal static class Loopback
{
    internal static async Task<(TcpClient Client, TcpClient Server)> PairAsync(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            Task<TcpClient> accept = listener.AcceptTcpClientAsync(cancellationToken).AsTask();
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, cancellationToken);
            return (client, await accept);
        }
        finally
        {
            listener.Stop();
        }
    }
}
