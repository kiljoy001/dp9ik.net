using System.Net.Sockets;
using System.Security.Cryptography;
using FluentAssertions;

namespace Dp9ik.Tests;

public sealed class LiveAuthServerTests
{
    private const int AuthServerPort = 567;
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    [Fact]
    [Trait("Category", "Live")]
    public async Task Can_Authenticate_Against_A_Live_Auth_Server()
    {
        if (!TryGetEnvironmentVariable("DP9IK_TEST_AUTH_SERVER", out var server) ||
            !TryGetEnvironmentVariable("DP9IK_TEST_AUTH_USER", out var user) ||
            !TryGetEnvironmentVariable("DP9IK_TEST_AUTH_PASSWORD", out var password))
        {
            return;
        }

        using var cancellation = new CancellationTokenSource(DefaultTimeout);
        using var tcpClient = new TcpClient();
        var endpoint = ParseEndpoint(server);
        await tcpClient.ConnectAsync(endpoint.Host, endpoint.Port, cancellation.Token);
        await using var stream = tcpClient.GetStream();

        var challenge = RandomNumberGenerator.GetBytes(Dp9ikConstants.ChallengeLength);
        var request = CreateTicketRequest(AuthMessageType.AuthPak, user, challenge);
        var clientKey = AuthKey.FromPassword(password);
        clientKey.ApplyAuthPakHash(user);

        var fileServerKey = AuthKey.FromPassword(password);
        fileServerKey.ApplyAuthPakHash(user);
        var fileServerState = new AuthPakState();
        var fileServerY = fileServerState.CreatePublicValue(fileServerKey, isClient: false);

        await stream.WriteAsync(request.Marshal(), cancellation.Token);
        await stream.WriteAsync(fileServerY, cancellation.Token);

        var clientState = new AuthPakState();
        var clientY = clientState.CreatePublicValue(clientKey, isClient: true);
        await stream.WriteAsync(clientY, cancellation.Token);

        var pakStatus = await StreamExtensions.ReadSingleByteAsync(stream, cancellation.Token);
        pakStatus.Should().Be((byte)AuthMessageType.AuthOk);

        var pakResponse = await StreamExtensions.ReadExactlyAsync(
            stream,
            2 * Dp9ikConstants.PakPublicValueLength,
            cancellation.Token);
        clientState.Finish(clientKey, pakResponse.AsSpan(Dp9ikConstants.PakPublicValueLength, Dp9ikConstants.PakPublicValueLength));

        var ticketRequest = CreateTicketRequest(AuthMessageType.AuthTreq, user, challenge);
        await stream.WriteAsync(ticketRequest.Marshal(), cancellation.Token);

        var ticketStatus = await StreamExtensions.ReadSingleByteAsync(stream, cancellation.Token);
        ticketStatus.Should().Be((byte)AuthMessageType.AuthOk);

        var (clientTicket, serverTicketRaw) = await ReadAuthServerTicketsAsync(stream, clientKey, cancellation.Token);
        clientTicket.Type.Should().Be(AuthMessageType.AuthTc);
        clientTicket.Form.Should().Be(TicketEncryptionForm.Form1);
        clientTicket.Challenge.Should().Equal(challenge);
        clientTicket.ClientUserText.Should().Be(user);
        clientTicket.ServerUserText.Should().Be(user);
        serverTicketRaw.Should().NotBeEmpty();
        clientKey.SharedKey.Should().NotEqual(new byte[Dp9ikConstants.PakKeyLength]);
    }

    private static TicketRequest CreateTicketRequest(AuthMessageType type, string user, byte[] challenge)
    {
        var request = new TicketRequest(type);
        request.SetAuthId(user);
        request.SetAuthDomain(string.Empty);
        request.SetChallenge(challenge);
        request.SetHostId(user);
        request.SetUserId(user);
        return request;
    }

    private static (string Host, int Port) ParseEndpoint(string value)
    {
        var lastColon = value.LastIndexOf(':');
        if (lastColon <= 0 || !int.TryParse(value[(lastColon + 1)..], out var port))
        {
            return (value, AuthServerPort);
        }

        return (value[..lastColon], port);
    }

    private static async Task<(Ticket Ticket, byte[] ServerTicketRaw)> ReadAuthServerTicketsAsync(
        Stream stream,
        AuthKey clientKey,
        CancellationToken cancellationToken)
    {
        const int limit = 2 * Dp9ikConstants.MaxTicketLength;
        var buffer = new List<byte>(limit);
        var chunk = new byte[256];
        Ticket? clientTicket = null;
        var clientTicketLength = 0;

        while (buffer.Count <= limit)
        {
            if (clientTicket is null && buffer.Count > 0)
            {
                var snapshot = buffer.ToArray();
                if (Ticket.TryUnmarshal(clientKey, snapshot, out clientTicket, out clientTicketLength))
                {
                    // Keep reading briefly so the encrypted server ticket can arrive on the same socket.
                }
            }

            using var readWindow = clientTicket is null
                ? null
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var readToken = cancellationToken;
            if (readWindow is not null)
            {
                readWindow.CancelAfter(TimeSpan.FromMilliseconds(150));
                readToken = readWindow.Token;
            }

            try
            {
                var read = await stream.ReadAsync(chunk, readToken);
                if (read == 0)
                {
                    if (clientTicket is not null)
                    {
                        return (clientTicket, buffer.Skip(clientTicketLength).ToArray());
                    }

                    continue;
                }

                buffer.AddRange(chunk.AsSpan(0, read).ToArray());
            }
            catch (OperationCanceledException) when (clientTicket is not null && !cancellationToken.IsCancellationRequested)
            {
                return (clientTicket, buffer.Skip(clientTicketLength).ToArray());
            }
            catch (IOException) when (clientTicket is not null)
            {
                return (clientTicket, buffer.Skip(clientTicketLength).ToArray());
            }
        }

        throw new InvalidOperationException($"Ticket response exceeded {limit} bytes.");
    }

    private static bool TryGetEnvironmentVariable(string name, out string value)
    {
        value = Environment.GetEnvironmentVariable(name) ?? string.Empty;
        return !string.IsNullOrWhiteSpace(value);
    }
}
