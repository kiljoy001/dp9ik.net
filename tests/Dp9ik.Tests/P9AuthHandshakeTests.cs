using System.Net;
using System.Net.Sockets;
using Dp9ik.Tests.Support;
using FluentAssertions;

namespace Dp9ik.Tests;

public sealed class P9AuthHandshakeTests
{
    [Fact]
    public async Task HandshakeAsync_Completes_Offline_With_Local_Client_And_Local_Auth_Server_Model()
    {
        var config = new AuthServerConfig("example.test", "bootes", "testpassword");

        var result = await RunHandshakeAsync(config);

        result.User.Should().Be("scott");
        result.Observation.Greeting.Should().Be($"dp9ik@{config.Domain}");
        result.Observation.OfferRequest.Should().NotBeNull();
        result.Observation.OfferRequest!.Type.Should().Be(AuthMessageType.AuthPak);
        result.Observation.OfferRequest.AuthIdText.Should().Be(config.User);
        result.Observation.OfferRequest.AuthDomainText.Should().Be(config.Domain);
        result.Observation.Reply.Should().NotBeNull();
        result.Observation.Reply!.Type.Should().Be(AuthMessageType.AuthAs);
        result.Observation.Reply.Challenge.Should().Equal(result.Observation.ClientChallenge);
        result.Observation.Reply.Random.Should().NotEqual(new byte[Dp9ikConstants.NonceLength]);
    }

    [Fact]
    public async Task HandshakeAsync_Rejects_Unsupported_Choice()
    {
        var config = new AuthServerConfig("example.test", "bootes", "testpassword");

        var act = () => RunHandshakeAsync(
            config,
            choice: "p9sk1 example.test",
            stopAfterChoice: true,
            readReply: false);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Unsupported auth choice*");
    }

    [Fact]
    public async Task HandshakeAsync_Rejects_Empty_Client_User()
    {
        var config = new AuthServerConfig("example.test", "bootes", "testpassword");

        var act = () => RunHandshakeAsync(
            config,
            proofTransform: (request, authConfig, proof) =>
                proof with
                {
                    Ticket = CreateTicket(
                        AuthMessageType.AuthTs,
                        request.Challenge,
                        string.Empty,
                        authConfig.User,
                        proof.Ticket.SessionKey)
                },
            readReply: false);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Authenticated user is empty*");
    }

    [Fact]
    public async Task HandshakeAsync_Rejects_Unexpected_Ticket_Type()
    {
        var config = new AuthServerConfig("example.test", "bootes", "testpassword");

        var act = () => RunHandshakeAsync(
            config,
            proofTransform: (request, authConfig, proof) =>
                proof with
                {
                    Ticket = CreateTicket(
                        AuthMessageType.AuthTc,
                        request.Challenge,
                        proof.Ticket.ClientUserText,
                        authConfig.User,
                        proof.Ticket.SessionKey)
                },
            readReply: false);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Unexpected ticket type*");
    }

    [Fact]
    public async Task HandshakeAsync_Rejects_Unexpected_Authenticator_Type()
    {
        var config = new AuthServerConfig("example.test", "bootes", "testpassword");

        var act = () => RunHandshakeAsync(
            config,
            proofTransform: (request, _, proof) =>
                proof with
                {
                    Authenticator = CreateAuthenticator(
                        AuthMessageType.AuthAs,
                        request.Challenge,
                        proof.Authenticator.Random)
                },
            readReply: false);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Unexpected authenticator type*");
    }

    [Fact]
    public async Task HandshakeAsync_Rejects_Ticket_Challenge_Mismatch()
    {
        var config = new AuthServerConfig("example.test", "bootes", "testpassword");

        var act = () => RunHandshakeAsync(
            config,
            proofTransform: (_, authConfig, proof) =>
                proof with
                {
                    Ticket = CreateTicket(
                        AuthMessageType.AuthTs,
                        CreatePattern(Dp9ikConstants.ChallengeLength, 40),
                        proof.Ticket.ClientUserText,
                        authConfig.User,
                        proof.Ticket.SessionKey)
                },
            readReply: false);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Ticket challenge mismatch*");
    }

    [Fact]
    public async Task HandshakeAsync_Rejects_Authenticator_Challenge_Mismatch()
    {
        var config = new AuthServerConfig("example.test", "bootes", "testpassword");

        var act = () => RunHandshakeAsync(
            config,
            proofTransform: (_, _, proof) =>
                proof with
                {
                    Authenticator = CreateAuthenticator(
                        AuthMessageType.AuthAc,
                        CreatePattern(Dp9ikConstants.ChallengeLength, 80),
                        proof.Authenticator.Random)
                },
            readReply: false);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Authenticator challenge mismatch*");
    }

    [Theory]
    [InlineData("", "bootes", "password", "domain")]
    [InlineData("example.test", "", "password", "user")]
    [InlineData("example.test", "bootes", "", "password")]
    public void Validate_Rejects_Missing_Fields(string domain, string user, string password, string expectedName)
    {
        var config = new AuthServerConfig(domain, user, password);

        var act = () => config.Validate();

        act.Should().Throw<ArgumentException>()
            .WithMessage($"*{expectedName}*");
    }

    [Fact]
    public async Task HandshakeAsync_Rejects_Invalid_Config_Before_Any_Protocol_IO()
    {
        var config = new AuthServerConfig(string.Empty, "bootes", "testpassword");

        var act = () => P9AuthProtocol.HandshakeAsync(Stream.Null, config, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Domain*");
    }

    private static async Task<HandshakeResult> RunHandshakeAsync(
        AuthServerConfig config,
        string? choice = null,
        bool stopAfterChoice = false,
        Func<TicketRequest, AuthServerConfig, ProofPayload, ProofPayload>? proofTransform = null,
        bool readReply = true)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var cts = new CancellationTokenSource(TestTimeouts.Network);
        listener.Start();

        var serverTask = RunServerAsync(listener, config, cts.Token);
        var observation = await RunClientAsync(
            listener.LocalEndpoint,
            config,
            choice ?? $"dp9ik {config.Domain}",
            stopAfterChoice,
            proofTransform,
            readReply,
            cts.Token);
        var user = await serverTask;

        return new HandshakeResult(user, observation);
    }

    private static async Task<string> RunServerAsync(TcpListener listener, AuthServerConfig config, CancellationToken cancellationToken)
    {
        using var socket = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = socket.GetStream();
        return await P9AuthProtocol.HandshakeAsync(stream, config, cancellationToken);
    }

    private static async Task<HandshakeObservation> RunClientAsync(
        EndPoint endpoint,
        AuthServerConfig config,
        string choice,
        bool stopAfterChoice,
        Func<TicketRequest, AuthServerConfig, ProofPayload, ProofPayload>? proofTransform,
        bool readReply,
        CancellationToken cancellationToken)
    {
        using var socket = new TcpClient();
        await socket.ConnectAsync(((IPEndPoint)endpoint).Address, ((IPEndPoint)endpoint).Port, cancellationToken);
        await using var stream = socket.GetStream();

        var greeting = await CStringEncoding.ReadAsync(stream, 4096, cancellationToken);
        await CStringEncoding.WriteAsync(stream, choice, cancellationToken);

        if (stopAfterChoice)
        {
            return new HandshakeObservation(greeting, "client!!"u8.ToArray(), null, null);
        }

        var clientChallenge = "client!!"u8.ToArray();
        await stream.WriteAsync(clientChallenge, cancellationToken);

        var encodedOffer = await StreamExtensions.ReadExactlyAsync(
            stream,
            Dp9ikConstants.TicketRequestLength + Dp9ikConstants.PakPublicValueLength,
            cancellationToken);

        TicketRequest.TryUnmarshal(encodedOffer[..Dp9ikConstants.TicketRequestLength], out var offerRequest, out _)
            .Should().BeTrue();

        offerRequest.Should().NotBeNull();
        var authServerKey = CreateAuthServerKey(config);
        var defaultProof = BuildValidProof(
            offerRequest!,
            config,
            authServerKey,
            encodedOffer[Dp9ikConstants.TicketRequestLength..]);
        var proof = proofTransform?.Invoke(offerRequest, config, defaultProof) ?? defaultProof;

        await stream.WriteAsync(proof.AuthServerY, cancellationToken);
        await stream.WriteAsync(proof.Ticket.Marshal(authServerKey), cancellationToken);
        await stream.WriteAsync(proof.Authenticator.Marshal(proof.Ticket), cancellationToken);

        Authenticator? reply = null;
        if (readReply)
        {
            var encodedReply = await StreamExtensions.ReadExactlyAsync(
                stream,
                Dp9ikConstants.MaxAuthenticatorLength,
                cancellationToken);

            Authenticator.TryUnmarshal(proof.Ticket, encodedReply, out reply, out _).Should().BeTrue();
            reply.Should().NotBeNull();
        }

        return new HandshakeObservation(greeting, clientChallenge, offerRequest, reply);
    }

    private static AuthKey CreateAuthServerKey(AuthServerConfig config)
    {
        var key = AuthKey.FromPassword(config.Password);
        key.ApplyAuthPakHash(config.User);
        return key;
    }

    private static ProofPayload BuildValidProof(
        TicketRequest request,
        AuthServerConfig config,
        AuthKey authServerKey,
        byte[] fileServerY)
    {
        var authServerState = new AuthPakState();
        var authServerY = authServerState.CreatePublicValue(authServerKey, isClient: false);
        authServerState.Finish(authServerKey, fileServerY);

        var ticket = CreateTicket(
            AuthMessageType.AuthTs,
            request.Challenge,
            "scott",
            config.User,
            CreatePattern(Dp9ikConstants.NonceLength, 20));
        var authenticator = CreateAuthenticator(
            AuthMessageType.AuthAc,
            request.Challenge,
            CreatePattern(Dp9ikConstants.NonceLength, 120));

        return new ProofPayload(authServerY, ticket, authenticator);
    }

    private static Ticket CreateTicket(
        AuthMessageType type,
        ReadOnlySpan<byte> challenge,
        string clientUser,
        string serverUser,
        ReadOnlySpan<byte> sessionKey)
    {
        var ticket = new Ticket(type, TicketEncryptionForm.Form1);
        ticket.SetChallenge(challenge);
        ticket.SetClientUser(clientUser);
        ticket.SetServerUser(serverUser);
        ticket.SetSessionKey(sessionKey);
        return ticket;
    }

    private static Authenticator CreateAuthenticator(
        AuthMessageType type,
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> random)
    {
        var authenticator = new Authenticator(type);
        authenticator.SetChallenge(challenge);
        authenticator.SetRandom(random);
        return authenticator;
    }

    private static byte[] CreatePattern(int length, byte seed)
    {
        var bytes = new byte[length];
        for (var index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(seed + index);
        }

        return bytes;
    }

    private sealed record HandshakeResult(string User, HandshakeObservation Observation);

    private sealed record HandshakeObservation(
        string Greeting,
        byte[] ClientChallenge,
        TicketRequest? OfferRequest,
        Authenticator? Reply);

    private sealed record ProofPayload(byte[] AuthServerY, Ticket Ticket, Authenticator Authenticator);
}
