using Org.BouncyCastle.Security;

namespace Dp9ik.P9Auth;

/// <summary>An authenticated dp9ik peer and the session secret both sides derived.</summary>
/// <param name="User">The client user named in the ticket.</param>
/// <param name="Secret">The 256-byte secret factotum gives tlssrv and tlsclient as their PSK.</param>
public sealed record P9AuthResult(string User, byte[] Secret);

/// <summary>The server side of p9any negotiating dp9ik, as 9front factotum's p9any and dp9ik run it.</summary>
public static class P9AuthProtocol
{
    private static readonly SecureRandom Random = new();

    /// <summary>Authenticates a client and returns its user.</summary>
    public static async Task<string> HandshakeAsync(Stream stream, AuthServerConfig config, CancellationToken cancellationToken)
        => (await AuthenticateAsync(stream, config, cancellationToken)).User;

    /// <summary>Runs the server side of p9any/dp9ik and returns the client user and the session secret.</summary>
    public static async Task<P9AuthResult> AuthenticateAsync(Stream stream, AuthServerConfig config, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(config);
        config.Validate();

        var key = AuthKey.FromPassword(config.Password);
        key.ApplyAuthPakHash(config.User);

        await CStringEncoding.WriteAsync(stream, $"dp9ik@{config.Domain}", cancellationToken);
        var choice = await CStringEncoding.ReadAsync(stream, 4096, cancellationToken);
        P9AuthSecurityPolicy.ValidateChoice(choice, config.Domain);

        var clientChallenge = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.ChallengeLength, cancellationToken);
        var serverChallenge = RandomBytes(Dp9ikConstants.ChallengeLength);

        var offer = BuildOffer(config, key, serverChallenge);
        await stream.WriteAsync(offer.Encoded, cancellationToken);

        var authServerY = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.PakPublicValueLength, cancellationToken);
        offer.State.Finish(key, authServerY);

        var proof = await ReadClientProofAsync(stream, key, cancellationToken);
        P9AuthSecurityPolicy.ValidateProof(proof.Ticket, proof.Authenticator, serverChallenge);

        string user = P9AuthSecurityPolicy.GetAuthenticatedUser(proof.Ticket);
        var serverRandom = RandomBytes(Dp9ikConstants.NonceLength);
        var reply = BuildReply(proof.Ticket, clientChallenge, serverRandom);
        await stream.WriteAsync(reply, cancellationToken);

        return new P9AuthResult(user, SessionSecret.Derive(proof.Authenticator.Random, serverRandom, proof.Ticket.SessionKey));
    }

    private static (byte[] Encoded, AuthPakState State) BuildOffer(AuthServerConfig config, AuthKey key, byte[] serverChallenge)
    {
        var request = new TicketRequest(AuthMessageType.AuthPak);
        request.SetAuthId(config.User);
        request.SetAuthDomain(config.Domain);
        request.SetChallenge(serverChallenge);

        var encodedRequest = request.Marshal();
        var state = new AuthPakState();
        var publicValue = state.CreatePublicValue(key, isClient: true);

        return (encodedRequest.Concat(publicValue).ToArray(), state);
    }

    private static byte[] BuildReply(Ticket ticket, byte[] clientChallenge, byte[] serverRandom)
    {
        var reply = new Authenticator(AuthMessageType.AuthAs);
        reply.SetChallenge(clientChallenge);
        reply.SetRandom(serverRandom);
        return reply.Marshal(ticket);
    }

    private static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        Random.NextBytes(bytes);
        return bytes;
    }

    private static async Task<(Ticket Ticket, Authenticator Authenticator)> ReadClientProofAsync(Stream stream, AuthKey key, CancellationToken cancellationToken)
    {
        var buffer = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.MaxTicketLength + Dp9ikConstants.MaxAuthenticatorLength, cancellationToken);
        var ticket = ReadTicket(key, buffer);
        var authenticator = ReadAuthenticator(ticket, buffer.AsSpan(Dp9ikConstants.MaxTicketLength));
        return (ticket, authenticator);
    }

    /// <summary>As factotum does for dp9ik, a form 0 (DES) ticket is refused rather than downgraded to.</summary>
    private static Ticket ReadTicket(AuthKey key, byte[] buffer)
    {
        if (!Ticket.TryUnmarshal(key, buffer, out var ticket, out _)) throw new InvalidOperationException("Unable to decode the client ticket.");
        return ticket!.Form == TicketEncryptionForm.Form1 ? ticket : throw new InvalidOperationException("dp9ik requires a form 1 ticket.");
    }

    private static Authenticator ReadAuthenticator(Ticket ticket, ReadOnlySpan<byte> buffer) => Authenticator.TryUnmarshal(ticket, buffer, out var authenticator, out _)
        ? authenticator!
        : throw new InvalidOperationException("Unable to decode the client authenticator.");
}
