using System.Security.Cryptography;

namespace Dp9ik.P9Auth;

public static class P9AuthProtocol
{
    public static async Task<string> HandshakeAsync(Stream stream, AuthServerConfig config, CancellationToken cancellationToken)
    {
        config.Validate();

        var key = AuthKey.FromPassword(config.Password);
        key.ApplyAuthPakHash(config.User);

        await CStringEncoding.WriteAsync(stream, $"dp9ik@{config.Domain}", cancellationToken);
        var choice = await CStringEncoding.ReadAsync(stream, 4096, cancellationToken);
        ValidateChoice(choice, config.Domain);

        var clientChallenge = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.ChallengeLength, cancellationToken);
        var serverChallenge = RandomNumberGenerator.GetBytes(Dp9ikConstants.ChallengeLength);

        var offer = BuildOffer(config, key, serverChallenge);
        await stream.WriteAsync(offer.Encoded, cancellationToken);

        var authServerY = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.PakPublicValueLength, cancellationToken);
        offer.State.Finish(key, authServerY);

        var proof = await ReadClientProofAsync(stream, key, cancellationToken);
        ValidateProof(proof, serverChallenge);

        var reply = BuildReply(proof.Ticket, clientChallenge);
        await stream.WriteAsync(reply, cancellationToken);

        return string.IsNullOrWhiteSpace(proof.Ticket.ClientUserText)
            ? throw new InvalidOperationException("Authenticated user is empty.")
            : proof.Ticket.ClientUserText;
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

    private static byte[] BuildReply(Ticket ticket, byte[] clientChallenge)
    {
        var reply = new Authenticator(AuthMessageType.AuthAs);
        reply.SetChallenge(clientChallenge);
        reply.SetRandom(RandomNumberGenerator.GetBytes(Dp9ikConstants.NonceLength));
        return reply.Marshal(ticket);
    }

    private static async Task<(Ticket Ticket, Authenticator Authenticator)> ReadClientProofAsync(Stream stream, AuthKey key, CancellationToken cancellationToken)
    {
        var buffer = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.MaxTicketLength + Dp9ikConstants.MaxAuthenticatorLength, cancellationToken);
        var ticket = ReadTicket(key, buffer);
        var authenticator = ReadAuthenticator(ticket, buffer.AsSpan(Dp9ikConstants.MaxTicketLength));
        return (ticket, authenticator);
    }

    private static void ValidateChoice(string choice, string domain)
    {
        if (!string.Equals(choice, $"dp9ik {domain}", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Unsupported auth choice '{choice}'.");
        }
    }

    private static void ValidateProof((Ticket Ticket, Authenticator Authenticator) proof, byte[] serverChallenge)
    {
        EnsureTicketType(proof.Ticket);
        EnsureAuthenticatorType(proof.Authenticator);
        EnsureTicketChallenge(proof.Ticket, serverChallenge);
        EnsureAuthenticatorChallenge(proof.Authenticator, serverChallenge);
    }

    private static Ticket ReadTicket(AuthKey key, byte[] buffer) => Ticket.TryUnmarshal(key, buffer, out var ticket, out _)
        ? ticket!
        : throw new InvalidOperationException("Unable to decode the client ticket.");

    private static Authenticator ReadAuthenticator(Ticket ticket, ReadOnlySpan<byte> buffer) => Authenticator.TryUnmarshal(ticket, buffer, out var authenticator, out _)
        ? authenticator!
        : throw new InvalidOperationException("Unable to decode the client authenticator.");

    private static void EnsureAuthenticatorChallenge(Authenticator authenticator, byte[] serverChallenge)
    {
        if (!authenticator.Challenge.SequenceEqual(serverChallenge))
        {
            throw new InvalidOperationException("Authenticator challenge mismatch.");
        }
    }

    private static void EnsureAuthenticatorType(Authenticator authenticator)
    {
        if (authenticator.Type != AuthMessageType.AuthAc)
        {
            throw new InvalidOperationException($"Unexpected authenticator type {authenticator.Type}.");
        }
    }

    private static void EnsureTicketChallenge(Ticket ticket, byte[] serverChallenge)
    {
        if (!ticket.Challenge.SequenceEqual(serverChallenge))
        {
            throw new InvalidOperationException("Ticket challenge mismatch.");
        }
    }

    private static void EnsureTicketType(Ticket ticket)
    {
        if (ticket.Type != AuthMessageType.AuthTs)
        {
            throw new InvalidOperationException($"Unexpected ticket type {ticket.Type}.");
        }
    }
}
