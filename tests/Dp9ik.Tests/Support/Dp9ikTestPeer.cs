using FluentAssertions;

namespace Dp9ik.Tests.Support;

/// <summary>
/// The client side of a dp9ik exchange, playing both the 9front client and its auth server, as
/// the offline handshake tests do. It records the values both sides need for the session secret.
/// </summary>
internal static class Dp9ikTestPeer
{
    internal static readonly byte[] ClientChallenge = "client!!"u8.ToArray();

    internal static async Task<PeerResult> RunAsync(Stream stream, AuthServerConfig config, string clientUser, CancellationToken cancellationToken,
        TicketEncryptionForm form = TicketEncryptionForm.Form1, Action<byte[]>? tamper = null)
    {
        string greeting = await CStringEncoding.ReadAsync(stream, 4096, cancellationToken);
        greeting.Should().Be($"dp9ik@{config.Domain}");
        await CStringEncoding.WriteAsync(stream, $"dp9ik {config.Domain}", cancellationToken);
        await stream.WriteAsync(ClientChallenge, cancellationToken);

        byte[] offer = await StreamExtensions.ReadExactlyAsync(
            stream, Dp9ikConstants.TicketRequestLength + Dp9ikConstants.PakPublicValueLength, cancellationToken);
        TicketRequest.TryUnmarshal(offer[..Dp9ikConstants.TicketRequestLength], out TicketRequest? request, out _).Should().BeTrue();

        AuthKey authServerKey = AuthKey.FromPassword(config.Password);
        authServerKey.ApplyAuthPakHash(config.User);
        var authServerState = new AuthPakState();
        byte[] authServerY = authServerState.CreatePublicValue(authServerKey, isClient: false);
        authServerState.Finish(authServerKey, offer[Dp9ikConstants.TicketRequestLength..]);

        byte[] ticketKey = Pattern(Dp9ikConstants.NonceLength, 20);
        byte[] clientRandom = Pattern(Dp9ikConstants.NonceLength, 120);
        var ticket = new Ticket(AuthMessageType.AuthTs, form);
        ticket.SetChallenge(request!.Challenge);
        ticket.SetClientUser(clientUser);
        ticket.SetServerUser(config.User);
        ticket.SetSessionKey(ticketKey);
        var authenticator = new Authenticator(AuthMessageType.AuthAc);
        authenticator.SetChallenge(request.Challenge);
        authenticator.SetRandom(clientRandom);

        await stream.WriteAsync(authServerY, cancellationToken);
        // The server reads a fixed-size proof; a shorter form 0 proof is padded to that size.
        byte[] proof = [.. ticket.Marshal(authServerKey), .. authenticator.Marshal(ticket)];
        tamper?.Invoke(proof);
        await stream.WriteAsync(proof, cancellationToken);
        int padding = Dp9ikConstants.MaxTicketLength + Dp9ikConstants.MaxAuthenticatorLength - proof.Length;
        if (padding > 0) await stream.WriteAsync(new byte[padding], cancellationToken);

        byte[] encodedReply = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.MaxAuthenticatorLength, cancellationToken);
        Authenticator.TryUnmarshal(ticket, encodedReply, out Authenticator? reply, out _).Should().BeTrue();
        return new PeerResult(ticketKey, clientRandom, reply!.Random.ToArray());
    }

    internal static byte[] Pattern(int length, byte seed)
    {
        var bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(seed + index);
        }

        return bytes;
    }

    internal sealed record PeerResult(byte[] TicketKey, byte[] ClientRandom, byte[] ServerRandom);
}
