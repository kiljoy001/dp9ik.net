using FluentAssertions;

namespace Dp9ik.Tests;

public sealed class TicketAndAuthenticatorTests
{
    [Fact]
    public void Ticket_And_Authenticator_RoundTrip_Using_Form1()
    {
        var key = CreateSharedKey("testpassword", "scott");

        var ticket = new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1);
        ticket.SetChallenge("chal1234"u8);
        ticket.SetClientUser("scott");
        ticket.SetServerUser("bootes");
        ticket.SetSessionKey(CreatePattern(Dp9ikConstants.NonceLength, 1));

        var encodedTicket = ticket.Marshal(key);

        Ticket.TryUnmarshal(key, encodedTicket, out var decodedTicket, out var ticketLength).Should().BeTrue();
        ticketLength.Should().Be(encodedTicket.Length);
        decodedTicket.Should().NotBeNull();
        decodedTicket!.ClientUserText.Should().Be("scott");
        decodedTicket.ServerUserText.Should().Be("bootes");
        decodedTicket.SessionKey.Should().Equal(ticket.SessionKey);

        var authenticator = new Authenticator(AuthMessageType.AuthAc);
        authenticator.SetChallenge(ticket.Challenge);
        authenticator.SetRandom(CreatePattern(Dp9ikConstants.NonceLength, 32));

        var encodedAuthenticator = authenticator.Marshal(decodedTicket);

        Authenticator.TryUnmarshal(decodedTicket, encodedAuthenticator, out var decodedAuthenticator, out var authenticatorLength)
            .Should().BeTrue();

        authenticatorLength.Should().Be(encodedAuthenticator.Length);
        decodedAuthenticator.Should().NotBeNull();
        decodedAuthenticator!.Random.Should().Equal(authenticator.Random);
    }

    [Fact]
    public void Ticket_And_Authenticator_Invalid_Buffers_Report_Zero_Consumed()
    {
        var key = CreateSharedKey("testpassword", "scott");
        var ticket = new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1);
        ticket.SetSessionKey(CreatePattern(Dp9ikConstants.NonceLength, 1));

        Ticket.TryUnmarshal(key, [0xFF], out var decodedTicket, out var ticketLength).Should().BeFalse();
        decodedTicket.Should().BeNull();
        ticketLength.Should().Be(0);

        Authenticator.TryUnmarshal(ticket, [0xFF], out var decodedAuthenticator, out var authenticatorLength).Should().BeFalse();
        decodedAuthenticator.Should().BeNull();
        authenticatorLength.Should().Be(0);
    }

    [Fact]
    public void Ticket_And_Authenticator_Wrong_Keys_Report_Zero_Consumed()
    {
        var key = CreateSharedKey("testpassword", "scott");
        var wrongKey = CreateSharedKey("wrongpassword", "scott");

        var ticket = new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1);
        ticket.SetChallenge("chal1234"u8);
        ticket.SetClientUser("scott");
        ticket.SetServerUser("bootes");
        ticket.SetSessionKey(CreatePattern(Dp9ikConstants.NonceLength, 1));

        var encodedTicket = ticket.Marshal(key);

        Ticket.TryUnmarshal(wrongKey, encodedTicket, out var decodedTicket, out var ticketLength).Should().BeFalse();
        decodedTicket.Should().BeNull();
        ticketLength.Should().Be(0);

        var authenticator = new Authenticator(AuthMessageType.AuthAc);
        authenticator.SetChallenge(ticket.Challenge);
        authenticator.SetRandom(CreatePattern(Dp9ikConstants.NonceLength, 32));

        var encodedAuthenticator = authenticator.Marshal(ticket);
        var wrongTicket = new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1);
        wrongTicket.SetChallenge(ticket.Challenge);
        wrongTicket.SetClientUser("scott");
        wrongTicket.SetServerUser("bootes");
        wrongTicket.SetSessionKey(CreatePattern(Dp9ikConstants.NonceLength, 96));

        Authenticator.TryUnmarshal(wrongTicket, encodedAuthenticator, out var decodedAuthenticator, out var authenticatorLength)
            .Should().BeFalse();

        decodedAuthenticator.Should().BeNull();
        authenticatorLength.Should().Be(0);
    }

    [Fact]
    public void Native_Struct_Sizes_Match_Drawterm()
    {
        NativeLayout.SizeOfTicket().Should().Be(98);
        NativeLayout.SizeOfAuthenticator().Should().Be(41);
        NativeLayout.SizeOfAuthKey().Should().Be(503);
        NativeLayout.SizeOfAuthPakState().Should().Be(116);
    }

    private static AuthKey CreateSharedKey(string password, string user)
    {
        var clientKey = AuthKey.FromPassword(password);
        clientKey.ApplyAuthPakHash(user);

        var serverKey = AuthKey.FromPassword(password);
        serverKey.ApplyAuthPakHash(user);

        var clientState = new AuthPakState();
        var serverState = new AuthPakState();

        var clientY = clientState.CreatePublicValue(clientKey, isClient: true);
        var serverY = serverState.CreatePublicValue(serverKey, isClient: false);

        clientState.Finish(clientKey, serverY);
        serverState.Finish(serverKey, clientY);

        return clientKey;
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
}
