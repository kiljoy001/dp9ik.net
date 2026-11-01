using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Dp9ik.P9Auth;
using Dp9ik.Tests.Support;
using Dp9ik.Tls;
using FluentAssertions;
using Reqnroll;

namespace Dp9ik.Tests.Steps;

/// <summary>The client side of p9any and dp9ik, against the library's server, scripted servers and a test authsrv.</summary>
[Binding]
[Scope(Feature = "The client side of p9any and dp9ik gets tickets from the auth server and proves itself")]
public sealed class P9AuthClientSteps : IDisposable
{
    private readonly CancellationTokenSource timeout = new(TestTimeouts.Network);
    private readonly List<PasswordPrompt> prompts = [];
    private readonly Queue<string?> passwords = new();
    private TestAuthServer? authServer;
    private Func<Stream, Task<byte[]?>>? server;
    private Task<byte[]?>? serving;
    private Ticket? serverTicket;
    private TcpClient? clientSocket;
    private TcpClient? serverSocket;
    private P9AuthClientResult? result;
    private Exception? error;
    private string? clientUser;
    private string? choice;
    private bool readOk;
    private bool wroteChallenge;
    private byte[]? serverChallenge;
    private MemoryStream? written;

    [Given(@"^an auth server for the domain ""([^""]*)"" that knows ""([^""]*)"" with ""([^""]*)"" and ""([^""]*)"" with ""([^""]*)""$")]
    public void GivenAuthServer(string domain, string user1, string password1, string user2, string password2)
    {
        _ = domain;
        authServer = new TestAuthServer(new Dictionary<string, string> { [user1] = password1, [user2] = password2 });
    }

    [Given(@"^a dp9ik server for ""([^""]*)"" whose authid is ""([^""]*)"" with ""([^""]*)""$")]
    public void GivenServer(string domain, string authid, string password)
        => server = async stream =>
        {
            P9AuthResult authenticated = await P9AuthProtocol.AuthenticateAsync(stream, new AuthServerConfig(domain, authid, password), timeout.Token);
            clientUser = authenticated.User;
            return authenticated.Secret;
        };

    [Given(@"^a dp9ik server for ""([^""]*)"" whose authid is ""([^""]*)"" with ""([^""]*)"" that answers the proof with ""([^""]*)""$")]
    public void GivenServerAnswering(string domain, string authid, string password, string answer)
        => server = stream => ScriptedDp9ikAsync(stream, domain, authid, password, async (_, _) =>
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes(Expand(answer)), timeout.Token);
            serverSocket!.Client.Shutdown(SocketShutdown.Send);
            return null;
        });

    [Given(@"^a dp9ik server for ""([^""]*)"" whose authid is ""([^""]*)"" with ""([^""]*)"" that answers with an authenticator of another challenge$")]
    public void GivenServerLying(string domain, string authid, string password)
        => server = stream => ScriptedDp9ikAsync(stream, domain, authid, password, async (ticket, _) =>
        {
            var reply = new Authenticator(AuthMessageType.AuthAs);
            reply.SetChallenge("another!"u8);
            reply.SetRandom(RandomNumberGenerator.GetBytes(Dp9ikConstants.NonceLength));
            await stream.WriteAsync(reply.Marshal(ticket), timeout.Token);
            return null;
        });

    [Given(@"^a dp9ik server for ""([^""]*)"" whose authid is ""([^""]*)"" with ""([^""]*)"" that answers with 68 bytes that are not an authenticator$")]
    public void GivenServerGarbling(string domain, string authid, string password)
        => server = stream => ScriptedDp9ikAsync(stream, domain, authid, password, async (_, _) =>
        {
            await stream.WriteAsync(new byte[Dp9ikConstants.MaxAuthenticatorLength], timeout.Token);
            return null;
        });

    [Given(@"^a scripted dp9ik server for ""([^""]*)"" whose authid is ""([^""]*)"" with ""([^""]*)""$")]
    public void GivenScriptedServer(string domain, string authid, string password)
        => server = stream => ScriptedDp9ikAsync(stream, domain, authid, password, async (ticket, clientChallenge) =>
        {
            byte[] serverRandom = RandomNumberGenerator.GetBytes(Dp9ikConstants.NonceLength);
            var reply = new Authenticator(AuthMessageType.AuthAs);
            reply.SetChallenge(clientChallenge);
            reply.SetRandom(serverRandom);
            await stream.WriteAsync(reply.Marshal(ticket), timeout.Token);
            return serverRandom;
        });

    [Given(@"^a scripted server that offers ""([^""]*)""$")]
    public void GivenOffer(string offer) => server = stream => ScriptedP9anyAsync(stream, offer, "OK", hangUp: false);

    [Given(@"^a scripted server that offers ""([^""]*)"" and answers the choice with ""([^""]*)""$")]
    public void GivenOfferAnswered(string offer, string answer) => server = stream => ScriptedP9anyAsync(stream, offer, answer, hangUp: false);

    [Given(@"^a scripted server that hangs up after offering ""([^""]*)""$")]
    public void GivenOfferHangingUp(string offer) => server = stream => ScriptedP9anyAsync(stream, offer, "OK", hangUp: true);

    [Given(@"^a scripted server that offers ""dp9ik@"" and a domain making the offer (\d+) bytes$")]
    public void GivenLongOffer(int length) => server = stream => ScriptedP9anyAsync(stream, "dp9ik@" + new string('f', length - 6), "OK", hangUp: false);

    [Given("the auth server hangs up halfway through its AuthPAK values")]
    public void GivenHangingUpInPak() => authServer!.HangUpInPak = true;

    [Given("the auth server hangs up halfway through the tickets")]
    public void GivenHangingUpInTickets() => authServer!.HangUpInTickets = true;

    [Given(@"^the auth server answers AuthPAK with AuthOKvar ""([^""]*)"" and (\d+) bytes of its values$")]
    public void GivenOkVar(string count, int sent)
    {
        authServer!.OkVarCount = System.Text.RegularExpressions.Regex.Unescape(count);
        authServer.OkVarSent = sent;
    }

    [Given("the auth server cannot be dialled")]
    public void GivenUndialable() => authServer!.Undialable = true;

    [Given(@"^the auth server refuses with ""([^""]*)""$")]
    public void GivenRefusing(string refusal) => authServer!.Refusal = refusal;

    [Given("the auth server hangs up on the ticket request")]
    public void GivenHangingUp() => authServer!.HangUpOnTicketRequest = true;

    [When(@"^""([^""]*)"" authenticates to it with the password ""([^""]*)""$")]
    public Task WhenAuthenticates(string user, string password)
    {
        passwords.Enqueue(password);
        return AuthenticateAsync(user);
    }

    [When(@"^""([^""]*)"" authenticates to it with the passwords ""([^""]*)"" and then ""([^""]*)""$")]
    public Task WhenAuthenticatesTwice(string user, string first, string second)
    {
        passwords.Enqueue(first);
        passwords.Enqueue(second);
        return AuthenticateAsync(user);
    }

    [When(@"^""([^""]*)"" authenticates to it with no password$")]
    public Task WhenNoPassword(string user)
    {
        passwords.Enqueue(null);
        return AuthenticateAsync(user);
    }

    [When(@"^the client is started with (.+)$")]
    public async Task WhenStartedWith(string argument)
    {
        written = new MemoryStream();
        var config = new P9AuthClientConfig("glenda", AskAsync, (_, _) => ValueTask.FromResult<Stream>(new MemoryStream()));
        (Stream? stream, P9AuthClientConfig? used) = argument switch
        {
            "a null stream" => ((Stream?)null, config),
            "a null configuration" => (written, null),
            "a blank user" => (written, config with { User = " " }),
            "a user of 28 bytes" => (written, config with { User = new string('u', 28) }),
            "no password source" => (written, config with { Password = null! }),
            "no way to dial the auth server" => (written, config with { DialAuthServer = null! }),
            _ => throw new ArgumentOutOfRangeException(nameof(argument), argument, null),
        };
        try
        {
            await P9AuthClient.AuthenticateAsync(stream!, used!, timeout.Token);
        }
        catch (ArgumentException caught)
        {
            error = caught;
        }
    }

    [Then(@"^the ticket names ""([^""]*)"" as the client's and the server's user, as authsrv's mkticket does$")]
    public void ThenTicketNames(string user)
    {
        error.Should().BeNull();
        result!.ClientUser.Should().Be(user);
        result.ServerUser.Should().Be(user);
    }

    [Then(@"^the server reports the client ""([^""]*)""$")]
    public void ThenServerReports(string user) => clientUser.Should().Be(user);

    [Then("the client and the server hold the same 256-byte secret")]
    public async Task ThenSameSecret()
    {
        byte[]? secret = await serving!.WaitAsync(timeout.Token);
        result!.Secret.Should().HaveCount(SessionSecret.Length).And.Equal(secret);
    }

    [Then("TLS-PSK keyed by that secret carries data both ways")]
    public async Task ThenTls()
    {
        byte[] secret = (await serving!.WaitAsync(timeout.Token))!;
        Task<Stream> accepting = P9PskTls.AcceptAsync(serverSocket!.GetStream(), secret, timeout.Token);
        Stream client = await P9PskTls.ConnectAsync(clientSocket!.GetStream(), result!.Secret, timeout.Token);
        Stream server = await accepting;
        await client.WriteAsync("to server"u8.ToArray(), timeout.Token);
        await client.FlushAsync(timeout.Token);
        await server.WriteAsync("to client"u8.ToArray(), timeout.Token);
        await server.FlushAsync(timeout.Token);
        (await ReadAsync(server, 9)).Should().Be("to server");
        (await ReadAsync(client, 9)).Should().Be("to client");
    }

    [Then("the auth server was asked AuthPAK and then AuthTreq on one call")]
    public void ThenAskedOnOneCall()
    {
        authServer!.Requests.Select(request => request.Type).Should().Equal(AuthMessageType.AuthPak, AuthMessageType.AuthTreq);
        authServer.Dialled.Should().Equal("fog");
    }

    [Then(@"^each request names the authid ""([^""]*)"", the domain ""([^""]*)"", and ""([^""]*)"" as hostid and uid$")]
    public void ThenRequestsName(string authid, string domain, string user)
    {
        foreach (TicketRequest request in authServer!.Requests)
        {
            request.AuthIdText.Should().Be(authid);
            request.AuthDomainText.Should().Be(domain);
            request.HostIdText.Should().Be(user);
            request.UserIdText.Should().Be(user);
        }
    }

    [Then("each request carries the server's challenge")]
    public void ThenRequestsCarryChallenge()
        => authServer!.Requests.Should().AllSatisfy(request => request.Challenge.Should().Equal(serverChallenge));

    [Then(@"^the password was asked for once, as ""([^""]*)""$")]
    public void ThenAskedOnce(string text)
    {
        prompts.Should().ContainSingle();
        prompts[0].Text.Should().Be(text);
        prompts[0].Mismatch.Should().BeFalse();
    }

    [Then("the password was asked for twice, the second time after a mismatch")]
    public void ThenAskedTwice() => prompts.Select(prompt => prompt.Mismatch).Should().Equal(false, true);

    [Then(@"^the client chose ""([^""]*)""$")]
    public void ThenChose(string expected) => choice.Should().Be(expected);

    [Then(@"^the client read ""OK"" after its choice: (yes|no)$")]
    public void ThenReadOk(string answer) => readOk.Should().Be(answer == "yes");

    [Then(@"^the client wrote its challenge: (yes|no)$")]
    public void ThenWroteChallengeOrNot(string answer) => wroteChallenge.Should().Be(answer == "yes");

    [Then(@"^the server's ticket names ""([^""]*)"" as both users and holds a key that is not all zeros$")]
    public void ThenServerTicket(string user)
    {
        serverTicket!.ClientUserText.Should().Be(user);
        serverTicket.ServerUserText.Should().Be(user);
        serverTicket.SessionKey.Should().Contain(b => b != 0);
    }

    [Then(@"^the outcome is ""([^""]*)""$")]
    public void ThenOutcome(string outcome)
    {
        if (outcome == "authenticated")
        {
            error.Should().BeNull();
            result.Should().NotBeNull();
        }
        else
        {
            ThenFails(outcome);
        }
    }

    [Then(@"^its message starts ""([^""]*)""$")]
    public void ThenMessageStarts(string start) => error!.Message.Should().StartWith(start);

    [Then("the client wrote its challenge next")]
    public void ThenWroteChallenge() => wroteChallenge.Should().BeTrue();

    [Then("the client wrote no challenge")]
    public void ThenNoChallenge() => wroteChallenge.Should().BeFalse();

    [Then(@"^authentication fails with ""([^""]*)""$")]
    public void ThenFails(string message)
    {
        result.Should().BeNull();
        error.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Be(Expand(message));
    }

    [Then(@"^it fails with (an argument-null error|an argument error) for ""([^""]*)""$")]
    public void ThenArgumentError(string kind, string parameter)
    {
        Type expected = kind == "an argument-null error" ? typeof(ArgumentNullException) : typeof(ArgumentException);
        error.Should().BeOfType(expected);
        ((ArgumentException)error!).ParamName.Should().Be(parameter);
    }

    [Then("nothing has been written to the server")]
    public void ThenNothingWritten() => written!.Length.Should().Be(0);

    public void Dispose()
    {
        clientSocket?.Dispose();
        serverSocket?.Dispose();
        timeout.Dispose();
    }

    private async Task AuthenticateAsync(string user)
    {
        (clientSocket, serverSocket) = await Loopback.PairAsync(timeout.Token);
        Stream serverStream = serverSocket.GetStream();
        serving = Task.Run(async () =>
        {
            try
            {
                return await server!(serverStream);
            }
            catch (Exception caught) when (caught is IOException or EndOfStreamException or InvalidOperationException)
            {
                // A server that refuses hangs up, so the client reads the end rather than waiting.
                serverSocket.Close();
                return null;
            }
            catch
            {
                serverSocket.Close();
                throw;
            }
        });
        var config = new P9AuthClientConfig(user, AskAsync, authServer!.DialAsync);
        try
        {
            result = await P9AuthClient.AuthenticateAsync(clientSocket.GetStream(), config, timeout.Token);
        }
        catch (InvalidOperationException caught)
        {
            error = caught;
            clientSocket.Client.Shutdown(SocketShutdown.Send);
            await serving.WaitAsync(timeout.Token);
        }

        await authServer.EndedAsync().WaitAsync(timeout.Token);
    }

    private ValueTask<string?> AskAsync(PasswordPrompt prompt, CancellationToken cancellationToken)
    {
        prompts.Add(prompt);
        return ValueTask.FromResult(passwords.Count > 0 ? passwords.Dequeue() : null);
    }

    // p9any's offer, the choice read, OK or another answer after a v.2 offer, and then whether the
    // client's challenge comes; the call is then hung up.
    private async Task<byte[]?> ScriptedP9anyAsync(Stream stream, string offer, string answer, bool hangUp)
    {
        await CStringEncoding.WriteAsync(stream, offer, timeout.Token);
        if (hangUp)
        {
            serverSocket!.Client.Shutdown(SocketShutdown.Send);
            return null;
        }

        choice = await CStringEncoding.ReadAsync(stream, 4096, timeout.Token);
        if (offer.StartsWith("v.2 ", StringComparison.Ordinal))
        {
            await CStringEncoding.WriteAsync(stream, answer, timeout.Token);
            readOk = true;
        }

        byte[] challenge = new byte[Dp9ikConstants.ChallengeLength];
        wroteChallenge = await stream.ReadAtLeastAsync(challenge, challenge.Length, throwOnEndOfStream: false, timeout.Token) == challenge.Length;
        serverSocket!.Client.Shutdown(SocketShutdown.Send);
        return null;
    }

    // A server whose own steps are the library's, as P9AuthProtocol runs them, but whose answer to
    // the proof is the scenario's; it returns the server's random when it answers with one.
    private async Task<byte[]?> ScriptedDp9ikAsync(Stream stream, string domain, string authid, string password, Func<Ticket, byte[], Task<byte[]?>> answer)
    {
        AuthKey key = AuthKey.FromPassword(password);
        key.ApplyAuthPakHash(authid);
        await CStringEncoding.WriteAsync(stream, $"dp9ik@{domain}", timeout.Token);
        choice = await CStringEncoding.ReadAsync(stream, 4096, timeout.Token);
        byte[] clientChallenge = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.ChallengeLength, timeout.Token);
        serverChallenge = RandomNumberGenerator.GetBytes(Dp9ikConstants.ChallengeLength);
        var request = new TicketRequest(AuthMessageType.AuthPak);
        request.SetAuthId(authid);
        request.SetAuthDomain(domain);
        request.SetChallenge(serverChallenge);
        var state = new AuthPakState();
        await stream.WriteAsync((byte[])[.. request.Marshal(), .. state.CreatePublicValue(key, isClient: true)], timeout.Token);
        state.Finish(key, await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.PakPublicValueLength, timeout.Token));
        byte[] proof = await StreamExtensions.ReadExactlyAsync(stream, Dp9ikConstants.MaxTicketLength + Dp9ikConstants.MaxAuthenticatorLength, timeout.Token);
        Ticket.TryUnmarshal(key, proof, out Ticket? ticket, out _).Should().BeTrue();
        Authenticator.TryUnmarshal(ticket!, proof.AsSpan(Dp9ikConstants.MaxTicketLength), out Authenticator? authenticator, out _).Should().BeTrue();
        ticket!.Type.Should().Be(AuthMessageType.AuthTs);
        ticket.Challenge.Should().Equal(serverChallenge);
        authenticator!.Type.Should().Be(AuthMessageType.AuthAc);
        authenticator.Challenge.Should().Equal(serverChallenge);
        clientUser = ticket.ClientUserText;
        serverTicket = ticket;
        byte[]? serverRandom = await answer(ticket, clientChallenge);
        return serverRandom is null ? null : SessionSecret.Derive(authenticator.Random, serverRandom, ticket.SessionKey);
    }

    // "text followed by N y": the text and then N y's.
    private static string Expand(string text)
    {
        System.Text.RegularExpressions.Match match = System.Text.RegularExpressions.Regex.Match(text, @"^(.*) followed by (\d+) y$");
        return match.Success ? match.Groups[1].Value + new string('y', int.Parse(match.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture)) : text;
    }

    private async Task<string> ReadAsync(Stream stream, int length)
    {
        byte[] buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, timeout.Token);
        return Encoding.UTF8.GetString(buffer);
    }
}
