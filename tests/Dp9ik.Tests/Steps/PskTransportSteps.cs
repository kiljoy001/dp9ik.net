using System.Net;
using System.Net.Sockets;
using System.Text;
using Dp9ik.P9Auth;
using Dp9ik.Tests.Support;
using Dp9ik.Tls;
using FluentAssertions;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Reqnroll;

namespace Dp9ik.Tests.Steps;

[Binding]
[Scope(Feature = "The dp9ik session secret keys a TLS-PSK channel that 9front accepts")]
public sealed class PskTransportSteps : IDisposable
{
    private static readonly Dictionary<string, int> Suites = new(StringComparer.Ordinal)
    {
        ["TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"] = CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
        ["TLS_PSK_WITH_AES_128_CBC_SHA256"] = CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
        ["TLS_PSK_WITH_AES_128_CBC_SHA"] = CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
        ["TLS_PSK_WITH_AES_256_GCM_SHA384"] = CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384,
        ["a certificate-based cipher suite"] = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    };

    private readonly CancellationTokenSource timeout = new(TimeSpan.FromSeconds(2));
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly byte[] secret = RandomBytes(256);
    private Task<string>? server;
    private ProbeClient? probe;
    private Exception? clientError;
    private string? clientReceived;
    private string? authenticatedUser;
    private readonly MemoryStream written = new();

    [Given("a PSK server keyed with a dp9ik session secret")]
    public void GivenServer()
    {
        listener.Start();
        server = Task.Run(async () =>
        {
            using TcpClient socket = await listener.AcceptTcpClientAsync(timeout.Token);
            Stream channel = await P9PskTls.AcceptAsync(socket.GetStream(), secret, timeout.Token);
            return await ExchangeAsync(channel, "from server");
        });
    }

    [When(@"^a TLS 1.2 client offering only (\S+) connects with identity ""(.*)"" and the same secret$")]
    public Task WhenClientOffers(string suite, string identity) => ConnectProbeAsync(identity, secret, [Suites[suite]], ProtocolVersion.TLSv12);

    [When(@"^a client connects with identity ""(.*)"" and a different secret$")]
    public Task WhenWrongSecret(string identity) => ConnectProbeAsync(identity, RandomBytes(256), AllSuites(), ProtocolVersion.TLSv12);

    [When(@"^a client connects with identity ""(.*)"" and the same secret$")]
    public Task WhenWrongIdentity(string identity) => ConnectProbeAsync(identity, secret, AllSuites(), ProtocolVersion.TLSv12);

    [When(@"^a client offers only (.+)$")]
    public Task WhenClientOffersOnly(string offer)
        => offer == "TLS 1.3"
            ? ConnectProbeAsync(P9PskTls.Identity, secret, [CipherSuite.TLS_AES_128_GCM_SHA256], ProtocolVersion.TLSv13)
            : ConnectProbeAsync(P9PskTls.Identity, secret, [Suites[offer]], ProtocolVersion.TLSv12);

    [Then(@"^the handshake completes with (\S+)$")]
    public void ThenCompletes(string suite)
    {
        clientError.Should().BeNull();
        probe!.Selected.Should().Be(Suites[suite]);
    }

    [Then("bytes written by either side are read by the other")]
    public async Task ThenBytesFlow()
    {
        clientReceived.Should().Be("from server");
        (await server!.WaitAsync(timeout.Token)).Should().Be("from client");
    }

    [Then("the handshake fails and no application data is exchanged")]
    public async Task ThenRefused()
    {
        await ThenHandshakeFails();
        clientReceived.Should().BeNull();
    }

    [Then("the handshake fails")]
    public async Task ThenHandshakeFails()
    {
        clientError.Should().NotBeNull();
        Func<Task> serverRun = () => server!.WaitAsync(timeout.Token);
        await serverRun.Should().ThrowAsync<Exception>();
    }

    [Given("a server that runs the dp9ik handshake and then TLS-PSK with its session secret")]
    public void GivenAuthenticatingServer()
    {
        listener.Start();
        server = Task.Run(async () =>
        {
            using TcpClient socket = await listener.AcceptTcpClientAsync(timeout.Token);
            NetworkStream transport = socket.GetStream();
            P9AuthResult result = await P9AuthProtocol.AuthenticateAsync(transport, new AuthServerConfig("example.test", "bootes", "testpassword"), timeout.Token);
            authenticatedUser = result.User;
            Stream channel = await P9PskTls.AcceptAsync(transport, result.Secret, timeout.Token);
            return await ExchangeAsync(channel, "from server");
        });
    }

    [When("a client authenticates with dp9ik, derives the same secret and opens TLS-PSK")]
    public async Task WhenClientAuthenticates()
    {
        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, Port, timeout.Token);
        NetworkStream transport = socket.GetStream();
        Dp9ikTestPeer.PeerResult peer = await Dp9ikTestPeer.RunAsync(transport, new AuthServerConfig("example.test", "bootes", "testpassword"), "scott", timeout.Token);
        Stream channel = await P9PskTls.ConnectAsync(transport, SessionSecret.Derive(peer.ClientRandom, peer.ServerRandom, peer.TicketKey), timeout.Token);
        clientReceived = await ExchangeAsync(channel, "from client");
    }

    [Then("the server reports the client's user")]
    public async Task ThenServerReportsUser()
    {
        await server!.WaitAsync(timeout.Token);
        authenticatedUser.Should().Be("scott");
    }

    [When(@"^the (server|client) is opened with (a null transport|a null secret|an empty secret)$")]
    public void WhenOpenedWith(string side, string argument)
    {
        Stream? transport = argument == "a null transport" ? null : written;
        byte[]? key = argument switch
        {
            "a null secret" => null,
            "an empty secret" => [],
            _ => secret,
        };
        Func<Task<Stream>> open = side == "server"
            ? () => P9PskTls.AcceptAsync(transport!, key!, timeout.Token)
            : () => P9PskTls.ConnectAsync(transport!, key!, timeout.Token);
        try
        {
            open().GetAwaiter().GetResult();
        }
        catch (Exception caught)
        {
            clientError = caught;
        }
    }

    [Then(@"^it fails with (an argument-null error|an argument error) for ""(.*)""$")]
    public void ThenArgumentFailure(string kind, string parameter)
    {
        if (kind == "an argument-null error")
        {
            clientError.Should().BeOfType<ArgumentNullException>().Which.ParamName.Should().Be(parameter);
        }
        else
        {
            clientError.Should().BeOfType<ArgumentException>().Which.ParamName.Should().Be(parameter);
            clientError!.Message.Should().StartWith("The PSK is the dp9ik session secret.");
        }
    }

    [Then("nothing has been written to the transport")]
    public void ThenTransportUntouched() => written.Length.Should().Be(0);

    [Then("data crosses the encrypted channel in both directions")]
    public Task ThenDataCrosses() => ThenBytesFlow();

    public void Dispose()
    {
        listener.Stop();
        listener.Dispose();
        timeout.Dispose();
        written.Dispose();
    }

    private int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

    private static int[] AllSuites() => [.. Suites.Values.Take(3)];

    private async Task ConnectProbeAsync(string identity, byte[] key, int[] suites, ProtocolVersion version)
    {
        var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, Port, timeout.Token);
        probe = new ProbeClient(new BcTlsCrypto(new SecureRandom()), new BasicTlsPskIdentity(identity, key), suites, version);
        try
        {
            var protocol = new TlsClientProtocol(socket.GetStream());
            await Task.Run(() => protocol.Connect(probe), timeout.Token);
            clientReceived = await ExchangeAsync(protocol.Stream, "from client");
        }
        catch (Exception caught) when (caught is TlsFatalAlert or TlsFatalAlertReceived or IOException or TlsException)
        {
            clientError = caught;
            socket.Dispose();
        }
    }

    /// <summary>Writes one line and reads the peer's line.</summary>
    private async Task<string> ExchangeAsync(Stream channel, string message)
    {
        byte[] outgoing = Encoding.ASCII.GetBytes(message + "\n");
        await channel.WriteAsync(outgoing, timeout.Token);
        await channel.FlushAsync(timeout.Token);
        var received = new List<byte>();
        var one = new byte[1];
        while (await channel.ReadAsync(one, timeout.Token) == 1 && one[0] != '\n')
        {
            received.Add(one[0]);
        }

        return Encoding.ASCII.GetString(received.ToArray());
    }

    private static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }

    private sealed class ProbeClient(TlsCrypto crypto, TlsPskIdentity identity, int[] suites, ProtocolVersion version)
        : PskTlsClient(crypto, identity)
    {
        internal int Selected { get; private set; } = -1;

        public override void NotifySelectedCipherSuite(int selectedCipherSuite)
        {
            Selected = selectedCipherSuite;
            base.NotifySelectedCipherSuite(selectedCipherSuite);
        }

        protected override int[] GetSupportedCipherSuites() => suites;

        protected override ProtocolVersion[] GetSupportedVersions() => version.Only();
    }
}
