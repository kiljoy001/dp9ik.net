using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using Dp9ik.P9Auth;
using Dp9ik.Tests.Support;
using Dp9ik.Tls;
using FluentAssertions;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Reqnroll;

namespace Dp9ik.Tests.Steps;

[Binding]
[Scope(Feature = "dp9ik runs in managed code and matches 9front")]
public sealed class ManagedDp9ikSteps
{
    private const int Cases = 24;
    private static readonly BigInteger P = BigInteger.Pow(2, 448) - BigInteger.Pow(2, 224) - 1;
    private readonly Random random = new(9001);
    private readonly List<string> passwords = new();
    private readonly List<string> users = new();
    private string password = string.Empty;
    private (byte[] Server, byte[] Client) pakKeys;
    private AuthKey? serverKey;
    private AuthPakState? serverState;
    private string referenceServerState = string.Empty;
    private Exception? finishError;
    private byte[]? sealedTicket;
    private byte[]? secondSealedTicket;
    private AuthKey? ticketKey;
    private P9AuthResult? handshake;
    private Dp9ikTestPeer.PeerResult? peer;
    private TicketEncryptionForm form = TicketEncryptionForm.Form1;
    private int? tamperedByte;
    private readonly List<BigInteger> chosenScalars = new();
    private readonly List<(byte[] Managed, byte[] Reference)> chosenKeys = new();
    private int boundaryReferenceExit;
    private byte[]? boundaryReferenceKey;
    private AuthServerConfig config = new("example.test", "bootes", "testpassword");

    [Given("generated passwords, including empty, longer than 8 bytes and non-ASCII")]
    public void GivenPasswords()
    {
        passwords.AddRange(["", "a", "12345678", "123456789", "testpassword", "pässwörd-über-lang", "日本語のパスワード"]);
        while (passwords.Count < Cases) passwords.Add(RandomText(random.Next(1, 40)));
    }

    [Given(@"^a generated password of (\d+) bytes$")]
    public void GivenPasswordOfLength(int length) => passwords.Add(RandomText(length));

    [When("each is turned into an Authkey by the library and by the reference")]
    public static void WhenKeysDerived()
    {
    }

    [Then("the DES and AES keys are identical")]
    public void ThenKeysIdentical()
    {
        foreach (string candidate in passwords)
            AuthKey.FromPassword(candidate).RawHex.Should().Be(ReferenceTool.Run("passtokey", candidate)[0], $"password '{candidate}'");
    }

    [Given(@"^the password ""(.*)""$")]
    public void GivenPassword(string value) => password = value;

    [When("the library derives its AES key")]
    public static void WhenAesKeyDerived()
    {
    }

    [Then(@"^it equals PBKDF2-HMAC-SHA1 with salt ""(.*)"", (\d+) iterations and (\d+) bytes$")]
    public void ThenPbkdf2(string salt, int iterations, int length)
    {
        var generator = new Pkcs5S2ParametersGenerator(new Sha1Digest());
        generator.Init(Encoding.UTF8.GetBytes(password), Encoding.ASCII.GetBytes(salt), iterations);
        byte[] expected = ((KeyParameter)generator.GenerateDerivedMacParameters(length * 8)).GetKey();
        AuthKey.FromPassword(password).AesKey.Should().Equal(expected);
    }

    [Given("generated passwords and user names")]
    public void GivenPasswordsAndUsers()
    {
        GivenPasswords();
        users.AddRange(["glenda", "bootes", "", "a-very-long-user-name-beyond-28", "ユーザー"]);
        while (users.Count < passwords.Count) users.Add(RandomText(random.Next(1, 20)));
    }

    [When("the library and the reference apply the AuthPAK hash")]
    public static void WhenPakHashed()
    {
    }

    [Then("the 448-byte PM and PN point encodings are identical")]
    public void ThenPakHashesIdentical()
    {
        for (int index = 0; index < passwords.Count; index++)
        {
            AuthKey key = AuthKey.FromPassword(passwords[index]);
            key.ApplyAuthPakHash(users[index]);
            string reference = ReferenceTool.Run("authpak_hash", ReferenceTool.Run("passtokey", passwords[index])[0], users[index])[0];
            key.RawHex.Should().Be(reference, $"password '{passwords[index]}', user '{users[index]}'");
        }
    }

    [When("the library builds each Authkey from the reference DES and AES keys and applies the AuthPAK hash")]
    public static void WhenBuiltFromKeys()
    {
    }

    [Then("its DES key, AES key and PAK hash equal the reference passtokey and authpak_hash")]
    public void ThenBuiltFromKeysMatches()
    {
        for (int index = 0; index < passwords.Count; index++)
        {
            byte[] reference = Convert.FromHexString(
                ReferenceTool.Run("authpak_hash", ReferenceTool.Run("passtokey", passwords[index])[0], users[index])[0]);
            byte[] des = reference[..Dp9ikConstants.DesKeyLength];
            byte[] aes = reference.AsSpan(Dp9ikConstants.DesKeyLength, Dp9ikConstants.AesKeyLength).ToArray();
            AuthKey key = AuthKey.FromKeys(des, aes);
            key.ApplyAuthPakHash(users[index]);
            key.DesKey.Should().Equal(des);
            key.AesKey.Should().Equal(aes);
            key.PakHash.Should().Equal(reference[^Dp9ikConstants.PakHashLength..], $"user '{users[index]}'");
        }
    }

    [Given("a password and user shared by both sides")]
    public void GivenSharedPassword()
    {
        password = "shared secret";
        users.Add("glenda");
    }

    [When(@"^the (managed|reference) client and the (managed|reference) server exchange AuthPAK public values$")]
    public void WhenPakExchanged(string client, string server)
    {
        for (int round = 0; round < 4; round++)
            pakKeys = Exchange(client == "managed", server == "managed", password, password);
    }

    [Then("both derive the same 32-byte PAK key")]
    public void ThenSamePakKey()
    {
        pakKeys.Client.Should().HaveCount(32);
        pakKeys.Client.Should().Equal(pakKeys.Server);
        pakKeys.Client.Should().NotEqual(new byte[32]);
    }

    [Given("a client and a server whose passwords differ")]
    public void GivenDifferentPasswords() => users.Add("glenda");

    [When("they exchange AuthPAK public values")]
    public void WhenDifferentPasswordsExchange() => pakKeys = Exchange(true, true, "client password", "server password");

    [Then("their PAK keys differ")]
    public void ThenPakKeysDiffer() => pakKeys.Client.Should().NotEqual(pakKeys.Server);

    [Given("a server that has sent its AuthPAK public value")]
    public void GivenServerSent()
    {
        serverKey = Key("server password", "glenda");
        byte[] scalar = BigEndian(BigInteger.Pow(2, 447) + 0x5EED);
        serverState = new AuthPakState();
        byte[] y = serverState.CreatePublicValue(serverKey, isClient: false, scalar);
        referenceServerState = NativeState(isClient: false, scalar, y);
    }

    [Given("chosen scalars including 1, p-1 and values with the top scalar bit set")]
    public void GivenChosenScalars()
    {
        chosenScalars.AddRange([BigInteger.One, P - 1, BigInteger.Pow(2, 447), BigInteger.Pow(2, 447) + 0x1234567]);
        while (chosenScalars.Count < 10)
        {
            var bytes = new byte[56];
            random.NextBytes(bytes);
            bytes[0] |= 0x80;
            BigInteger candidate = new(bytes, isUnsigned: true, isBigEndian: true);
            if (candidate < P) chosenScalars.Add(candidate);
        }
    }

    [When("the library and the reference each finish an exchange from the same scalar and peer value")]
    public void WhenChosenScalarsFinish()
    {
        foreach (BigInteger chosen in chosenScalars)
        {
            AuthKey key = Key("chosen scalar", "glenda");
            string keyHex = key.RawHex;
            byte[] scalar = BigEndian(chosen);
            var state = new AuthPakState();
            byte[] y = state.CreatePublicValue(key, isClient: true, scalar);
            // The state owns the scalar and clears it when it finishes.
            string native = NativeState(isClient: true, scalar, y);
            byte[] peer = Convert.FromHexString(ReferenceTool.Run("authpak_new", keyHex, "0")[1]);
            state.Finish(key, peer);
            byte[] reference = Convert.FromHexString(ReferenceTool.Run("authpak_finish", native, keyHex, Convert.ToHexStringLower(peer))[0]);
            chosenKeys.Add((key.SharedKey, reference.AsSpan(Dp9ikConstants.DesKeyLength + Dp9ikConstants.AesKeyLength, Dp9ikConstants.PakKeyLength).ToArray()));
        }
    }

    [Then("their PAK keys are identical")]
    public void ThenChosenKeysIdentical()
    {
        chosenKeys.Should().HaveCount(chosenScalars.Count);
        string[] mismatched = chosenKeys.Select((pair, index) => (pair, index))
            .Where(entry => !entry.pair.Managed.SequenceEqual(entry.pair.Reference))
            .Select(entry => chosenScalars[entry.index].ToString("X", System.Globalization.CultureInfo.InvariantCulture)).ToArray();
        mismatched.Should().BeEmpty();
    }

    [When(@"^it receives the encoding (\S+) as the client's public value$")]
    public void WhenReceivesBoundary(string value)
    {
        BigInteger encoded = value switch
        {
            "(p-1)/2" => (P - 1) / 2,
            "(p+1)/2" => (P + 1) / 2,
            _ => BigInteger.Parse(value, System.Globalization.CultureInfo.InvariantCulture),
        };
        byte[] y = BigEndian(encoded);
        string keyHex = serverKey!.RawHex;
        boundaryReferenceExit = ReferenceTool.ExitCode("authpak_finish", referenceServerState, keyHex, Convert.ToHexStringLower(y));
        boundaryReferenceKey = boundaryReferenceExit == 0
            ? Convert.FromHexString(ReferenceTool.Run("authpak_finish", referenceServerState, keyHex, Convert.ToHexStringLower(y))[0])
                .AsSpan(Dp9ikConstants.DesKeyLength + Dp9ikConstants.AesKeyLength, Dp9ikConstants.PakKeyLength).ToArray()
            : null;
        try
        {
            serverState!.Finish(serverKey, y);
        }
        catch (InvalidOperationException caught)
        {
            finishError = caught;
        }
    }

    [Then("the library accepts or rejects it as the reference does, with the same key when accepted")]
    public void ThenBoundaryMatches()
    {
        if (boundaryReferenceKey is null)
        {
            boundaryReferenceExit.Should().Be(3);
            finishError.Should().NotBeNull();
        }
        else
        {
            finishError.Should().BeNull();
            serverKey!.SharedKey.Should().Equal(boundaryReferenceKey);
        }
    }

    [When(@"^it receives (an encoding greater than \(p-1\)/2|a value that is not on the curve) as the client's public value$")]
    public void WhenReceives(string value)
    {
        byte[] y = value.StartsWith("an encoding greater", StringComparison.Ordinal) ? BigEndian(P - 1) : OffCurveValue();
        if (value.StartsWith("a value that is not", StringComparison.Ordinal))
            ReferenceTool.ExitCode("authpak_finish", referenceServerState, serverKey!.RawHex, Convert.ToHexStringLower(y)).Should().Be(3);
        try
        {
            serverState!.Finish(serverKey!, y);
        }
        catch (Exception caught)
        {
            finishError = caught;
        }
    }

    [Then("finishing the exchange fails without producing a key")]
    public void ThenFinishFails()
    {
        finishError.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Be("AuthPAK public value rejected.");
        serverKey!.SharedKey.Should().Equal(new byte[32]);
    }

    [Given(@"^a generated (ticket|authenticator) and a 32-byte key$")]
    public void GivenGeneratedMessage(string message) => ticketKey = KeyWithPakKey();

    [Given(@"^a generated form 0 (ticket|authenticator) and a DES key$")]
    public void GivenGeneratedFormZero(string message)
    {
        form = TicketEncryptionForm.Form0;
        ticketKey = AuthKey.FromPassword(RandomText(12));
    }

    [Then(@"^the opened (ticket|authenticator) equals the original$")]
    public static void ThenOpenedEqualsOriginal(string message)
    {
        // Each round of the seal-and-open step already compares the opened message with the original.
        message.Should().NotBeEmpty();
    }

    [When(@"^the (managed|reference) seals it and the (managed|reference) opens it$")]
    public void WhenSealedAndOpened(string sealer, string opener)
    {
        AuthKey key = ticketKey!;
        for (int round = 0; round < Cases; round++)
        {
            Ticket ticket = GeneratedTicket();
            byte[] wire = sealer == "managed"
                ? ticket.Marshal(key)
                : Convert.FromHexString(ReferenceTool.Run("ticket_marshal", key.RawHex, Convert.ToHexStringLower(ticket.ToNativeLayout()))[0]);
            if (opener == "managed")
            {
                Ticket.TryUnmarshal(key, wire, out Ticket? opened, out int consumed).Should().BeTrue();
                consumed.Should().Be(wire.Length);
                opened!.ToNativeLayout().Should().Equal(ticket.ToNativeLayout());
            }
            else
            {
                string[] opened = ReferenceTool.Run("ticket_unmarshal", key.RawHex, Convert.ToHexStringLower(wire));
                int.Parse(opened[0], System.Globalization.CultureInfo.InvariantCulture).Should().Be(wire.Length);
                Convert.FromHexString(opened[1]).Should().Equal(ticket.ToNativeLayout());
            }

            Authenticator authenticator = GeneratedAuthenticator();
            byte[] authWire = sealer == "managed"
                ? authenticator.Marshal(ticket)
                : Convert.FromHexString(ReferenceTool.Run("authenticator_marshal",
                    Convert.ToHexStringLower(ticket.ToNativeLayout()), Convert.ToHexStringLower(authenticator.ToNativeLayout()))[0]);
            if (opener == "managed")
            {
                Authenticator.TryUnmarshal(ticket, authWire, out Authenticator? opened, out _).Should().BeTrue();
                opened!.ToNativeLayout().Should().Equal(authenticator.ToNativeLayout());
            }
            else
            {
                string[] opened = ReferenceTool.Run("authenticator_unmarshal",
                    Convert.ToHexStringLower(ticket.ToNativeLayout()), Convert.ToHexStringLower(authWire));
                Convert.FromHexString(opened[1]).Should().Equal(authenticator.ToNativeLayout());
            }
        }
    }

    [Given("a sealed ticket")]
    public void GivenSealedTicket()
    {
        ticketKey = KeyWithPakKey();
        sealedTicket = GeneratedTicket().Marshal(ticketKey);
    }

    [When("any single byte of it is changed")]
    public static void WhenTampered()
    {
    }

    [Then("it never opens as a form 1 ticket")]
    public void ThenNeverOpensAsForm1()
    {
        for (int index = 0; index < sealedTicket!.Length; index++)
        {
            byte[] tampered = sealedTicket.ToArray();
            tampered[index] ^= (byte)(1 + (index % 255));
            // A changed signature makes convM2T read the bytes as a form 0 ticket, which by chance can
            // decrypt to a ticket type, as in 9front; dp9ik servers refuse form 0 tickets.
            if (Ticket.TryUnmarshal(ticketKey!, tampered, out Ticket? opened, out _))
                opened!.Form.Should().Be(TicketEncryptionForm.Form0, $"byte {index} was changed");
            else
                opened.Should().BeNull();
        }
    }

    [Given("two tickets sealed in a row by the library")]
    public void GivenTwoTickets()
    {
        ticketKey = KeyWithPakKey();
        sealedTicket = GeneratedTicket().Marshal(ticketKey);
        secondSealedTicket = GeneratedTicket().Marshal(ticketKey);
    }

    [Then(@"^each begins with the 8-byte signature ""(.*)""$")]
    public void ThenSignature(string signature)
    {
        Encoding.ASCII.GetString(sealedTicket!, 0, 8).Should().Be(signature);
        Encoding.ASCII.GetString(secondSealedTicket!, 0, 8).Should().Be(signature);
    }

    [Then("the second 4-byte little-endian counter is greater than the first")]
    public void ThenCounterIncreases()
        => BitConverter.ToUInt32(secondSealedTicket!, 8).Should().BeGreaterThan(BitConverter.ToUInt32(sealedTicket!, 8));

    [Given("a completed dp9ik handshake between a managed server and a client")]
    public async Task GivenHandshake() => (handshake, peer) = await HandshakeAsync();

    [Then(@"^the server's session secret is (\d+) bytes$")]
    public void ThenSecretLength(int length) => handshake!.Secret.Should().HaveCount(length);

    [Then(@"^it equals HKDF-SHA256 with the two nonces as salt, info ""(.*)"" and the ticket key$")]
    public void ThenSecretIsHkdf(string info)
    {
        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(peer!.TicketKey, [.. peer.ClientRandom, .. peer.ServerRandom], Encoding.ASCII.GetBytes(info)));
        var expected = new byte[256];
        hkdf.GenerateBytes(expected, 0, expected.Length);
        handshake!.Secret.Should().Equal(expected);
    }

    [Then("the client derives the same secret")]
    public void ThenClientSecret()
        => SessionSecret.Derive(peer!.ClientRandom, peer.ServerRandom, peer.TicketKey).Should().Equal(handshake!.Secret);

    [Given(@"^a client that presents a valid form 0 \(DES\) ticket and authenticator$")]
    public void GivenFormZeroClient() => form = TicketEncryptionForm.Form0;

    [Given(@"^a client whose proof has one changed byte in its (ticket|authenticator)$")]
    public void GivenTamperedProof(string part)
        => tamperedByte = (part == "ticket" ? 0 : Dp9ikConstants.MaxTicketLength) + 20;

    [When("it completes the dp9ik exchange with a managed server")]
    public async Task WhenFormZeroExchange()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var timeout = new CancellationTokenSource(TestTimeouts.Network);
        listener.Start();
        Task<P9AuthResult> server = Task.Run(async () =>
        {
            using TcpClient socket = await listener.AcceptTcpClientAsync(timeout.Token);
            await using NetworkStream stream = socket.GetStream();
            return await P9AuthProtocol.AuthenticateAsync(stream, config, timeout.Token);
        });
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, timeout.Token);
        await using NetworkStream clientStream = client.GetStream();
        Action<byte[]>? tamper = tamperedByte is int index ? proof => proof[index] ^= 0x5A : null;
        Func<Task> clientRun = () => Dp9ikTestPeer.RunAsync(clientStream, config, "scott", timeout.Token, form, tamper);
        await clientRun.Should().ThrowAsync<Exception>();
        try { handshake = await server; } catch (Exception caught) { finishError = caught; }
    }

    [Then("the server rejects the proof as factotum does for dp9ik")]
    public void ThenFormZeroRejected()
        => finishError.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Be("dp9ik requires a form 1 ticket.");

    [Then(@"^the server fails with ""(.*)""$")]
    public void ThenServerFails(string message)
        => finishError.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Be(message);

    [Then("no session secret is produced")]
    public void ThenNoSecret() => handshake.Should().BeNull();

    [Given("the Dp9ik, Dp9ik.P9Auth and Dp9ik.Tls assemblies")]
    public static void GivenAssemblies()
    {
    }

    [Then("none of them references System.Diagnostics.Process")]
    public void ThenNoProcessReference()
    {
        foreach (var assembly in new[] { typeof(AuthKey).Assembly, typeof(P9AuthProtocol).Assembly, typeof(P9PskTls).Assembly })
        {
            using var stream = File.OpenRead(assembly.Location);
            using var pe = new PEReader(stream);
            MetadataReader metadata = pe.GetMetadataReader();
            IEnumerable<string> references = metadata.TypeReferences.Select(handle => metadata.GetTypeReference(handle))
                .Select(type => $"{metadata.GetString(type.Namespace)}.{metadata.GetString(type.Name)}");
            references.Should().NotContain(name => name.StartsWith("System.Diagnostics.Process", StringComparison.Ordinal),
                $"{assembly.GetName().Name} must not start processes");
        }
    }

    [Then("a complete dp9ik handshake still succeeds")]
    public async Task ThenHandshakeSucceeds() => (await HandshakeAsync()).Result.User.Should().Be("scott");

    private async Task<(P9AuthResult Result, Dp9ikTestPeer.PeerResult Peer)> HandshakeAsync()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var timeout = new CancellationTokenSource(TestTimeouts.Network);
        listener.Start();
        Task<P9AuthResult> server = Task.Run(async () =>
        {
            using TcpClient socket = await listener.AcceptTcpClientAsync(timeout.Token);
            await using NetworkStream stream = socket.GetStream();
            return await P9AuthProtocol.AuthenticateAsync(stream, config, timeout.Token);
        });
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, timeout.Token);
        await using NetworkStream clientStream = client.GetStream();
        Dp9ikTestPeer.PeerResult result = await Dp9ikTestPeer.RunAsync(clientStream, config, "scott", timeout.Token);
        return (await server, result);
    }

    private (byte[] Server, byte[] Client) Exchange(bool managedClient, bool managedServer, string clientPassword, string serverPassword)
    {
        AuthKey clientKey = Key(clientPassword, users[0]);
        AuthKey serverSideKey = Key(serverPassword, users[0]);
        (Func<byte[], byte[]> finishClient, byte[] clientY) = Start(clientKey, managedClient, isClient: true);
        (Func<byte[], byte[]> finishServer, byte[] serverY) = Start(serverSideKey, managedServer, isClient: false);
        return (finishServer(clientY), finishClient(serverY));
    }

    private static (Func<byte[], byte[]> Finish, byte[] Y) Start(AuthKey key, bool managed, bool isClient)
    {
        if (managed)
        {
            var state = new AuthPakState();
            byte[] y = state.CreatePublicValue(key, isClient);
            return (peerY =>
            {
                state.Finish(key, peerY);
                return key.SharedKey;
            }, y);
        }

        string[] created = ReferenceTool.Run("authpak_new", key.RawHex, isClient ? "1" : "0");
        string keyHex = key.RawHex;
        return (peerY => Convert.FromHexString(ReferenceTool.Run("authpak_finish", created[0], keyHex, Convert.ToHexStringLower(peerY))[0])
            .AsSpan(Dp9ikConstants.DesKeyLength + Dp9ikConstants.AesKeyLength, Dp9ikConstants.PakKeyLength).ToArray(), Convert.FromHexString(created[1]));
    }

    private static AuthKey Key(string secret, string user)
    {
        AuthKey key = AuthKey.FromPassword(secret);
        key.ApplyAuthPakHash(user);
        return key;
    }

    private AuthKey KeyWithPakKey()
    {
        AuthKey key = AuthKey.FromPassword("ticket key");
        byte[] raw = Convert.FromHexString(key.RawHex);
        random.NextBytes(raw.AsSpan(Dp9ikConstants.DesKeyLength + Dp9ikConstants.AesKeyLength, Dp9ikConstants.PakKeyLength));
        key.Replace(raw);
        return key;
    }

    /// <summary>The smallest Decaf encoding the reference rejects as off-curve.</summary>
    private byte[] OffCurveValue()
    {
        for (int s = 2; ; s++)
        {
            byte[] candidate = BigEndian(s);
            if (ReferenceTool.ExitCode("authpak_finish", referenceServerState, serverKey!.RawHex, Convert.ToHexStringLower(candidate)) == 3)
                return candidate;
        }
    }

    private Ticket GeneratedTicket()
    {
        var ticket = new Ticket(AuthMessageType.AuthTs, form);
        ticket.SetChallenge(Bytes(Dp9ikConstants.ChallengeLength));
        ticket.SetClientUser(RandomText(random.Next(1, 27)));
        ticket.SetServerUser(RandomText(random.Next(1, 27)));
        byte[] key = Bytes(Dp9ikConstants.NonceLength);
        if (form == TicketEncryptionForm.Form0) key.AsSpan(Dp9ikConstants.DesKeyLength).Clear();
        ticket.SetSessionKey(key);
        return ticket;
    }

    private Authenticator GeneratedAuthenticator()
    {
        var authenticator = new Authenticator(AuthMessageType.AuthAc);
        authenticator.SetChallenge(Bytes(Dp9ikConstants.ChallengeLength));
        // Form 0 authenticators carry no random field.
        authenticator.SetRandom(form == TicketEncryptionForm.Form0 ? new byte[Dp9ikConstants.NonceLength] : Bytes(Dp9ikConstants.NonceLength));
        return authenticator;
    }

    private byte[] Bytes(int length)
    {
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    private string RandomText(int length)
        => new(Enumerable.Range(0, length).Select(_ => (char)random.Next('!', '~' + 1)).ToArray());

    /// <summary>The native PAKpriv struct: int isclient (little-endian), x[56], y[56].</summary>
    private static string NativeState(bool isClient, byte[] scalar, byte[] y)
        => Convert.ToHexStringLower([.. BitConverter.GetBytes(isClient ? 1 : 0), .. scalar, .. y]);

    private static byte[] BigEndian(BigInteger value)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var padded = new byte[Dp9ikConstants.PakPublicValueLength];
        bytes.CopyTo(padded, padded.Length - bytes.Length);
        return padded;
    }
}
