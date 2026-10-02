using System.Numerics;
using System.Text;
using Dp9ik.P9Auth;
using Dp9ik.Tests.Support;
using FluentAssertions;
using Org.BouncyCastle.Security;
using Reqnroll;
using Element = Dp9ik.AuthPakCurve.Element;

namespace Dp9ik.Tests.Steps;

/// <summary>Boundaries, misuse and argument checks of the managed dp9ik primitives.</summary>
[Binding]
[Scope(Feature = "dp9ik runs in managed code and matches 9front")]
public sealed class ManagedDp9ikEdgeSteps
{
    private static readonly BigInteger P = AuthPakCurve.P;
    private readonly Random random = new(448);
    private readonly List<BigInteger> fieldValues = new();
    private readonly List<string> fieldMismatches = new();
    private AuthKey? key;
    private AuthPakState? state;
    private byte[]? scalar;
    private byte[]? drawn;
    private Exception? error;
    private Element negated;
    private BigInteger negatedInput;
    private byte[]? message;
    private Ticket? ticket;
    private byte[]? wire;
    private TicketRequest? request;
    private SecretBytes? secret;
    private long written = -1;

    [Given("a client state created from a chosen scalar")]
    public void GivenChosenClientState()
    {
        key = PakKey();
        scalar = BigEndian(BigInteger.Pow(2, 447) + 77);
        state = new AuthPakState();
        state.CreatePublicValue(key, isClient: true, scalar);
    }

    [When("it finishes an exchange with the reference server")]
    public void WhenFinishesWithReference()
        => state!.Finish(key!, Convert.FromHexString(ReferenceTool.Run("authpak_new", key!.RawHex, "0")[1]));

    [Then("the scalar buffer it was given is zeroed")]
    public void ThenScalarZeroed() => scalar.Should().Equal(new byte[Dp9ikConstants.PakScalarLength]);

    [Then("finishing again fails because no public value has been created")]
    public void ThenFinishAgainFails()
    {
        WhenFinishedWithPeer();
        ThenFinishingFails();
    }

    [Given("a new AuthPAK state")]
    public void GivenNewState()
    {
        key = PakKey();
        state = new AuthPakState();
    }

    [When("it is finished with a peer public value")]
    public void WhenFinishedWithPeer()
        => error = Catch(() => state!.Finish(key!, new byte[Dp9ikConstants.PakPublicValueLength]));

    [Then("finishing fails because no public value has been created")]
    public void ThenFinishingFails()
        => error.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Be("No AuthPAK public value has been created.");

    [Given("a random source yielding p, then a value below p only when read little-endian or signed, then a valid scalar")]
    public void GivenScriptedRandom()
    {
        // p itself, then 0xFF*28 0x00*28: at least p big-endian, small little-endian and negative signed.
        byte[] lowWhenMisread = [.. Enumerable.Repeat((byte)0xFF, 28), .. new byte[28]];
        scalar = BigEndian(BigInteger.Pow(2, 447) + 1);
        drawn = AuthPakCurve.RandomScalar(new ScriptedRandom([BigEndian(P), lowWhenMisread, scalar]));
    }

    [When("the library draws an AuthPAK scalar")]
    public static void WhenScalarDrawn()
    {
    }

    [Then("it returns the third value")]
    public void ThenThirdValue() => drawn.Should().Equal(scalar);

    [Given("generated field elements including 0, 1, p-1 and encodings at or above p")]
    public void GivenFieldValues()
    {
        BigInteger top = BigInteger.Pow(2, 448) - 1;
        fieldValues.AddRange([0, 1, 2, P - 1, P, P + 5, top, BigInteger.Pow(2, 224), (P - 1) / 2]);
        while (fieldValues.Count < 24)
            fieldValues.Add(new BigInteger(Bytes(Dp9ikConstants.PakScalarLength), isUnsigned: true, isBigEndian: true));
    }

    [When("each is added, subtracted, multiplied, squared, negated, inverted and raised to a power")]
    public void WhenFieldOperations()
    {
        BigInteger exponent = (P - 3) / 4;
        for (int index = 0; index < fieldValues.Count; index++)
        {
            BigInteger a = fieldValues[index];
            BigInteger b = fieldValues[(index * 7 + 3) % fieldValues.Count];
            Element x = Element.FromBigEndian(BigEndian(a));
            Element y = Element.FromBigEndian(BigEndian(b));
            Expect($"{a:X} reduces", x, a);
            Expect($"{a:X} + {b:X}", x + y, a + b);
            Expect($"{a:X} - {b:X}", x - y, a - b);
            Expect($"{a:X} * {b:X}", x * y, a * b);
            Expect($"{a:X} squared", x.Square(), a * a);
            Expect($"-{a:X}", -x, -a);
            Expect($"{a:X} ^ (p-3)/4", x.Pow(exponent), BigInteger.ModPow(Mod(a), exponent, P));
            if (!Mod(a).IsZero) Expect($"1/{a:X}", x.Invert(), BigInteger.ModPow(Mod(a), P - 2, P));
        }
    }

    [When("each is doubled by addition 64 times in a row before being multiplied")]
    public void WhenDoubledByAddition()
    {
        foreach (BigInteger a in fieldValues)
        {
            Element x = Element.FromBigEndian(BigEndian(a));
            for (int round = 0; round < 64; round++) x += x;
            Expect($"{a:X} doubled 64 times, squared", x * x, a * a * BigInteger.Pow(2, 128));
        }
    }

    [Then("every result equals the same operation on integers modulo p")]
    public void ThenFieldMatches() => fieldMismatches.Should().BeEmpty();

    [Then("2, 3, 4, 5 and 6 are squares modulo p")]
    public static void ThenSmallSquares()
    {
        foreach (int value in new[] { 2, 3, 4, 5, 6 })
            AuthPakCurve.Legendre(Element.FromInt(value)).Should().Be(1, $"{value} is a square");
    }

    [Then("7 is not a square modulo p")]
    public static void ThenSevenNonSquare() => AuthPakCurve.Legendre(Element.FromInt(7)).Should().Be(-1);

    [Then("the library's Elligator non-square is 7")]
    public static void ThenNonSquareIsSeven() => AuthPakCurve.NonSquare.Should().Be(7);

    [When(@"^decaf_neg is applied to a value with n = (\S+)$")]
    public void WhenDecafNeg(string n)
    {
        negatedInput = 12345;
        BigInteger value = n switch
        {
            "(p-1)/2" => (P - 1) / 2,
            "(p+1)/2" => (P + 1) / 2,
            "p-1" => P - 1,
            _ => BigInteger.Parse(n, System.Globalization.CultureInfo.InvariantCulture),
        };
        negated = AuthPakCurve.NegateIfHigh(Element.FromBigInteger(value), Element.FromBigInteger(negatedInput));
    }

    [Then(@"^the value is (kept|negated)$")]
    public void ThenDecafNegOutcome(string outcome)
        => negated.ToBigInteger().Should().Be(outcome == "kept" ? negatedInput : P - negatedInput);

    [Given(@"^the 8 bytes ""(.*)""$")]
    public void GivenEightBytes(string text) => message = Encoding.ASCII.GetBytes(text);

    [Then("form1check reports a ticket from the server")]
    public void ThenFormCheckTicket() => Form1.Check(message).Should().Be(AuthMessageType.AuthTs);

    [Then(@"^the 7 bytes ""(.*)"" are not recognised$")]
    public static void ThenSevenBytesUnrecognised(string text) => Form1.Check(Encoding.ASCII.GetBytes(text)).Should().BeNull();

    [Given("a form1 message sealed from only its type byte")]
    public void GivenEmptyBody()
    {
        key = TicketKey();
        message = Form1.Seal([(byte)AuthMessageType.AuthTs], key.SharedKey);
        message.Should().HaveCount(Form1.Overhead);
    }

    [Then("opening the sealed message fails")]
    public void ThenSealedMessageRejected() => Form1.Open(message, key!.SharedKey).Should().BeNull();

    [Given(@"^a form 1 ticket of type (\w+)$")]
    public void GivenTicketOfType(string type)
    {
        key = TicketKey();
        ticket = new Ticket(Enum.Parse<AuthMessageType>(type), TicketEncryptionForm.Form1);
    }

    [Then("marshalling it fails with an argument error")]
    public void ThenMarshalFails()
        => Catch(() => ticket!.Marshal(key!)).Should().BeOfType<ArgumentException>()
            .Which.Message.Should().StartWith("Message type AuthOk has no form1 signature.");

    [Given(@"^a marshalled form (0|1) (ticket|authenticator)$")]
    public void GivenMarshalled(int formNumber, string kind)
    {
        key = TicketKey();
        ticket = MakeTicket((TicketEncryptionForm)formNumber, "glenda", "bootes");
        wire = kind == "ticket" ? ticket.Marshal(key) : MakeAuthenticator().Marshal(ticket);
        message = Encoding.ASCII.GetBytes(kind);
    }

    [Then("unmarshalling one byte less than it fails and consumes nothing")]
    public void ThenTruncatedRejected()
    {
        Unmarshal(wire.AsSpan(0, wire!.Length - 1), out int consumed).Should().BeFalse();
        consumed.Should().Be(0);
    }

    [Then("unmarshalling all of it consumes exactly its length")]
    public void ThenWholeAccepted()
    {
        Unmarshal(wire, out int consumed).Should().BeTrue();
        consumed.Should().Be(wire!.Length);
    }

    [Given("a ticket whose client and server users are 27-byte names")]
    public void GivenLongestNames()
    {
        key = TicketKey();
        ticket = MakeTicket(TicketEncryptionForm.Form1, new string('c', 27), new string('s', 27));
    }

    [When("it is sealed and opened by the library and by the reference")]
    public void WhenSealedAndOpenedByBoth() => wire = ticket!.Marshal(key!);

    [Then("both open the same 27-byte names")]
    public void ThenBothOpenNames()
    {
        Ticket.TryUnmarshal(key!, wire, out Ticket? opened, out _).Should().BeTrue();
        opened!.ClientUserText.Should().Be(new string('c', 27));
        opened.ServerUserText.Should().Be(new string('s', 27));
        string[] reference = ReferenceTool.Run("ticket_unmarshal", key!.RawHex, Convert.ToHexStringLower(wire!));
        Convert.FromHexString(reference[1]).Should().Equal(opened.ToNativeLayout());
    }

    [When(@"^a (ticket client user|ticket server user|ticket request auth id|ticket request host id|ticket request user id|ticket request auth domain) of (\d+) bytes is set$")]
    public void WhenTextFieldSet(string field, int length)
    {
        string value = new('n', length);
        var target = new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1);
        var targetRequest = new TicketRequest(AuthMessageType.AuthTreq);
        Action set = field switch
        {
            "ticket client user" => () => target.SetClientUser(value),
            "ticket server user" => () => target.SetServerUser(value),
            "ticket request auth id" => () => targetRequest.SetAuthId(value),
            "ticket request host id" => () => targetRequest.SetHostId(value),
            "ticket request user id" => () => targetRequest.SetUserId(value),
            _ => () => targetRequest.SetAuthDomain(value),
        };
        error = Catch(set);
        if (error is null)
        {
            string read = field switch
            {
                "ticket client user" => target.ClientUserText,
                "ticket server user" => target.ServerUserText,
                "ticket request auth id" => targetRequest.AuthIdText,
                "ticket request host id" => targetRequest.HostIdText,
                "ticket request user id" => targetRequest.UserIdText,
                _ => targetRequest.AuthDomainText,
            };
            read.Should().Be(value);
        }
    }

    [Then("it is accepted")]
    public void ThenAccepted() => error.Should().BeNull();

    [Then(@"^it is refused with ""(.*)""$")]
    public void ThenRefused(string text)
        => error.Should().BeOfType<ArgumentException>().Which.Message.Should().StartWith(text);

    [Given("a ticket request whose name and domain fields are filled with no terminator")]
    public void GivenUnterminatedRequest()
    {
        wire = new byte[Dp9ikConstants.TicketRequestLength];
        wire.AsSpan().Fill((byte)'x');
        wire[0] = (byte)AuthMessageType.AuthTreq;
    }

    [When("the library unmarshals it")]
    public void WhenRequestUnmarshalled() => TicketRequest.TryUnmarshal(wire, out request, out _).Should().BeTrue();

    [Then("the auth id, host id and user id read as their first 27 bytes")]
    public void ThenNamesTerminated()
    {
        string name = new('x', Dp9ikConstants.NameLength - 1);
        request!.AuthIdText.Should().Be(name);
        request.HostIdText.Should().Be(name);
        request.UserIdText.Should().Be(name);
    }

    [Then("the auth domain reads as its first 47 bytes")]
    public void ThenDomainTerminated() => request!.AuthDomainText.Should().Be(new string('x', Dp9ikConstants.DomainLength - 1));

    [Given(@"^the reference seals a form (0|1) ticket whose user names fill all 28 bytes$")]
    public void GivenReferenceSealsFullNames(int formNumber)
    {
        key = TicketKey();
        var form = (TicketEncryptionForm)formNumber;
        byte[] native = MakeTicket(form, "c", "s").ToNativeLayout();
        int names = 1 + Dp9ikConstants.ChallengeLength;
        native.AsSpan(names, Dp9ikConstants.NameLength).Fill((byte)'c');
        native.AsSpan(names + Dp9ikConstants.NameLength, Dp9ikConstants.NameLength).Fill((byte)'s');
        wire = Convert.FromHexString(ReferenceTool.Run("ticket_marshal", key.RawHex, Convert.ToHexStringLower(native))[0]);
    }

    [When("the library and the reference open it")]
    public void WhenBothOpen()
    {
        Ticket.TryUnmarshal(key!, wire, out ticket, out _).Should().BeTrue();
        message = Convert.FromHexString(ReferenceTool.Run("ticket_unmarshal", key!.RawHex, Convert.ToHexStringLower(wire!))[1]);
    }

    [Then("both read the client and server users as their first 27 bytes")]
    public void ThenBothTerminate()
    {
        ticket!.ClientUserText.Should().Be(new string('c', Dp9ikConstants.NameLength - 1));
        ticket.ServerUserText.Should().Be(new string('s', Dp9ikConstants.NameLength - 1));
        ticket.ToNativeLayout().Should().Equal(message);
    }

    [Given(@"^a ticket whose client user is set to ""(.*)"" and then to ""(.*)""$")]
    public void GivenRenamed(string first, string second)
    {
        ticket = new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1);
        ticket.SetClientUser(first);
        ticket.SetClientUser(second);
    }

    [Then(@"^its client user reads ""(.*)""$")]
    public void ThenClientUserReads(string expected)
    {
        ticket!.ClientUserText.Should().Be(expected);
        ticket.ClientUser.AsSpan(Encoding.UTF8.GetByteCount(expected)).ToArray().Should().OnlyContain(value => value == 0);
    }

    [When(@"^an Authkey is built from a (\d+)-byte DES key and a (\d+)-byte AES key$")]
    public void WhenBuiltFromWrongSizes(int des, int aes)
        => error = Catch(() => AuthKey.FromKeys(new byte[des], new byte[aes]));

    [When(@"^(the session secret|Plan 9 DES|an Authkey replace|a ticket challenge) is given (.+)$")]
    public void WhenGivenWrongLength(string operation, string input)
    {
        byte[] nonce = new byte[Dp9ikConstants.NonceLength];
        error = Catch((operation, input) switch
        {
            ("the session secret", "a 31-byte client nonce") => (Action)(() => SessionSecret.Derive(new byte[31], nonce, nonce)),
            ("the session secret", "a 31-byte server nonce") => () => SessionSecret.Derive(nonce, new byte[31], nonce),
            ("the session secret", _) => () => SessionSecret.Derive(nonce, nonce, new byte[31]),
            ("Plan 9 DES", _) => () => Plan9Des.Encrypt(new byte[Dp9ikConstants.DesKeyLength], new byte[7]),
            ("an Authkey replace", _) => () => AuthKey.FromPassword("x").Replace(new byte[Dp9ikConstants.AuthKeySize - 1]),
            _ => () => new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1).SetChallenge(new byte[9]),
        });
    }

    [Then(@"^it fails with an argument error starting ""(.*)""$")]
    public void ThenArgumentError(string text) => ThenRefused(text);

    [When(@"^(\S+) is called with a null (\w+)$")]
    public void WhenCalledWithNull(string operation, string argument)
    {
        AuthKey authKey = PakKey();
        var formTicket = new Ticket(AuthMessageType.AuthTs, TicketEncryptionForm.Form1);
        byte[] buffer = new byte[Dp9ikConstants.MaxTicketLength];
        error = Catch(operation switch
        {
            "AuthKey.FromPassword" => (Action)(() => AuthKey.FromPassword(null!)),
            "AuthKey.ApplyAuthPakHash" => () => authKey.ApplyAuthPakHash(null!),
            "AuthPakState.CreatePublicValue" => () => new AuthPakState().CreatePublicValue(null!, isClient: true),
            "AuthPakState.Finish" => () => FinishWithNullKey(authKey),
            "Ticket.Marshal" => () => formTicket.Marshal(null!),
            "Ticket.TryUnmarshal" => () => Ticket.TryUnmarshal(null!, buffer, out _, out _),
            "Authenticator.Marshal" => () => new Authenticator(AuthMessageType.AuthAc).Marshal(null!),
            _ => () => Authenticator.TryUnmarshal(null!, buffer, out _, out _),
        });
    }

    [Then(@"^it fails with an argument-null error for ""(.*)""$")]
    public void ThenArgumentNull(string argument)
        => error.Should().BeOfType<ArgumentNullException>().Which.ParamName.Should().Be(argument);

    [When("a managed server is started with a null configuration")]
    public void WhenServerWithoutConfig()
    {
        using var stream = new MemoryStream();
        error = Catch(() => P9AuthProtocol.AuthenticateAsync(stream, null!, CancellationToken.None).GetAwaiter().GetResult());
        written = stream.Length;
    }

    [Then("nothing has been written to the client")]
    public void ThenNothingWritten() => written.Should().Be(0);

    [Given("a secret buffer holding non-zero bytes")]
    public void GivenSecret()
    {
        message = Enumerable.Range(1, 56).Select(value => (byte)value).ToArray();
        secret = new SecretBytes(message);
        secret.Bytes.Should().BeSameAs(message);
    }

    [When("it is released")]
    public void WhenReleased() => secret!.Dispose();

    [Then("every byte of it is zero")]
    public void ThenZeroed() => message.Should().OnlyContain(value => value == 0);

    private static void FinishWithNullKey(AuthKey authKey)
    {
        var pending = new AuthPakState();
        pending.CreatePublicValue(authKey, isClient: true);
        pending.Finish(null!, new byte[Dp9ikConstants.PakPublicValueLength]);
    }

    private bool Unmarshal(ReadOnlySpan<byte> buffer, out int consumed)
        => Encoding.ASCII.GetString(message!) == "ticket"
            ? Ticket.TryUnmarshal(key!, buffer, out _, out consumed)
            : Authenticator.TryUnmarshal(ticket!, buffer, out _, out consumed);

    private void Expect(string operation, Element actual, BigInteger expected)
    {
        if (actual.ToBigInteger() != Mod(expected)) fieldMismatches.Add(operation);
    }

    private static BigInteger Mod(BigInteger value) => ((value % P) + P) % P;

    private static Exception? Catch(Action action)
    {
        try
        {
            action();
            return null;
        }
        catch (Exception caught)
        {
            return caught;
        }
    }

    private static AuthKey PakKey()
    {
        AuthKey authKey = AuthKey.FromPassword("edge password");
        authKey.ApplyAuthPakHash("glenda");
        return authKey;
    }

    private AuthKey TicketKey()
    {
        AuthKey authKey = AuthKey.FromPassword("ticket key");
        byte[] raw = Convert.FromHexString(authKey.RawHex);
        random.NextBytes(raw.AsSpan(Dp9ikConstants.DesKeyLength + Dp9ikConstants.AesKeyLength, Dp9ikConstants.PakKeyLength));
        authKey.Replace(raw);
        return authKey;
    }

    private Ticket MakeTicket(TicketEncryptionForm form, string clientUser, string serverUser)
    {
        var made = new Ticket(AuthMessageType.AuthTs, form);
        made.SetChallenge(Bytes(Dp9ikConstants.ChallengeLength));
        made.SetClientUser(clientUser);
        made.SetServerUser(serverUser);
        byte[] sessionKey = Bytes(Dp9ikConstants.NonceLength);
        if (form == TicketEncryptionForm.Form0) sessionKey.AsSpan(Dp9ikConstants.DesKeyLength).Clear();
        made.SetSessionKey(sessionKey);
        return made;
    }

    private Authenticator MakeAuthenticator()
    {
        var made = new Authenticator(AuthMessageType.AuthAc);
        made.SetChallenge(Bytes(Dp9ikConstants.ChallengeLength));
        made.SetRandom(Bytes(Dp9ikConstants.NonceLength));
        return made;
    }

    private byte[] Bytes(int length)
    {
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    private static byte[] BigEndian(BigInteger value)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var padded = new byte[Dp9ikConstants.PakScalarLength];
        bytes.CopyTo(padded, padded.Length - bytes.Length);
        return padded;
    }

    /// <summary>Yields the given draws in order.</summary>
    private sealed class ScriptedRandom(IEnumerable<byte[]> draws) : SecureRandom
    {
        private readonly Queue<byte[]> remaining = new(draws);

        public override void NextBytes(byte[] buf) => remaining.Dequeue().CopyTo(buf, 0);
    }
}
