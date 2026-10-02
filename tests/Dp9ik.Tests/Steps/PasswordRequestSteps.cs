using System.Text;
using Dp9ik.Tests.Support;
using FluentAssertions;
using Reqnroll;

namespace Dp9ik.Tests.Steps;

/// <summary>Password requests (convPR2M and convM2PR) and random Authkeys (authsrv's mkkey).</summary>
[Binding]
[Scope(Feature = "dp9ik runs in managed code and matches 9front")]
public sealed class PasswordRequestSteps
{
    private const int Cases = 24;
    private readonly Random random = new(90);
    private TicketEncryptionForm form = TicketEncryptionForm.Form1;
    private Ticket? ticket;
    private PasswordRequest? request;
    private byte[]? wire;
    private PasswordRequest? opened;
    private byte[]? referenceOpened;
    private Exception? error;
    private AuthKey? first;
    private AuthKey? second;

    [Given(@"^a generated form (0|1) password request and its ticket$")]
    public void GivenGenerated(int formNumber) => form = (TicketEncryptionForm)formNumber;

    [When(@"^the (managed|reference) seals the password request and the (managed|reference) opens it$")]
    public void WhenSealedAndOpened(string sealer, string opener)
    {
        for (int round = 0; round < Cases; round++)
        {
            Ticket sealing = MakeTicket();
            PasswordRequest original = MakeRequest();
            byte[] sealedRequest = sealer == "managed"
                ? original.Marshal(sealing)
                : Convert.FromHexString(ReferenceTool.Run("passwordreq_marshal", Hex(sealing.ToNativeLayout()), Hex(original.ToNativeLayout()))[0]);
            if (opener == "managed")
            {
                PasswordRequest.TryUnmarshal(sealing, sealedRequest, out PasswordRequest? read, out int consumed).Should().BeTrue();
                consumed.Should().Be(sealedRequest.Length);
                read!.ToNativeLayout().Should().Equal(original.ToNativeLayout());
            }
            else
            {
                string[] read = ReferenceTool.Run("passwordreq_unmarshal", Hex(sealing.ToNativeLayout()), Hex(sealedRequest));
                int.Parse(read[0], System.Globalization.CultureInfo.InvariantCulture).Should().Be(sealedRequest.Length);
                Convert.FromHexString(read[1]).Should().Equal(original.ToNativeLayout());
            }
        }
    }

    [Then("the opened password request equals the original")]
    public static void ThenEqual()
    {
        // Each round of the seal-and-open step compares the opened request with the original.
    }

    [Given("the reference seals a form 1 password request whose passwords fill 28 bytes and secret fills 32")]
    public void GivenFullFields()
    {
        ticket = MakeTicket();
        var native = new byte[Dp9ikConstants.PasswordRequestSize];
        native[0] = (byte)AuthMessageType.AuthPass;
        native.AsSpan(1, Dp9ikConstants.PasswordLength).Fill((byte)'o');
        native.AsSpan(1 + Dp9ikConstants.PasswordLength, Dp9ikConstants.PasswordLength).Fill((byte)'n');
        native[1 + (2 * Dp9ikConstants.PasswordLength)] = 1;
        native.AsSpan(2 + (2 * Dp9ikConstants.PasswordLength), Dp9ikConstants.SecretLength).Fill((byte)'s');
        wire = Convert.FromHexString(ReferenceTool.Run("passwordreq_marshal", Hex(ticket.ToNativeLayout()), Hex(native))[0]);
    }

    [When("the library and the reference open the password request")]
    public void WhenBothOpen()
    {
        PasswordRequest.TryUnmarshal(ticket!, wire, out opened, out _).Should().BeTrue();
        referenceOpened = Convert.FromHexString(ReferenceTool.Run("passwordreq_unmarshal", Hex(ticket!.ToNativeLayout()), Hex(wire!))[1]);
    }

    [Then("both read the passwords as their first 27 bytes and the secret as its first 31")]
    public void ThenTerminated()
    {
        opened!.OldPasswordText.Should().Be(new string('o', 27));
        opened.NewPasswordText.Should().Be(new string('n', 27));
        opened.SecretText.Should().Be(new string('s', 31));
        opened.ChangeSecret.Should().BeTrue();
        opened.ToNativeLayout().Should().Equal(referenceOpened);
    }

    [Given(@"^a sealed form (0|1) password request$")]
    public void GivenSealed(int formNumber)
    {
        form = (TicketEncryptionForm)formNumber;
        ticket = MakeTicket();
        wire = MakeRequest().Marshal(ticket);
    }

    [Then("changing any single byte of it makes opening fail")]
    public void ThenTamperedFails()
    {
        for (int index = 0; index < wire!.Length; index++)
        {
            byte[] tampered = wire.ToArray();
            tampered[index] ^= 0x01;
            PasswordRequest.TryUnmarshal(ticket!, tampered, out PasswordRequest? read, out int consumed).Should().BeFalse($"byte {index}");
            read.Should().BeNull();
            consumed.Should().Be(0);
        }
    }

    [Then("opening one byte less than it fails and consumes nothing")]
    public void ThenTruncatedFails()
    {
        PasswordRequest.TryUnmarshal(ticket!, wire.AsSpan(0, wire!.Length - 1), out _, out int consumed).Should().BeFalse();
        consumed.Should().Be(0);
    }

    [Then("opening all of it consumes exactly its length")]
    public void ThenWholeOpens()
    {
        PasswordRequest.TryUnmarshal(ticket!, wire, out _, out int consumed).Should().BeTrue();
        consumed.Should().Be(wire!.Length);
    }

    [When(@"^the password request's (old password|new password|secret) is set to (\d+) bytes$")]
    public void WhenFieldSet(string field, int length)
    {
        request = new PasswordRequest(AuthMessageType.AuthPass);
        string value = new('v', length);
        error = Catch(field switch
        {
            "old password" => () => request.SetOldPassword(value),
            "new password" => () => request.SetNewPassword(value),
            _ => (Action)(() => request.SetSecret(value)),
        });
        if (error is null)
        {
            string read = field switch
            {
                "old password" => request.OldPasswordText,
                "new password" => request.NewPasswordText,
                _ => request.SecretText,
            };
            read.Should().Be(value);
        }
    }

    [Then("the field is accepted")]
    public void ThenAccepted() => error.Should().BeNull();

    [Then(@"^the field is refused with ""(.*)""$")]
    public void ThenRefused(string message)
        => error.Should().BeOfType<ArgumentException>().Which.Message.Should().StartWith(message);

    [When(@"^a password request is (marshalled|unmarshalled) with a null ticket$")]
    public void WhenNullTicket(string operation)
        => error = Catch(operation == "marshalled"
            ? () => new PasswordRequest(AuthMessageType.AuthPass).Marshal(null!)
            : () => PasswordRequest.TryUnmarshal(null!, new byte[Dp9ikConstants.MaxPasswordRequestLength], out _, out _));

    [Then(@"^the password request fails with an argument-null error for ""(.*)""$")]
    public void ThenArgumentNull(string parameter)
        => error.Should().BeOfType<ArgumentNullException>().Which.ParamName.Should().Be(parameter);

    [Given(@"^a password request with change-secret (false|true)$")]
    public void GivenFlag(bool flag)
    {
        ticket = MakeTicket();
        request = MakeRequest();
        request.ChangeSecret = flag;
    }

    [When("the library seals it and the reference opens it")]
    public void WhenLibrarySealsReferenceOpens()
        => referenceOpened = Convert.FromHexString(
            ReferenceTool.Run("passwordreq_unmarshal", Hex(ticket!.ToNativeLayout()), Hex(request!.Marshal(ticket)))[1]);

    [Then(@"^the reference reads change-secret (\d)$")]
    public void ThenFlagByte(byte value) => referenceOpened![1 + (2 * Dp9ikConstants.PasswordLength)].Should().Be(value);

    [When("the library makes two random Authkeys")]
    public void WhenRandomKeys()
    {
        first = AuthKey.CreateRandom();
        second = AuthKey.CreateRandom();
    }

    [Then("their DES, AES and PAK keys are 7, 16 and 32 bytes, not all zero, and differ between the two")]
    public void ThenRandomKeys()
    {
        foreach ((byte[] a, byte[] b, int length) in new[]
        {
            (first!.DesKey, second!.DesKey, 7), (first.AesKey, second.AesKey, 16), (first.SharedKey, second.SharedKey, 32),
        })
        {
            a.Should().HaveCount(length);
            a.Should().NotEqual(new byte[length]);
            a.Should().NotEqual(b);
        }
    }

    [Then(@"^applying the AuthPAK hash for ""(.*)"" gives the reference authpak_hash of a key with the same DES and AES keys$")]
    public void ThenRandomKeyHashes(string user)
    {
        AuthKey expected = AuthKey.FromKeys(first!.DesKey, first.AesKey);
        expected.ApplyAuthPakHash(user);
        string reference = ReferenceTool.Run("authpak_hash", expected.RawHex, user)[0];
        first.ApplyAuthPakHash(user);
        first.PakHash.Should().Equal(Convert.FromHexString(reference)[^Dp9ikConstants.PakHashLength..]);
    }

    private Ticket MakeTicket()
    {
        var made = new Ticket(AuthMessageType.AuthTp, form);
        made.SetChallenge(Bytes(Dp9ikConstants.ChallengeLength));
        made.SetClientUser(Text(random.Next(1, 27)));
        made.SetServerUser(Text(random.Next(1, 27)));
        byte[] key = Bytes(Dp9ikConstants.NonceLength);
        if (form == TicketEncryptionForm.Form0) key.AsSpan(Dp9ikConstants.DesKeyLength).Clear();
        made.SetSessionKey(key);
        return made;
    }

    private PasswordRequest MakeRequest()
    {
        var made = new PasswordRequest(AuthMessageType.AuthPass);
        made.SetOldPassword(Text(random.Next(0, 27)));
        made.SetNewPassword(Text(random.Next(0, 27)));
        made.ChangeSecret = random.Next(2) == 1;
        made.SetSecret(Text(random.Next(0, 31)));
        return made;
    }

    private byte[] Bytes(int length)
    {
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    private string Text(int length) => new(Enumerable.Range(0, length).Select(_ => (char)random.Next('!', '~' + 1)).ToArray());

    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);

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
}
