using FluentAssertions;

namespace Dp9ik.Tests;

public sealed class AuthKeyTests
{
    [Fact]
    public void FromPassword_Derives_NonZero_Aes_Key()
    {
        var key = AuthKey.FromPassword("testpassword");

        key.AesKey.Should().NotEqual(new byte[Dp9ikConstants.AesKeyLength]);
    }

    [Fact]
    public void AuthPak_Client_And_Server_Flow_Derive_The_Same_Shared_Key()
    {
        var clientKey = AuthKey.FromPassword("testpassword");
        clientKey.ApplyAuthPakHash("scott");

        var serverKey = AuthKey.FromPassword("testpassword");
        serverKey.ApplyAuthPakHash("scott");

        var clientState = new AuthPakState();
        var serverState = new AuthPakState();

        var clientY = clientState.CreatePublicValue(clientKey, isClient: true);
        var serverY = serverState.CreatePublicValue(serverKey, isClient: false);

        clientState.Finish(clientKey, serverY);
        serverState.Finish(serverKey, clientY);

        clientKey.SharedKey.Should().Equal(serverKey.SharedKey);
        clientKey.SharedKey.Should().NotEqual(new byte[Dp9ikConstants.PakKeyLength]);
    }

    [Fact]
    public void Finish_Rejects_Invalid_Public_Value_Length()
    {
        var key = AuthKey.FromPassword("testpassword");
        key.ApplyAuthPakHash("scott");

        var state = new AuthPakState();
        _ = state.CreatePublicValue(key, isClient: true);

        var act = () => state.Finish(key, [0x01]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*public value length*");
    }
}
