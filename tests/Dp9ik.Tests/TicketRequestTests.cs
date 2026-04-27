using FluentAssertions;

namespace Dp9ik.Tests;

public sealed class TicketRequestTests
{
    [Fact]
    public void Marshal_RoundTrips_All_Fixed_Width_Fields()
    {
        var request = new TicketRequest(AuthMessageType.AuthPak);
        request.SetAuthId("authid");
        request.SetAuthDomain("example.test");
        request.SetChallenge("chal1234"u8);
        request.SetHostId("file-server");
        request.SetUserId("scott");

        var encoded = request.Marshal();

        encoded.Should().HaveCount(Dp9ikConstants.TicketRequestLength);
        TicketRequest.TryUnmarshal(encoded, out var decoded, out var consumed).Should().BeTrue();
        consumed.Should().Be(encoded.Length);
        decoded.Should().NotBeNull();
        decoded!.Type.Should().Be(AuthMessageType.AuthPak);
        decoded.AuthIdText.Should().Be("authid");
        decoded.AuthDomainText.Should().Be("example.test");
        decoded.HostIdText.Should().Be("file-server");
        decoded.UserIdText.Should().Be("scott");
        decoded.Challenge.Should().Equal("chal1234"u8.ToArray());
    }

    [Fact]
    public void TryUnmarshal_Returns_Zero_Consumed_For_Invalid_Buffer()
    {
        TicketRequest.TryUnmarshal([0xFF], out var decoded, out var consumed).Should().BeFalse();
        decoded.Should().BeNull();
        consumed.Should().Be(0);
    }

    [Fact]
    public void Struct_Size_Matches_Drawterm_Layout()
    {
        NativeLayout.SizeOfTicketRequest().Should().Be(Dp9ikConstants.TicketRequestLength);
    }
}
