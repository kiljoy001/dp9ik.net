using System.Text;
using FluentAssertions;

namespace Dp9ik.Tests;

public sealed class CStringEncodingTests
{
    [Fact]
    public async Task WriteAsync_Appends_A_Terminating_Null()
    {
        await using var stream = new MemoryStream();

        await CStringEncoding.WriteAsync(stream, "dp9ik@example.test", CancellationToken.None);

        stream.ToArray().Should().Equal(Encoding.UTF8.GetBytes("dp9ik@example.test\0"));
    }

    [Fact]
    public async Task ReadAsync_Stops_At_The_First_Null_Terminator()
    {
        var buffer = Encoding.UTF8.GetBytes("dp9ik example.test\0ignored");
        await using var stream = new MemoryStream(buffer);

        var value = await CStringEncoding.ReadAsync(stream, 64, CancellationToken.None);

        value.Should().Be("dp9ik example.test");
        stream.Position.Should().Be("dp9ik example.test\0".Length);
    }

    [Fact]
    public async Task ReadAsync_Rejects_Strings_That_Exceed_MaxBytes()
    {
        var buffer = Encoding.UTF8.GetBytes("four\0");
        await using var stream = new MemoryStream(buffer);

        var act = () => CStringEncoding.ReadAsync(stream, 3, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*3 bytes*");
    }
}
