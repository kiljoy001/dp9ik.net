namespace Dp9ik.P9Auth;

/// <summary>Exact-length reads used by the protocol.</summary>
public static class StreamExtensions
{
    /// <summary>Reads exactly <paramref name="length"/> bytes, failing at end of stream.</summary>
    public static async Task<byte[]> ReadExactlyAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, cancellationToken);
        return buffer;
    }

    /// <summary>Reads one byte, failing at end of stream.</summary>
    public static async Task<byte> ReadSingleByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = await ReadExactlyAsync(stream, 1, cancellationToken);
        return buffer[0];
    }
}
