using System.Text;

namespace Dp9ik.P9Auth;

/// <summary>NUL-terminated UTF-8 strings, as p9any exchanges them.</summary>
public static class CStringEncoding
{
    /// <summary>Reads a string up to its NUL, failing when it exceeds <paramref name="maxBytes"/>.</summary>
    public static async Task<string> ReadAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var bytes = await ReadBytesAsync(stream, maxBytes, new List<byte>(), cancellationToken);
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>Writes a string followed by a NUL.</summary>
    public static Task WriteAsync(Stream stream, string value, CancellationToken cancellationToken)
    {
        var buffer = Encoding.UTF8.GetBytes(value + "\0");
        return stream.WriteAsync(buffer, cancellationToken).AsTask();
    }

    private static async Task<byte[]> ReadBytesAsync(Stream stream, int maxBytes, List<byte> bytes, CancellationToken cancellationToken)
    {
        var next = await StreamExtensions.ReadSingleByteAsync(stream, cancellationToken);
        return next == 0 ? bytes.ToArray() : await ReadMoreAsync(stream, maxBytes, bytes, next, cancellationToken);
    }

    private static Task<byte[]> ReadMoreAsync(Stream stream, int maxBytes, List<byte> bytes, byte next, CancellationToken cancellationToken)
    {
        if (bytes.Count >= maxBytes)
        {
            throw new InvalidOperationException($"CString exceeded {maxBytes} bytes.");
        }

        bytes.Add(next);
        return ReadBytesAsync(stream, maxBytes, bytes, cancellationToken);
    }
}
