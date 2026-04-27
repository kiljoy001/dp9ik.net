namespace Dp9ik;

internal static class HexEncoding
{
    internal static byte[] FromHex(string value) => Convert.FromHexString(value);

    internal static string ToHex(ReadOnlySpan<byte> value) => Convert.ToHexString(value).ToLowerInvariant();
}
