using System.Text;

namespace Dp9ik;

internal static class FixedField
{
    internal static byte[] Create(int length) => new byte[length];

    internal static string ReadText(byte[] value)
    {
        var zeroIndex = Array.IndexOf(value, (byte)0);
        var length = zeroIndex < 0 ? value.Length : zeroIndex;
        return Encoding.UTF8.GetString(value, 0, length);
    }

    internal static void SetExact(ReadOnlySpan<byte> value, byte[] target)
    {
        if (value.Length != target.Length)
        {
            throw new ArgumentException($"Expected {target.Length} bytes.", nameof(value));
        }

        value.CopyTo(target);
    }

    internal static void SetText(string value, byte[] target) => SetVariable(Encoding.UTF8.GetBytes(value), target);

    internal static void SetVariable(ReadOnlySpan<byte> value, byte[] target)
    {
        if (value.Length > target.Length)
        {
            throw new ArgumentException($"Expected at most {target.Length} bytes.", nameof(value));
        }

        target.AsSpan().Clear();
        value.CopyTo(target);
    }
}
