using System.Text;

namespace Dp9ik;

internal static class FixedField
{
    internal static byte[] Create(int length) => new byte[length];

    internal static string ReadText(byte[] value)
    {
        // Text fields always hold their C terminator: setters leave room for it and decoders force it.
        return Encoding.UTF8.GetString(value, 0, Array.IndexOf(value, (byte)0));
    }

    internal static void SetExact(ReadOnlySpan<byte> value, byte[] target)
    {
        if (value.Length != target.Length)
        {
            throw new ArgumentException($"Expected {target.Length} bytes.", nameof(value));
        }

        value.CopyTo(target);
    }

    /// <summary>Sets a NUL-terminated text field; its last byte is reserved for the terminator, as ANAMELEN and DOMLEN reserve it.</summary>
    internal static void SetText(string value, byte[] target)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length >= target.Length)
        {
            throw new ArgumentException($"Expected at most {target.Length - 1} bytes.", nameof(value));
        }

        target.AsSpan().Clear();
        bytes.CopyTo(target, 0);
    }

    /// <summary>Forces the terminator a C decoder writes into the last byte of a received text field.</summary>
    internal static void Terminate(byte[] target) => target[^1] = 0;
}
