namespace Dp9ik;

/// <summary>A buffer holding secret material, zeroed when released, as 9front memsets its PAK state.</summary>
internal sealed class SecretBytes(byte[] bytes) : IDisposable
{
    internal byte[] Bytes { get; } = bytes;

    public void Dispose() => Array.Clear(Bytes);
}
