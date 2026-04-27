namespace Dp9ik;

public sealed class AuthPakState
{
    private byte[] _raw = new byte[Dp9ikConstants.AuthPakStateSize];

    public byte[] CreatePublicValue(AuthKey key, bool isClient)
    {
        var lines = NativeTool.Execute("authpak_new", key.RawHex, isClient ? "1" : "0");
        _raw = HexEncoding.FromHex(lines[0]);
        return HexEncoding.FromHex(lines[1]);
    }

    public void Finish(AuthKey key, ReadOnlySpan<byte> publicValue)
    {
        if (publicValue.Length != Dp9ikConstants.PakPublicValueLength)
        {
            throw new ArgumentException("Invalid public value length.", nameof(publicValue));
        }

        key.Replace(HexEncoding.FromHex(NativeTool.Execute(
            "authpak_finish",
            HexEncoding.ToHex(_raw),
            key.RawHex,
            HexEncoding.ToHex(publicValue))[0]));
        _raw = new byte[Dp9ikConstants.AuthPakStateSize];
    }
}
