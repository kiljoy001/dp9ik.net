namespace Dp9ik;

public sealed class AuthKey
{
    private byte[] _raw;

    private AuthKey(byte[] raw) => _raw = raw;

    public byte[] AesKey => Slice(Dp9ikConstants.DesKeyLength, Dp9ikConstants.AesKeyLength);

    public byte[] SharedKey => Slice(Dp9ikConstants.DesKeyLength + Dp9ikConstants.AesKeyLength, Dp9ikConstants.PakKeyLength);

    public static AuthKey FromPassword(string password) => new(HexEncoding.FromHex(NativeTool.Execute("passtokey", password)[0]));

    public void ApplyAuthPakHash(string user) => Replace(HexEncoding.FromHex(NativeTool.Execute("authpak_hash", RawHex, user)[0]));

    internal string RawHex => HexEncoding.ToHex(_raw);

    internal void Replace(byte[] raw) => _raw = raw;

    private byte[] Slice(int offset, int length) => _raw.AsSpan(offset, length).ToArray();
}
