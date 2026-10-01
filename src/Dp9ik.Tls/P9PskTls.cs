using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Dp9ik.Tls;

/// <summary>
/// TLS keyed by the dp9ik session secret, as 9front tlssrv -a and tlsclient -a use it: TLS 1.2,
/// PSK identity "p9secret" and the PSK suites of libsec tlshand.c. No certificates are involved.
/// </summary>
public static class P9PskTls
{
    /// <summary>The PSK identity 9front's tlssrv and tlsclient send and expect.</summary>
    public const string Identity = "p9secret";

    /// <summary>The PSK suites 9front offers, in its preference order.</summary>
    public static IReadOnlyList<int> CipherSuites { get; } =
    [
        CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
    ];

    /// <summary>Completes the server handshake and returns the encrypted stream.</summary>
    public static async Task<Stream> AcceptAsync(Stream transport, byte[] secret, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        Validate(secret);
        var protocol = new TlsServerProtocol(transport);
        await Task.Run(() => protocol.Accept(new Server(Crypto(), secret)), cancellationToken);
        return protocol.Stream;
    }

    /// <summary>Completes the client handshake and returns the encrypted stream.</summary>
    public static async Task<Stream> ConnectAsync(Stream transport, byte[] secret, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        Validate(secret);
        var protocol = new TlsClientProtocol(transport);
        await Task.Run(() => protocol.Connect(new Client(Crypto(), secret)), cancellationToken);
        return protocol.Stream;
    }

    private static void Validate(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0) throw new ArgumentException("The PSK is the dp9ik session secret.", nameof(secret));
    }

    private static BcTlsCrypto Crypto() => new(new SecureRandom());

    private static int[] Suites() => [.. CipherSuites];

    private sealed class Server(TlsCrypto crypto, byte[] secret) : PskTlsServer(crypto, new IdentityManager(secret))
    {
        protected override int[] GetSupportedCipherSuites() => Suites();

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();
    }

    private sealed class Client(TlsCrypto crypto, byte[] secret) : PskTlsClient(crypto, new BasicTlsPskIdentity(Identity, secret))
    {
        protected override int[] GetSupportedCipherSuites() => Suites();

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();
    }

    /// <summary>Knows only "p9secret"; any other identity is unknown_psk_identity.</summary>
    private sealed class IdentityManager(byte[] secret) : TlsPskIdentityManager
    {
        public byte[]? GetHint() => null;

        public byte[]? GetPsk(byte[] identity)
            => identity.AsSpan().SequenceEqual(System.Text.Encoding.ASCII.GetBytes(Identity)) ? secret : null;
    }
}
