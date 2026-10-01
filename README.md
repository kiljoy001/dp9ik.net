# dp9ik.net

9front's dp9ik authentication for .NET, in managed code.

| Package | Contents |
| --- | --- |
| `Dp9ik` | `passtokey`, AuthPAK (SPAKE2-EE over Ed448-Goldilocks with Decaf and Elligator 2), form 1 (ChaCha20-Poly1305) and form 0 (DES) tickets and authenticators, ticket requests, and the dp9ik session secret |
| `Dp9ik.P9Auth` | The server side of the p9any/dp9ik exchange over a `Stream` |
| `Dp9ik.Tls` | TLS 1.2 PSK keyed by the session secret, as `tlssrv` and `tlsclient -a` use it |

The cryptography uses [BouncyCastle](https://www.bouncycastle.org/). No native code, OpenSSL or helper processes are involved.

## Compatibility

Message formats and key derivations follow 9front `libauthsrv` (`passtokey.c`, `authpak.c`, `form1.c`, `convT2M.c`, `convM2T.c`, `convM2TR.c`) and factotum's dp9ik session secret. The tests compare every primitive with a reference built from drawterm's `libauthsrv`.

As in 9front:

- user names hold at most 27 bytes and the auth domain 47, leaving room for the C terminator (`ANAMELEN`, `DOMLEN`);
- received tickets and ticket requests have their names terminated;
- a dp9ik server refuses form 0 tickets;
- the TLS channel offers only `TLS_PSK_WITH_CHACHA20_POLY1305_SHA256`, `TLS_PSK_WITH_AES_128_CBC_SHA256` and `TLS_PSK_WITH_AES_128_CBC_SHA` with PSK identity `p9secret`.

## Use

Authenticate a client on a server whose key is registered with the auth server for its domain, then open the encrypted channel:

```csharp
using Dp9ik.P9Auth;
using Dp9ik.Tls;

var config = new AuthServerConfig(Domain: "example.org", User: "bootes", Password: serverPassword);
P9AuthResult result = await P9AuthProtocol.AuthenticateAsync(stream, config, cancellationToken);
Stream channel = await P9PskTls.AcceptAsync(stream, result.Secret, cancellationToken);
// result.User is the authenticated client user.
```

## License

MIT. See [LICENSE](LICENSE).
