namespace Dp9ik;

/// <summary>Field and message sizes from 9front authsrv.h.</summary>
public static class Dp9ikConstants
{
    /// <summary>ANAMELEN: a user name field, including its terminator.</summary>
    public const int NameLength = 28;
    /// <summary>DOMLEN: an auth domain field, including its terminator.</summary>
    public const int DomainLength = 48;
    /// <summary>PASSWDLEN: the password buffer passtokey reads.</summary>
    public const int PasswordLength = 28;
    /// <summary>CHALLEN: a challenge.</summary>
    public const int ChallengeLength = 8;
    /// <summary>NONCELEN: a nonce or form 1 ticket key.</summary>
    public const int NonceLength = 32;
    /// <summary>DESKEYLEN: a DES key.</summary>
    public const int DesKeyLength = 7;
    /// <summary>AESKEYLEN: an AES key.</summary>
    public const int AesKeyLength = 16;
    /// <summary>PAKKEYLEN: the key AuthPAK derives.</summary>
    public const int PakKeyLength = 32;
    /// <summary>PAKSLEN: an Ed448 scalar or field element.</summary>
    public const int PakScalarLength = 56;
    /// <summary>PAKPLEN: an extended-coordinates curve point.</summary>
    public const int PakPointLength = 224;
    /// <summary>PAKHASHLEN: the PM and PN points authpak_hash derives.</summary>
    public const int PakHashLength = 448;
    /// <summary>PAKYLEN: an AuthPAK public value.</summary>
    public const int PakPublicValueLength = 56;
    /// <summary>TICKREQLEN: a marshalled ticket request.</summary>
    public const int TicketRequestLength = 141;
    /// <summary>MAXTICKETLEN: the longest marshalled ticket.</summary>
    public const int MaxTicketLength = 124;
    /// <summary>MAXAUTHENTLEN: the longest marshalled authenticator.</summary>
    public const int MaxAuthenticatorLength = 68;
    /// <summary>The size of the native Ticket struct.</summary>
    public const int TicketSize = 98;
    /// <summary>The size of the native Authenticator struct.</summary>
    public const int AuthenticatorSize = 41;
    /// <summary>The size of the native Authkey struct.</summary>
    public const int AuthKeySize = 503;
    /// <summary>SECRETLEN: a secret field, including its terminator.</summary>
    public const int SecretLength = 32;

    /// <summary>The size of the native Passwordreq struct and its form 0 encoding.</summary>
    public const int PasswordRequestSize = 90;

    /// <summary>MAXPASSREQLEN: the longest marshalled password request.</summary>
    public const int MaxPasswordRequestLength = 117;

    /// <summary>The size of the native PAKpriv struct.</summary>
    public const int AuthPakStateSize = 116;
}
