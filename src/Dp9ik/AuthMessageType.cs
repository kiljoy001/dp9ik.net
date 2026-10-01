namespace Dp9ik;

/// <summary>Message types of the 9front authentication protocols, as authsrv.h defines them.</summary>
public enum AuthMessageType : byte
{
    /// <summary>Ticket request.</summary>
    AuthTreq = 1,
    /// <summary>Challenge-box request.</summary>
    AuthChal = 2,
    /// <summary>Change password.</summary>
    AuthPass = 3,
    /// <summary>Fixed-length reply follows.</summary>
    AuthOk = 4,
    /// <summary>Error follows.</summary>
    AuthErr = 5,
    /// <summary>Modify user.</summary>
    AuthMod = 6,
    /// <summary>APOP authentication for mail.</summary>
    AuthApop = 7,
    /// <summary>Variable-length reply follows.</summary>
    AuthOkVar = 9,
    /// <summary>CHAP authentication for PPP.</summary>
    AuthChap = 10,
    /// <summary>MS-CHAP authentication for PPP.</summary>
    AuthMsChap = 11,
    /// <summary>CRAM-MD5 authentication for IMAP.</summary>
    AuthCram = 12,
    /// <summary>HTTP authentication.</summary>
    AuthHttp = 13,
    /// <summary>VNC server login.</summary>
    AuthVnc = 14,
    /// <summary>AuthPAK public-value exchange for dp9ik.</summary>
    AuthPak = 19,
    /// <summary>Ticket encrypted with the server key.</summary>
    AuthTs = 64,
    /// <summary>Ticket encrypted with the client key.</summary>
    AuthTc = 65,
    /// <summary>Server-generated authenticator.</summary>
    AuthAs = 66,
    /// <summary>Client-generated authenticator.</summary>
    AuthAc = 67,
    /// <summary>Ticket encrypted with the client key for a password change.</summary>
    AuthTp = 68,
    /// <summary>HTTP reply.</summary>
    AuthHr = 69
}
