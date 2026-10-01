namespace Dp9ik;

/// <summary>Sizes of the native 9front structures, for interop with C callers.</summary>
public static class NativeLayout
{
    /// <summary>Gets the size of a marshalled Ticketreq.</summary>
    public static int SizeOfTicketRequest() => Dp9ikConstants.TicketRequestLength;

    /// <summary>Gets the size of the native Ticket struct.</summary>
    public static int SizeOfTicket() => Dp9ikConstants.TicketSize;

    /// <summary>Gets the size of the native Authenticator struct.</summary>
    public static int SizeOfAuthenticator() => Dp9ikConstants.AuthenticatorSize;

    /// <summary>Gets the size of the native Authkey struct.</summary>
    public static int SizeOfAuthKey() => Dp9ikConstants.AuthKeySize;

    /// <summary>Gets the size of the native PAKpriv struct.</summary>
    public static int SizeOfAuthPakState() => Dp9ikConstants.AuthPakStateSize;
}
