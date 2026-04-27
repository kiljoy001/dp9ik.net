namespace Dp9ik;

public static class NativeLayout
{
    public static int SizeOfTicketRequest() => Dp9ikConstants.TicketRequestLength;

    public static int SizeOfTicket() => Dp9ikConstants.TicketSize;

    public static int SizeOfAuthenticator() => Dp9ikConstants.AuthenticatorSize;

    public static int SizeOfAuthKey() => Dp9ikConstants.AuthKeySize;

    public static int SizeOfAuthPakState() => Dp9ikConstants.AuthPakStateSize;
}
