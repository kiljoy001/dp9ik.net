namespace Dp9ik;

internal static class AuthMessageClassifier
{
    private static readonly bool[] KnownAuthenticatorTypes = CreateKnownAuthenticatorTypes();

    private static readonly bool[] KnownTicketTypes = CreateKnownTicketTypes();

    internal static bool IsKnownAuthenticatorType(AuthMessageType type) => KnownAuthenticatorTypes[(byte)type];

    internal static bool IsKnownTicketType(AuthMessageType type) => KnownTicketTypes[(byte)type];

    private static bool[] CreateKnownAuthenticatorTypes()
    {
        var knownTypes = new bool[byte.MaxValue + 1];
        knownTypes[(byte)AuthMessageType.AuthAs] = true;
        knownTypes[(byte)AuthMessageType.AuthAc] = true;
        return knownTypes;
    }

    private static bool[] CreateKnownTicketTypes()
    {
        var knownTypes = new bool[byte.MaxValue + 1];
        knownTypes[(byte)AuthMessageType.AuthTs] = true;
        knownTypes[(byte)AuthMessageType.AuthTc] = true;
        knownTypes[(byte)AuthMessageType.AuthTp] = true;
        return knownTypes;
    }
}
