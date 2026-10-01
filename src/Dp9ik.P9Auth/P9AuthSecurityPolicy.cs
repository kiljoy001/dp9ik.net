namespace Dp9ik.P9Auth;

internal static class P9AuthSecurityPolicy
{
    internal static bool CanAcceptProof(
        AuthMessageType ticketType,
        AuthMessageType authenticatorType,
        bool ticketChallengeMatches,
        bool authenticatorChallengeMatches,
        bool hasAuthenticatedUser) =>
        HasExpectedTicketType(ticketType)
        && HasExpectedAuthenticatorType(authenticatorType)
        && ticketChallengeMatches
        && authenticatorChallengeMatches
        && hasAuthenticatedUser;

    internal static string GetAuthenticatedUser(Ticket ticket) =>
        HasAuthenticatedUser(ticket)
            ? ticket.ClientUserText
            : throw new InvalidOperationException("Authenticated user is empty.");

    internal static bool HasAuthenticatedUser(Ticket ticket) => !string.IsNullOrWhiteSpace(ticket.ClientUserText);

    internal static bool HasExpectedAuthenticatorType(AuthMessageType type) => type == AuthMessageType.AuthAc;

    internal static bool HasExpectedTicketType(AuthMessageType type) => type == AuthMessageType.AuthTs;

    internal static bool HasMatchingChallenge(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected) => actual.SequenceEqual(expected);

    internal static bool IsSupportedChoice(string choice, string domain) => string.Equals(choice, $"dp9ik {domain}", StringComparison.Ordinal);

    internal static void ValidateChoice(string choice, string domain)
    {
        if (!IsSupportedChoice(choice, domain))
        {
            throw new InvalidOperationException($"Unsupported auth choice '{choice}'.");
        }
    }

    internal static void ValidateProof(Ticket ticket, Authenticator authenticator, ReadOnlySpan<byte> expectedChallenge)
    {
        var hasExpectedTicketType = HasExpectedTicketType(ticket.Type);
        var hasExpectedAuthenticatorType = HasExpectedAuthenticatorType(authenticator.Type);
        var ticketChallengeMatches = HasMatchingChallenge(ticket.Challenge, expectedChallenge);
        var authenticatorChallengeMatches = HasMatchingChallenge(authenticator.Challenge, expectedChallenge);
        var hasAuthenticatedUser = HasAuthenticatedUser(ticket);

        if (CanAcceptProof(
            ticket.Type,
            authenticator.Type,
            ticketChallengeMatches,
            authenticatorChallengeMatches,
            hasAuthenticatedUser))
        {
            return;
        }

        EnsureExpectedTicketType(ticket.Type, hasExpectedTicketType);
        EnsureExpectedAuthenticatorType(authenticator.Type, hasExpectedAuthenticatorType);
        EnsureMatchingTicketChallenge(ticketChallengeMatches);
        EnsureMatchingAuthenticatorChallenge(authenticatorChallengeMatches);
        EnsureAuthenticatedUser(ticket, hasAuthenticatedUser);
    }

    private static void EnsureAuthenticatedUser(Ticket ticket, bool hasAuthenticatedUser)
    {
        if (!hasAuthenticatedUser)
        {
            _ = GetAuthenticatedUser(ticket);
        }
    }

    private static void EnsureExpectedAuthenticatorType(AuthMessageType type, bool hasExpectedAuthenticatorType)
    {
        if (!hasExpectedAuthenticatorType)
        {
            throw new InvalidOperationException($"Unexpected authenticator type {type}.");
        }
    }

    private static void EnsureExpectedTicketType(AuthMessageType type, bool hasExpectedTicketType)
    {
        if (!hasExpectedTicketType)
        {
            throw new InvalidOperationException($"Unexpected ticket type {type}.");
        }
    }

    private static void EnsureMatchingAuthenticatorChallenge(bool authenticatorChallengeMatches)
    {
        if (!authenticatorChallengeMatches)
        {
            throw new InvalidOperationException("Authenticator challenge mismatch.");
        }
    }

    private static void EnsureMatchingTicketChallenge(bool ticketChallengeMatches)
    {
        if (!ticketChallengeMatches)
        {
            throw new InvalidOperationException("Ticket challenge mismatch.");
        }
    }
}
