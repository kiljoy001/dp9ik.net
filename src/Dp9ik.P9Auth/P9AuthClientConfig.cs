using System.Text;

namespace Dp9ik.P9Auth;

/// <summary>What a password is asked for: the user, the auth domain, and whether the last one failed.</summary>
/// <param name="User">The user whose password is wanted.</param>
/// <param name="Domain">The auth domain the server's ticket request names.</param>
/// <param name="Mismatch">True when the auth server's ticket did not open with the password given before.</param>
public sealed record PasswordPrompt(string User, string Domain, bool Mismatch)
{
    /// <summary>drawterm's prompt, "user@dom dp9ik password".</summary>
    public string Text => $"{User}@{Domain} dp9ik password";
}

/// <summary>The client's user, where its password comes from, and how the auth server is reached.</summary>
/// <param name="User">The user to authenticate as, put in the ticket request as hostid and uid.</param>
/// <param name="Password">Gives the user's password, or null for none, which ends the client.</param>
/// <param name="DialAuthServer">Opens a call to the auth server of the domain it is given.</param>
public sealed record P9AuthClientConfig(
    string User,
    Func<PasswordPrompt, CancellationToken, ValueTask<string?>> Password,
    Func<string, CancellationToken, ValueTask<Stream>> DialAuthServer)
{
    /// <summary>Throws when the user is blank or longer than a ticket holds, or a function is missing.</summary>
    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(User, nameof(User));
        if (Encoding.UTF8.GetByteCount(User) >= Dp9ikConstants.NameLength)
        {
            throw new ArgumentException($"A user name holds at most {Dp9ikConstants.NameLength - 1} bytes.", nameof(User));
        }

        ArgumentNullException.ThrowIfNull(Password, nameof(Password));
        ArgumentNullException.ThrowIfNull(DialAuthServer, nameof(DialAuthServer));
    }
}

/// <summary>An authenticated server: the users its ticket names and the session secret both sides derived.</summary>
/// <param name="ClientUser">The ticket's client user.</param>
/// <param name="ServerUser">The ticket's server user, which authsrv makes the same as the client's.</param>
/// <param name="Secret">The 256-byte secret tlsclient gives TLS-PSK.</param>
public sealed record P9AuthClientResult(string ClientUser, string ServerUser, byte[] Secret);
