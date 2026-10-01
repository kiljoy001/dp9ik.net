namespace Dp9ik.P9Auth;

/// <summary>The server's identity in its authentication domain.</summary>
/// <param name="Domain">The authentication domain (authdom) the server belongs to.</param>
/// <param name="User">The server's authentication identity (authid), such as bootes.</param>
/// <param name="Password">The authid's password, registered with the domain's auth server.</param>
public sealed record AuthServerConfig(string Domain, string User, string Password)
{
    /// <summary>Throws when a field is missing or blank.</summary>
    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Domain, nameof(Domain));
        ArgumentException.ThrowIfNullOrWhiteSpace(User, nameof(User));
        ArgumentException.ThrowIfNullOrWhiteSpace(Password, nameof(Password));
    }
}
