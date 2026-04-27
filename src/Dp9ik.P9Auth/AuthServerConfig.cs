namespace Dp9ik.P9Auth;

public sealed record AuthServerConfig(string Domain, string User, string Password)
{
    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Domain, nameof(Domain));
        ArgumentException.ThrowIfNullOrWhiteSpace(User, nameof(User));
        ArgumentException.ThrowIfNullOrWhiteSpace(Password, nameof(Password));
    }
}
