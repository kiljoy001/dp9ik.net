namespace Dp9ik;

/// <summary>
/// 9front's Passwordreq: the old and new passwords and an optional new secret that auth/passwd sends
/// the auth server, marshalled as convPR2M and convM2PR define it under the ticket's key.
/// </summary>
public sealed class PasswordRequest
{
    private const int Form1Length = Dp9ikConstants.PasswordRequestSize - 1 + Form1.Overhead;

    /// <summary>Creates an empty request of the given type, normally AuthPass.</summary>
    public PasswordRequest(AuthMessageType type)
    {
        Type = type;
        OldPassword = FixedField.Create(Dp9ikConstants.PasswordLength);
        NewPassword = FixedField.Create(Dp9ikConstants.PasswordLength);
        Secret = FixedField.Create(Dp9ikConstants.SecretLength);
    }

    /// <summary>Gets the message type.</summary>
    public AuthMessageType Type { get; }

    /// <summary>Gets the NUL-terminated old password field.</summary>
    public byte[] OldPassword { get; }

    /// <summary>Gets the NUL-terminated new password field; empty keeps the password.</summary>
    public byte[] NewPassword { get; }

    /// <summary>Gets or sets whether <see cref="Secret"/> replaces the user's secret.</summary>
    public bool ChangeSecret { get; set; }

    /// <summary>Gets the NUL-terminated new secret field.</summary>
    public byte[] Secret { get; }

    /// <summary>Gets the old password as text.</summary>
    public string OldPasswordText => FixedField.ReadText(OldPassword);

    /// <summary>Gets the new password as text.</summary>
    public string NewPasswordText => FixedField.ReadText(NewPassword);

    /// <summary>Gets the new secret as text.</summary>
    public string SecretText => FixedField.ReadText(Secret);

    /// <summary>Sets the old password. Holds at most 27 bytes of UTF-8.</summary>
    public void SetOldPassword(string value) => FixedField.SetText(value, OldPassword);

    /// <summary>Sets the new password. Holds at most 27 bytes of UTF-8.</summary>
    public void SetNewPassword(string value) => FixedField.SetText(value, NewPassword);

    /// <summary>Sets the new secret. Holds at most 31 bytes of UTF-8.</summary>
    public void SetSecret(string value) => FixedField.SetText(value, Secret);

    /// <summary>convPR2M: form 0 is Plan 9 DES under the ticket's DES key, form 1 is form1 under the ticket key.</summary>
    public byte[] Marshal(Ticket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        byte[] plain = ToNativeLayout();
        if (ticket.Form == TicketEncryptionForm.Form0)
        {
            Plan9Des.Encrypt(ticket.SessionKey.AsSpan(0, Dp9ikConstants.DesKeyLength), plain);
            return plain;
        }

        return Form1.Seal(plain, ticket.SessionKey);
    }

    /// <summary>
    /// convM2PR: opens a request under the ticket's key and terminates its text fields; false when the
    /// buffer is too short or a form 1 request is not authentic.
    /// </summary>
    public static bool TryUnmarshal(Ticket ticket, ReadOnlySpan<byte> buffer, out PasswordRequest? request, out int consumed)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        request = null;
        consumed = 0;
        byte[]? plain;
        int length;
        if (ticket.Form == TicketEncryptionForm.Form0)
        {
            length = Dp9ikConstants.PasswordRequestSize;
            if (buffer.Length < length) return false;
            plain = buffer[..length].ToArray();
            Plan9Des.Decrypt(ticket.SessionKey.AsSpan(0, Dp9ikConstants.DesKeyLength), plain);
        }
        else
        {
            length = Form1Length;
            if (buffer.Length < length) return false;
            plain = Form1.Open(buffer[..length], ticket.SessionKey);
            if (plain is null) return false;
        }

        var result = new PasswordRequest((AuthMessageType)plain[0]);
        int offset = 1;
        plain.AsSpan(offset, Dp9ikConstants.PasswordLength).CopyTo(result.OldPassword);
        offset += Dp9ikConstants.PasswordLength;
        plain.AsSpan(offset, Dp9ikConstants.PasswordLength).CopyTo(result.NewPassword);
        offset += Dp9ikConstants.PasswordLength;
        result.ChangeSecret = plain[offset++] != 0;
        plain.AsSpan(offset, Dp9ikConstants.SecretLength).CopyTo(result.Secret);
        // convM2PR terminates every text field.
        FixedField.Terminate(result.OldPassword);
        FixedField.Terminate(result.NewPassword);
        FixedField.Terminate(result.Secret);
        request = result;
        consumed = length;
        return true;
    }

    /// <summary>The native Passwordreq struct: num, old, new, changesecret, secret.</summary>
    internal byte[] ToNativeLayout()
    {
        var bytes = new byte[Dp9ikConstants.PasswordRequestSize];
        bytes[0] = (byte)Type;
        OldPassword.CopyTo(bytes, 1);
        NewPassword.CopyTo(bytes, 1 + Dp9ikConstants.PasswordLength);
        bytes[1 + (2 * Dp9ikConstants.PasswordLength)] = ChangeSecret ? (byte)1 : (byte)0;
        Secret.CopyTo(bytes, 2 + (2 * Dp9ikConstants.PasswordLength));
        return bytes;
    }
}
