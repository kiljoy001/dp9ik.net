namespace Dp9ik;

/// <summary>How a ticket and its authenticators are encrypted.</summary>
public enum TicketEncryptionForm : byte
{
    /// <summary>Plan 9 DES, as p9sk1 uses; dp9ik servers refuse it.</summary>
    Form0 = 0,
    /// <summary>ChaCha20-Poly1305 under the AuthPAK-derived key, as dp9ik uses.</summary>
    Form1 = 1
}
