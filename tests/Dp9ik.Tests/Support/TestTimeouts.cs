namespace Dp9ik.Tests.Support;

/// <summary>Bounds on waits in the tests; generous enough for slow shared CI runners.</summary>
internal static class TestTimeouts
{
    /// <summary>The longest a network handshake test waits before failing as hung.</summary>
    internal static readonly TimeSpan Network = TimeSpan.FromSeconds(30);
}
