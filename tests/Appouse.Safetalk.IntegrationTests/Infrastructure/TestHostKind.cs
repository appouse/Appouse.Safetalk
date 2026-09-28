namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// The kind of server that hosts the protected application.
/// </summary>
public enum TestHostKind
{
    /// <summary>
    /// In-memory <c>Microsoft.AspNetCore.TestHost</c> server. It does not expose the raw request target, so the
    /// validator rebuilds it from the decoded request components (fallback path).
    /// </summary>
    TestServer,

    /// <summary>
    /// Real Kestrel server bound to <c>http://127.0.0.1:0</c>. The raw request target received on the wire is used.
    /// </summary>
    Kestrel,
}
