namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Client credentials shared by the test servers and clients.
/// </summary>
internal static class TestCredentials
{
    public const string ClientId = "partner-a";

    public const string Secret = "cGFydG5lci1hLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMw==";

    public const string OtherClientId = "partner-b";

    public const string OtherSecret = "cGFydG5lci1iLXNlY3JldC1mZWRjYmE5ODc2NTQzMjEwZmVkYw==";

    /// <summary>
    /// Every client known to the test servers.
    /// </summary>
    public static IReadOnlyDictionary<string, string> All { get; } = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [ClientId] = Secret,
        [OtherClientId] = OtherSecret,
    };
}
