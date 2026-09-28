namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Theory data that runs a scenario against every supported host.
/// </summary>
public static class TestHosts
{
    public static TheoryData<TestHostKind> All => new()
    {
        TestHostKind.TestServer,
        TestHostKind.Kestrel,
    };
}
