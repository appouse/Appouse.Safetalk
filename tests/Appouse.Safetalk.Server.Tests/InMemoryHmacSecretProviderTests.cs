using Appouse.Safetalk.Server.Tests.Infrastructure;

namespace Appouse.Safetalk.Server.Tests;

public sealed class InMemoryHmacSecretProviderTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task GetSecretAsync_KnownClient_ReturnsItsSecret()
    {
        InMemoryHmacSecretProvider provider = TestCredentials.CreateSecretProvider();

        Assert.Equal(TestCredentials.Secret, await provider.GetSecretAsync(TestCredentials.ClientId, CancellationToken));
        Assert.Equal(TestCredentials.OtherSecret, await provider.GetSecretAsync(TestCredentials.OtherClientId, CancellationToken));
    }

    [Theory]
    [InlineData("partner-unknown")]
    [InlineData("")]
    [InlineData("PARTNER-A")]
    [InlineData("Partner-A")]
    [InlineData("partner-a ")]
    public async Task GetSecretAsync_UnknownOrDifferentlyCasedClient_ReturnsNull(string clientId)
    {
        InMemoryHmacSecretProvider provider = TestCredentials.CreateSecretProvider();

        Assert.Null(await provider.GetSecretAsync(clientId, CancellationToken));
    }

    [Fact]
    public async Task Constructor_ClientIdsDifferingOnlyByCase_AreDistinctClients()
    {
        var provider = new InMemoryHmacSecretProvider(
        [
            KeyValuePair.Create("partner", "lower-secret"),
            KeyValuePair.Create("PARTNER", "upper-secret"),
        ]);

        Assert.Equal("lower-secret", await provider.GetSecretAsync("partner", CancellationToken));
        Assert.Equal("upper-secret", await provider.GetSecretAsync("PARTNER", CancellationToken));
    }

    [Fact]
    public async Task Constructor_EmptyCollection_KnowsNoClients()
    {
        var provider = new InMemoryHmacSecretProvider([]);

        Assert.Null(await provider.GetSecretAsync(TestCredentials.ClientId, CancellationToken));
    }

    [Fact]
    public async Task Constructor_SnapshotsTheSource()
    {
        var source = new Dictionary<string, string>(StringComparer.Ordinal) { [TestCredentials.ClientId] = TestCredentials.Secret };
        var provider = new InMemoryHmacSecretProvider(source);

        source[TestCredentials.ClientId] = "changed";
        source["late-client"] = "late-secret";

        Assert.Equal(TestCredentials.Secret, await provider.GetSecretAsync(TestCredentials.ClientId, CancellationToken));
        Assert.Null(await provider.GetSecretAsync("late-client", CancellationToken));
    }

    [Fact]
    public void Constructor_DuplicateClientId_ThrowsArgumentException()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            "secrets",
            () => new InMemoryHmacSecretProvider(
            [
                KeyValuePair.Create(TestCredentials.ClientId, "first"),
                KeyValuePair.Create(TestCredentials.ClientId, "second"),
            ]));

        Assert.Contains(TestCredentials.ClientId, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    public void Constructor_EmptyOrWhitespaceClientId_ThrowsArgumentException(string clientId)
    {
        Assert.Throws<ArgumentException>(
            "secrets",
            () => new InMemoryHmacSecretProvider([KeyValuePair.Create(clientId, TestCredentials.Secret)]));
    }

    [Fact]
    public void Constructor_NullClientId_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            "secrets",
            () => new InMemoryHmacSecretProvider([new KeyValuePair<string, string>(null!, TestCredentials.Secret)]));
    }

    [Fact]
    public void Constructor_EmptySecret_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(
            "secrets",
            () => new InMemoryHmacSecretProvider([KeyValuePair.Create(TestCredentials.ClientId, string.Empty)]));
    }

    [Fact]
    public void Constructor_NullSecret_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            "secrets",
            () => new InMemoryHmacSecretProvider([new KeyValuePair<string, string>(TestCredentials.ClientId, null!)]));
    }

    [Fact]
    public void Constructor_NullCollection_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("secrets", () => new InMemoryHmacSecretProvider(null!));
    }

    [Fact]
    public async Task GetSecretAsync_NullClientId_ThrowsArgumentNullException()
    {
        InMemoryHmacSecretProvider provider = TestCredentials.CreateSecretProvider();

        await Assert.ThrowsAsync<ArgumentNullException>(
            "clientId",
            () => provider.GetSecretAsync(null!, CancellationToken).AsTask());
    }
}
