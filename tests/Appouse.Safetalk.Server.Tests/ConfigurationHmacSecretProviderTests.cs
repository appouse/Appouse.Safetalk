using System.Globalization;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Server.Tests;

public sealed class ConfigurationHmacSecretProviderTests
{
    private const int AmbiguousClientEventId = 20;

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task GetSecretAsync_StringChild_ReturnsItsValue()
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(("partner-a", "secret-a")));

        Assert.Equal("secret-a", await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task GetSecretAsync_ObjectChildWithSecretKey_ReturnsTheSecret()
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(("partner-b:Secret", "secret-b"), ("partner-b:Description", "Partner B")));

        Assert.Equal("secret-b", await provider.GetSecretAsync("partner-b", CancellationToken));
    }

    [Theory]
    [InlineData("secret")]
    [InlineData("SECRET")]
    public async Task GetSecretAsync_SecretKeyInDifferentCase_IsFoundBecauseConfigurationKeysAreCaseInsensitive(string key)
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(($"partner-b:{key}", "secret-b")));

        Assert.Equal("secret-b", await provider.GetSecretAsync("partner-b", CancellationToken));
    }

    [Fact]
    public async Task GetSecretAsync_MixedForms_ResolvesEveryClient()
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(
            ("partner-a", "secret-a"),
            ("partner-b:Secret", "secret-b"),
            ("partner-c", "secret-c")));

        Assert.Equal("secret-a", await provider.GetSecretAsync("partner-a", CancellationToken));
        Assert.Equal("secret-b", await provider.GetSecretAsync("partner-b", CancellationToken));
        Assert.Equal("secret-c", await provider.GetSecretAsync("partner-c", CancellationToken));
    }

    [Theory]
    [InlineData("PARTNER-A")]
    [InlineData("Partner-A")]
    [InlineData("partner-a ")]
    [InlineData(" partner-a")]
    [InlineData("partner")]
    [InlineData("")]
    public async Task GetSecretAsync_ClientIdNotMatchingOrdinally_ReturnsNull(string clientId)
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(("partner-a", "secret-a")));

        Assert.Null(await provider.GetSecretAsync(clientId, CancellationToken));
    }

    [Fact]
    public async Task GetSecretAsync_ClientIdAsWrittenInConfiguration_IsMatchedOrdinally()
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(("Partner-A", "secret-a")));

        Assert.Equal("secret-a", await provider.GetSecretAsync("Partner-A", CancellationToken));
        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task GetSecretAsync_EmptyValuesAndObjectsWithoutSecret_AreIgnored()
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(
            ("empty-string", string.Empty),
            ("empty-secret:Secret", string.Empty),
            ("no-secret:Description", "has no secret"),
            ("valid", "secret")));

        Assert.Null(await provider.GetSecretAsync("empty-string", CancellationToken));
        Assert.Null(await provider.GetSecretAsync("empty-secret", CancellationToken));
        Assert.Null(await provider.GetSecretAsync("no-secret", CancellationToken));
        Assert.Equal("secret", await provider.GetSecretAsync("valid", CancellationToken));
    }

    [Fact]
    public async Task GetSecretAsync_NonExistentSection_KnowsNoClients()
    {
        IConfigurationRoot root = new ConfigurationBuilder().Build();
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Safetalk:Clients"));

        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task GetSecretAsync_UnknownClient_ReturnsNull()
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(("partner-a", "secret-a")));

        Assert.Null(await provider.GetSecretAsync("partner-z", CancellationToken));
    }

    [Fact]
    public async Task Reload_AddsRotatesAndRemovesClients()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Safetalk:Clients:partner-a", "secret-a"),
            new("Safetalk:Clients:partner-b:Secret", "secret-b"),
        ]);
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Safetalk:Clients"));

        source.Replace(
        [
            new("Safetalk:Clients:partner-a", "secret-a-rotated"),
            new("Safetalk:Clients:partner-c:Secret", "secret-c"),
        ]);

        Assert.Equal("secret-a-rotated", await provider.GetSecretAsync("partner-a", CancellationToken));
        Assert.Null(await provider.GetSecretAsync("partner-b", CancellationToken));
        Assert.Equal("secret-c", await provider.GetSecretAsync("partner-c", CancellationToken));
    }

    [Fact]
    public async Task Reload_ValueClearedToEmpty_DisablesTheClient()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Clients:partner-a", "secret-a"),
        ]);
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"));

        source.Update("Clients:partner-a", string.Empty);

        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task Reload_SectionAppearingLater_IsPickedUp()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot([]);
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Safetalk:Clients"));

        source.Update("Safetalk:Clients:partner-a", "secret-a");

        Assert.Equal("secret-a", await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task Reload_ThroughConfigurationRoot_IsPickedUp()
    {
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:partner-a", "secret-a")])
            .Build();
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"));

        root["Clients:partner-a"] = "secret-a-rotated";
        Assert.Equal("secret-a", await provider.GetSecretAsync("partner-a", CancellationToken)); // Snapshot until reload.
        root.Reload();

        Assert.Equal("secret-a-rotated", await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task Reload_Repeatedly_KeepsFollowingChanges()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot([]);
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"));

        for (int i = 0; i < 10; i++)
        {
            string secret = "secret-" + i.ToString(CultureInfo.InvariantCulture);
            source.Update("Clients:partner-a", secret);
            Assert.Equal(secret, await provider.GetSecretAsync("partner-a", CancellationToken));
        }
    }

    [Fact]
    public async Task Dispose_ThenGetSecretAsync_ThrowsObjectDisposedExceptionInsteadOfServingStaleSecrets()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Clients:partner-a", "secret-a"),
        ]);
        var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"));

        provider.Dispose();
        source.Update("Clients:partner-a", "secret-a-rotated");

        ObjectDisposedException exception = await Assert.ThrowsAsync<ObjectDisposedException>(
            () => provider.GetSecretAsync("partner-a", CancellationToken).AsTask());
        Assert.Equal(typeof(ConfigurationHmacSecretProvider).FullName, exception.ObjectName);
    }

    [Fact]
    public async Task Dispose_ThenGetSecretAsyncForUnknownClient_AlsoThrows()
    {
        var provider = new ConfigurationHmacSecretProvider(Clients(("partner-a", "secret-a")));

        provider.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => provider.GetSecretAsync("partner-z", CancellationToken).AsTask());
    }

    [Fact]
    public async Task Dispose_NullClientIdAfterDispose_StillReportsTheArgumentFirst()
    {
        var provider = new ConfigurationHmacSecretProvider(Clients(("partner-a", "secret-a")));

        provider.Dispose();

        await Assert.ThrowsAsync<ArgumentNullException>("clientId", () => provider.GetSecretAsync(null!, CancellationToken).AsTask());
    }

    [Fact]
    public void Dispose_StopsFollowingReloads()
    {
        // The reload registration is released: later reloads no longer rebuild the snapshot (which would log again).
        var logs = new LogCollector();
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Clients:partner-a", "secret-a"),
        ]);
        var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"), logs.CreateLogger<ConfigurationHmacSecretProvider>());
        source.Update("Clients:partner-a:Secret", "other"); // Makes the client ambiguous: the reload logs it.
        Assert.Single(logs.Find<ConfigurationHmacSecretProvider>(AmbiguousClientEventId));

        provider.Dispose();
        source.Update("Clients:partner-a:Secret", "still-ambiguous");

        Assert.Single(logs.Find<ConfigurationHmacSecretProvider>(AmbiguousClientEventId));
    }

    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        var provider = new ConfigurationHmacSecretProvider(Clients(("partner-a", "secret-a")));

        provider.Dispose();
        provider.Dispose();
    }

    [Fact]
    public async Task GetSecretAsync_DuringConcurrentReloads_AlwaysReturnsACompleteSnapshot()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Clients:partner-a", "secret-0"),
        ]);
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"));

        Task reloader = Task.Run(
            () =>
            {
                for (int i = 1; i <= 200; i++)
                {
                    source.Update("Clients:partner-a", "secret-" + i.ToString(CultureInfo.InvariantCulture));
                }
            },
            CancellationToken);

        var observed = new List<string?>();
        while (!reloader.IsCompleted)
        {
            observed.Add(await provider.GetSecretAsync("partner-a", CancellationToken));
        }

        await reloader;
        Assert.All(observed, secret => Assert.StartsWith("secret-", secret, StringComparison.Ordinal));
        Assert.Equal("secret-200", await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public void Constructor_NullConfiguration_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("clients", () => new ConfigurationHmacSecretProvider(null!));
    }

    [Fact]
    public async Task GetSecretAsync_NullClientId_ThrowsArgumentNullException()
    {
        using var provider = new ConfigurationHmacSecretProvider(Clients(("partner-a", "secret-a")));

        await Assert.ThrowsAsync<ArgumentNullException>("clientId", () => provider.GetSecretAsync(null!, CancellationToken).AsTask());
    }

    [Fact]
    public async Task Validator_WithConfigurationProvider_VerifiesRequestsAndFollowsRotation()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
        ]);
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"));
        var harness = new ValidatorHarness(provider);

        HmacValidationResult before = await harness.ValidateAsync(harness.NewRequest().Build());
        source.Update("Clients:" + TestCredentials.ClientId, "rotated-secret");
        SignedRequestBuilder oldSecret = harness.NewRequest();
        SignedRequestBuilder newSecret = harness.NewRequest();
        newSecret.Secret = "rotated-secret";

        HmacValidationResult withOldSecret = await harness.ValidateAsync(oldSecret.Build());
        HmacValidationResult withNewSecret = await harness.ValidateAsync(newSecret.Build());

        Assert.True(before.Succeeded);
        Assert.Equal(HmacValidationFailure.InvalidSignature, withOldSecret.Failure);
        Assert.True(withNewSecret.Succeeded);
    }

    [Fact]
    public async Task AmbiguousClient_StringInOneSourceAndObjectInAnother_IsIgnoredAndLoggedWhileOtherClientsWork()
    {
        var logs = new LogCollector();
        var overrides = new ReloadableConfigurationSource(
        [
            new("Safetalk:Clients:partner-a:Secret", "secret-a-from-vault"),
            new("Safetalk:Clients:partner-c:Secret", "secret-c"),
        ]);
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection(
            [
                new KeyValuePair<string, string?>("Safetalk:Clients:partner-a", "secret-a-from-json"),
                new KeyValuePair<string, string?>("Safetalk:Clients:partner-b", "secret-b"),
            ])
            .Add(overrides)
            .Build();

        using var provider = new ConfigurationHmacSecretProvider(
            root.GetSection("Safetalk:Clients"),
            logs.CreateLogger<ConfigurationHmacSecretProvider>());

        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));
        Assert.Equal("secret-b", await provider.GetSecretAsync("partner-b", CancellationToken));
        Assert.Equal("secret-c", await provider.GetSecretAsync("partner-c", CancellationToken));
        LogRecord log = Assert.Single(logs.Find<ConfigurationHmacSecretProvider>(AmbiguousClientEventId));
        Assert.Equal(LogLevel.Error, log.Level);
        Assert.Equal("partner-a", log.Properties["ClientId"]);
        Assert.Equal("Safetalk:Clients:partner-a", log.Properties["Path"]);
        Assert.DoesNotContain("secret-a-from", log.Message, StringComparison.Ordinal);
        Assert.Single(logs.Records);
    }

    [Fact]
    public async Task AmbiguousClient_ReloadRemovingOneForm_RestoresTheClientAndReintroducingItIgnoresItAgain()
    {
        var logs = new LogCollector();
        var overrides = new ReloadableConfigurationSource(
        [
            new("Clients:partner-a:Secret", "secret-a-object"),
        ]);
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:partner-a", "secret-a-string")])
            .Add(overrides)
            .Build();
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"), logs.CreateLogger<ConfigurationHmacSecretProvider>());
        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));

        overrides.Provider.Replace([]);
        string? restored = await provider.GetSecretAsync("partner-a", CancellationToken);
        overrides.Provider.Replace([new("Clients:partner-a:Secret", "secret-a-object")]);
        string? ignoredAgain = await provider.GetSecretAsync("partner-a", CancellationToken);

        Assert.Equal("secret-a-string", restored);
        Assert.Null(ignoredAgain);
        Assert.Equal(2, logs.Find<ConfigurationHmacSecretProvider>(AmbiguousClientEventId).Count);
    }

    [Fact]
    public async Task AmbiguousClient_ResolvedByRemovingTheStringForm_UsesTheObjectSecret()
    {
        var strings = new ReloadableConfigurationSource([new("Clients:partner-a", "secret-a-string")]);
        IConfigurationRoot root = new ConfigurationBuilder()
            .Add(strings)
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:partner-a:Secret", "secret-a-object")])
            .Build();
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"));
        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));

        strings.Provider.Replace([]);

        Assert.Equal("secret-a-object", await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task AmbiguousClient_KeysDifferingOnlyInCase_AreMergedAndStillIgnored()
    {
        // Configuration merges keys case-insensitively, so these two entries describe the same client.
        var logs = new LogCollector();
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:partner-a", "secret-a-string")])
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:PARTNER-A:secret", "secret-a-object")])
            .Build();

        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"), logs.CreateLogger<ConfigurationHmacSecretProvider>());

        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));
        Assert.Null(await provider.GetSecretAsync("PARTNER-A", CancellationToken));
        Assert.Single(logs.Find<ConfigurationHmacSecretProvider>(AmbiguousClientEventId));
    }

    [Fact]
    public async Task AmbiguousClient_StringPlusUnrelatedChildKey_IsIgnored()
    {
        // A scalar value next to any sub-key is ambiguous, not only next to a Secret key.
        using var provider = new ConfigurationHmacSecretProvider(Clients(("partner-a", "secret-a"), ("partner-a:Description", "Partner A")));

        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task AmbiguousClient_EmptyStringInOneSourceAndObjectInAnother_IsIgnored()
    {
        // For example an empty environment variable next to a JSON object: still two forms, so fail closed.
        var logs = new LogCollector();
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:partner-a:Secret", "secret-a-object")])
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:partner-a", string.Empty)])
            .Build();

        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"), logs.CreateLogger<ConfigurationHmacSecretProvider>());

        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));
        Assert.Single(logs.Find<ConfigurationHmacSecretProvider>(AmbiguousClientEventId));
    }

    [Fact]
    public async Task AmbiguousClient_WithoutLogger_IsIgnoredWithoutThrowing()
    {
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:partner-a", "secret-a")])
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:partner-a:Secret", "secret-a-object")])
            .Build();

        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"), logger: null);

        Assert.Null(await provider.GetSecretAsync("partner-a", CancellationToken));
    }

    [Fact]
    public async Task Validator_AmbiguousClient_IsRejectedAsUnknownClient()
    {
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:" + TestCredentials.ClientId, TestCredentials.Secret)])
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Clients:" + TestCredentials.ClientId + ":Secret", TestCredentials.Secret)])
            .Build();
        using var provider = new ConfigurationHmacSecretProvider(root.GetSection("Clients"));
        var harness = new ValidatorHarness(provider);

        HmacValidationResult result = await harness.ValidateAsync(harness.NewRequest().Build());

        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
    }

    private static IConfigurationSection Clients(params (string Key, string Value)[] entries)
    {
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(entry => new KeyValuePair<string, string?>("Safetalk:Clients:" + entry.Key, entry.Value)))
            .Build();
        return root.GetSection("Safetalk:Clients");
    }
}
