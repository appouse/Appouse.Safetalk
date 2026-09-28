using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacServerConfigurationTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public static TheoryData<string, string> InvalidValues { get; } = new()
    {
        { "AllowedClockSkew", "five minutes" },
        { "AllowedClockSkew", "PT5M" },
        { "MaxBodySize", "abc" },
        { "MaxBodySize", "1.5" },
        { "MaxBodySize", "1,024" },
        { "MaxBodySize", "99999999999" },
        { "MaxBodySize", "1e6" },
        { "EnableReplayProtection", "yes" },
        { "EnableReplayProtection", "1" },
        { "EnableReplayProtection", "on" },
        { "EnforcementMode", "Everything" },
        { "EnforcementMode", "2" },
        { "EnforcementMode", "-1" },
        { "EnforcementMode", "0" },
        { "EnforcementMode", "1" },
        { "EnforcementMode", " 1 " },
        { "EnforcementMode", "+1" },
        { "EnforcementMode", "0x1" },
        { "EnforcementMode", "AllRequests,MarkedEndpointsOnly" },
        { "EnforcementMode", "MarkedEndpointsOnly,AllRequests" },
        { "EnforcementMode", "AllRequests, MarkedEndpointsOnly" },
        { "EnforcementMode", "MarkedEndpointsOnly,MarkedEndpointsOnly" },
        { "EnforcementMode", "Marked Endpoints Only" },
        { "EnforcementMode", "MarkedEndpoints" },
        { "EnforcementMode", "None" },
    };

    [Fact]
    public void AddHmacServer_Configuration_BindsAllKeys()
    {
        using ServiceProvider provider = BuildProvider(
            ("Safetalk:AllowedClockSkew", "00:02:30"),
            ("Safetalk:MaxBodySize", "1024"),
            ("Safetalk:EnableReplayProtection", "true"),
            ("Safetalk:EnforcementMode", "MarkedEndpointsOnly"));

        HmacServerOptions options = provider.GetRequiredService<IOptions<HmacServerOptions>>().Value;

        Assert.Equal(TimeSpan.FromSeconds(150), options.AllowedClockSkew);
        Assert.Equal(1024, options.MaxBodySize);
        Assert.True(options.EnableReplayProtection);
        Assert.Equal(HmacEnforcementMode.MarkedEndpointsOnly, options.EnforcementMode);
    }

    [Fact]
    public void AddHmacServer_ConfigurationWithoutKeys_KeepsDefaults()
    {
        using ServiceProvider provider = BuildProvider(("Other:Key", "value"));

        HmacServerOptions options = provider.GetRequiredService<IOptions<HmacServerOptions>>().Value;

        Assert.Equal(HmacServerOptions.DefaultAllowedClockSkew, options.AllowedClockSkew);
        Assert.Equal(HmacServerOptions.DefaultMaxBodySize, options.MaxBodySize);
        Assert.False(options.EnableReplayProtection);
        Assert.Equal(HmacEnforcementMode.AllRequests, options.EnforcementMode);
    }

    [Fact]
    public void AddHmacServer_ConfigurationWithBlankValues_KeepsDefaults()
    {
        using ServiceProvider provider = BuildProvider(
            ("Safetalk:AllowedClockSkew", " "),
            ("Safetalk:MaxBodySize", string.Empty),
            ("Safetalk:EnableReplayProtection", "\t"),
            ("Safetalk:EnforcementMode", string.Empty));

        HmacServerOptions options = provider.GetRequiredService<IOptions<HmacServerOptions>>().Value;

        Assert.Equal(HmacServerOptions.DefaultAllowedClockSkew, options.AllowedClockSkew);
        Assert.Equal(HmacServerOptions.DefaultMaxBodySize, options.MaxBodySize);
        Assert.False(options.EnableReplayProtection);
        Assert.Equal(HmacEnforcementMode.AllRequests, options.EnforcementMode);
    }

    [Theory]
    [InlineData("markedendpointsonly", HmacEnforcementMode.MarkedEndpointsOnly)]
    [InlineData("MARKEDENDPOINTSONLY", HmacEnforcementMode.MarkedEndpointsOnly)]
    [InlineData("allrequests", HmacEnforcementMode.AllRequests)]
    [InlineData(" AllRequests ", HmacEnforcementMode.AllRequests)]
    [InlineData(" markedendpointsonly ", HmacEnforcementMode.MarkedEndpointsOnly)]
    [InlineData("\tMarkedEndpointsOnly\r\n", HmacEnforcementMode.MarkedEndpointsOnly)]
    public void AddHmacServer_Configuration_EnforcementModeIsCaseInsensitive(string value, HmacEnforcementMode expected)
    {
        using ServiceProvider provider = BuildProvider(("Safetalk:EnforcementMode", value));

        Assert.Equal(expected, provider.GetRequiredService<IOptions<HmacServerOptions>>().Value.EnforcementMode);
    }

    [Theory]
    [InlineData("True", true)]
    [InlineData("TRUE", true)]
    [InlineData("false", false)]
    [InlineData("False", false)]
    public void AddHmacServer_Configuration_BooleanIsCaseInsensitive(string value, bool expected)
    {
        using ServiceProvider provider = BuildProvider(("Safetalk:EnableReplayProtection", value));

        Assert.Equal(expected, provider.GetRequiredService<IOptions<HmacServerOptions>>().Value.EnableReplayProtection);
    }

    [Theory]
    [InlineData("0", 0)]
    [InlineData("2147483647", int.MaxValue)]
    [InlineData(" 4096 ", 4096)]
    public void AddHmacServer_Configuration_MaxBodySizeBoundaries(string value, int expected)
    {
        using ServiceProvider provider = BuildProvider(("Safetalk:MaxBodySize", value));

        Assert.Equal(expected, provider.GetRequiredService<IOptions<HmacServerOptions>>().Value.MaxBodySize);
    }

    [Theory]
    [InlineData("00:00:01", 1)]
    [InlineData("1.00:00:00", 86_400)]
    [InlineData("00:10:00", 600)]
    public void AddHmacServer_Configuration_ClockSkewUsesInvariantTimeSpanFormat(string value, int expectedSeconds)
    {
        using ServiceProvider provider = BuildProvider(("Safetalk:AllowedClockSkew", value));

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), provider.GetRequiredService<IOptions<HmacServerOptions>>().Value.AllowedClockSkew);
    }

    [Theory]
    [MemberData(nameof(InvalidValues))]
    public void AddHmacServer_InvalidValue_ThrowsInvalidOperationExceptionNamingKeyPathAtResolution(string key, string value)
    {
        using ServiceProvider provider = BuildProvider(("Safetalk:" + key, value));

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<IOptions<HmacServerOptions>>().Value);

        Assert.Contains("Safetalk:" + key, exception.Message, StringComparison.Ordinal);
        Assert.Contains(value, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddHmacServer_EnforcementModeWithCombinedNames_IsRejected()
    {
        // Enum.TryParse accepts comma-separated names and ORs them, which would turn this typo into
        // MarkedEndpointsOnly and silently relax enforcement.
        using ServiceProvider provider = BuildProvider(("Safetalk:EnforcementMode", "AllRequests,MarkedEndpointsOnly"));

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<IOptions<HmacServerOptions>>().Value);

        Assert.Contains("Safetalk:EnforcementMode", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(InvalidValues))]
    public async Task AddHmacServer_InvalidValue_FailsOnHostStart(string key, string value)
    {
        IConfiguration configuration = BuildConfiguration(("Safetalk:" + key, value));
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Services.AddHmacServer(configuration.GetSection("Safetalk"));
        using IHost host = builder.Build();

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(CancellationToken));

        Assert.Contains("Safetalk:" + key, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("AllowedClockSkew", "00:00:00")]
    [InlineData("AllowedClockSkew", "2.00:00:00")]
    [InlineData("AllowedClockSkew", "-00:05:00")]
    [InlineData("AllowedClockSkew", "5")]
    [InlineData("MaxBodySize", "-1")]
    public async Task AddHmacServer_ParsableButOutOfRangeValue_FailsValidationOnHostStart(string key, string value)
    {
        IConfiguration configuration = BuildConfiguration(("Safetalk:" + key, value));
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Services.AddHmacServer(configuration.GetSection("Safetalk"));
        using IHost host = builder.Build();

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(CancellationToken));

        Assert.Contains(exception.Failures, failure => failure.Contains(key, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AddHmacServer_ValidConfiguration_HostStarts()
    {
        IConfiguration configuration = BuildConfiguration(
            ("Safetalk:AllowedClockSkew", "00:01:00"),
            ("Safetalk:Clients:partner-a", "secret-a"));
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Services.AddHmacServer(configuration.GetSection("Safetalk"));
        using IHost host = builder.Build();

        await host.StartAsync(CancellationToken);
        await host.StopAsync(CancellationToken);
    }

    [Fact]
    public void AddHmacServer_RootConfiguration_NamesBareKey()
    {
        var services = new ServiceCollection();
        services.AddHmacServer(BuildConfiguration(("MaxBodySize", "abc")));
        using ServiceProvider provider = services.BuildServiceProvider();

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<IOptions<HmacServerOptions>>().Value);

        Assert.Contains("'MaxBodySize'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddHmacServer_NestedSection_NamesFullKeyPath()
    {
        var services = new ServiceCollection();
        services.AddHmacServer(BuildConfiguration(("App:Security:Safetalk:MaxBodySize", "abc")).GetSection("App:Security:Safetalk"));
        using ServiceProvider provider = services.BuildServiceProvider();

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<IOptions<HmacServerOptions>>().Value);

        Assert.Contains("App:Security:Safetalk:MaxBodySize", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Reload_UpdatesOptionsMonitorAndNotifiesListeners()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Safetalk:MaxBodySize", "1024"),
            new("Safetalk:EnforcementMode", "AllRequests"),
        ]);
        var services = new ServiceCollection();
        services.AddHmacServer(root.GetSection("Safetalk"));
        using ServiceProvider provider = services.BuildServiceProvider();
        IOptionsMonitor<HmacServerOptions> monitor = provider.GetRequiredService<IOptionsMonitor<HmacServerOptions>>();
        Assert.Equal(1024, monitor.CurrentValue.MaxBodySize);
        var notifications = new List<HmacServerOptions>();
        using IDisposable? subscription = monitor.OnChange(notifications.Add);

        source.Replace(
        [
            new("Safetalk:MaxBodySize", "2048"),
            new("Safetalk:EnforcementMode", "MarkedEndpointsOnly"),
            new("Safetalk:EnableReplayProtection", "true"),
            new("Safetalk:AllowedClockSkew", "00:00:30"),
        ]);

        HmacServerOptions current = monitor.CurrentValue;
        Assert.Equal(2048, current.MaxBodySize);
        Assert.Equal(HmacEnforcementMode.MarkedEndpointsOnly, current.EnforcementMode);
        Assert.True(current.EnableReplayProtection);
        Assert.Equal(TimeSpan.FromSeconds(30), current.AllowedClockSkew);
        Assert.NotEmpty(notifications);
    }

    [Fact]
    public void Reload_RemovedKey_RevertsToDefault()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Safetalk:MaxBodySize", "1024"),
            new("Safetalk:EnableReplayProtection", "true"),
        ]);
        var services = new ServiceCollection();
        services.AddHmacServer(root.GetSection("Safetalk"));
        using ServiceProvider provider = services.BuildServiceProvider();
        IOptionsMonitor<HmacServerOptions> monitor = provider.GetRequiredService<IOptionsMonitor<HmacServerOptions>>();
        Assert.True(monitor.CurrentValue.EnableReplayProtection);

        source.Replace([]);

        Assert.Equal(HmacServerOptions.DefaultMaxBodySize, monitor.CurrentValue.MaxBodySize);
        Assert.False(monitor.CurrentValue.EnableReplayProtection);
    }

    [Fact]
    public void Reload_ToInvalidValue_FailsClosedUntilFixed()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Safetalk:MaxBodySize", "1024"),
        ]);
        var services = new ServiceCollection();
        services.AddHmacServer(root.GetSection("Safetalk"));
        using ServiceProvider provider = services.BuildServiceProvider();
        IOptionsMonitor<HmacServerOptions> monitor = provider.GetRequiredService<IOptionsMonitor<HmacServerOptions>>();
        Assert.Equal(1024, monitor.CurrentValue.MaxBodySize);

        // The options monitor rebuilds the options inside the reload callback, so the reload itself may report the error.
        Record.Exception(() => source.Update("Safetalk:MaxBodySize", "abc"));
        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => monitor.CurrentValue);
        Record.Exception(() => source.Update("Safetalk:MaxBodySize", "4096"));

        Assert.Contains("Safetalk:MaxBodySize", exception.Message, StringComparison.Ordinal);
        Assert.Equal(4096, monitor.CurrentValue.MaxBodySize);
    }

    [Fact]
    public void AddHmacServer_ConfigurationThenDelegate_BothApplyInOrder()
    {
        var services = new ServiceCollection();
        services.AddHmacServer(BuildConfiguration(("Safetalk:MaxBodySize", "1024"), ("Safetalk:EnableReplayProtection", "true")).GetSection("Safetalk"));
        services.AddHmacServer(options => options.MaxBodySize = 2048);
        using ServiceProvider provider = services.BuildServiceProvider();

        HmacServerOptions options = provider.GetRequiredService<IOptions<HmacServerOptions>>().Value;

        Assert.Equal(2048, options.MaxBodySize);
        Assert.True(options.EnableReplayProtection);
        Assert.Single(services, d => d.ServiceType == typeof(IHmacRequestValidator));
    }

    [Fact]
    public void AddHmacServer_ConfigurationDoesNotAffectNamedOptions()
    {
        using ServiceProvider provider = BuildProvider(("Safetalk:MaxBodySize", "1024"));

        HmacServerOptions named = provider.GetRequiredService<IOptionsMonitor<HmacServerOptions>>().Get("other");

        Assert.Equal(HmacServerOptions.DefaultMaxBodySize, named.MaxBodySize);
    }

    [Fact]
    public async Task AddHmacServer_ClientsChild_RegistersConfigurationSecretProvider()
    {
        var services = new ServiceCollection();
        IHmacServerBuilder builder = services.AddHmacServer(BuildConfiguration(
            ("Safetalk:Clients:partner-a", "secret-a"),
            ("Safetalk:Clients:partner-b:Secret", "secret-b")).GetSection("Safetalk"));
        await using ServiceProvider provider = services.BuildServiceProvider();

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        IHmacSecretProvider secrets = provider.GetRequiredService<IHmacSecretProvider>();
        Assert.IsType<ConfigurationHmacSecretProvider>(secrets);
        Assert.Same(secrets, provider.GetRequiredService<IHmacSecretProvider>());
        Assert.Equal("secret-a", await secrets.GetSecretAsync("partner-a", CancellationToken));
        Assert.Equal("secret-b", await secrets.GetSecretAsync("partner-b", CancellationToken));
        Assert.Same(services, builder.Services);
    }

    [Fact]
    public void AddHmacServer_WithoutClientsChild_RegistersNoSecretProvider()
    {
        var services = new ServiceCollection();

        services.AddHmacServer(BuildConfiguration(("Safetalk:MaxBodySize", "1024")).GetSection("Safetalk"));

        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IHmacSecretProvider));
    }

    [Fact]
    public void AddHmacServer_ClientsChildThenAddSecretProvider_CustomProviderWins()
    {
        var services = new ServiceCollection();
        services.AddSingleton<InstanceTracker>();

        services.AddHmacServer(BuildConfiguration(("Safetalk:Clients:partner-a", "secret-a")).GetSection("Safetalk"))
            .AddSecretProvider<ScopedSecretProvider>();

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        Assert.Equal(typeof(ScopedSecretProvider), descriptor.ImplementationType);
    }

    [Fact]
    public async Task AddHmacServer_ClientsChild_ReplacesEarlierInMemorySecrets()
    {
        var services = new ServiceCollection();
        services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);

        services.AddHmacServer(BuildConfiguration(("Safetalk:Clients:partner-z", "secret-z")).GetSection("Safetalk"));
        await using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        IHmacSecretProvider secrets = provider.GetRequiredService<IHmacSecretProvider>();
        Assert.Equal("secret-z", await secrets.GetSecretAsync("partner-z", CancellationToken));
        Assert.Null(await secrets.GetSecretAsync(TestCredentials.ClientId, CancellationToken));
    }

    [Fact]
    public async Task AddSecretsFromConfiguration_ReplacesPreviousProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<InstanceTracker>();

        IHmacServerBuilder builder = services.AddHmacServer()
            .AddInMemorySecrets(TestCredentials.Secrets)
            .AddSecretProvider<ScopedSecretProvider>()
            .AddSecretsFromConfiguration(BuildConfiguration(("Partners:partner-z", "secret-z")).GetSection("Partners"));
        await using ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        IHmacSecretProvider secrets = provider.GetRequiredService<IHmacSecretProvider>();
        Assert.IsType<ConfigurationHmacSecretProvider>(secrets);
        Assert.Equal("secret-z", await secrets.GetSecretAsync("partner-z", CancellationToken));
        Assert.Null(await secrets.GetSecretAsync(TestCredentials.ClientId, CancellationToken));
        Assert.Empty(provider.GetRequiredService<InstanceTracker>().Instances);
        Assert.NotNull(builder);
    }

    [Fact]
    public void AddSecretsFromConfiguration_ThenAddInMemorySecrets_InMemoryWins()
    {
        var services = new ServiceCollection();

        services.AddHmacServer()
            .AddSecretsFromConfiguration(BuildConfiguration(("Partners:partner-z", "secret-z")).GetSection("Partners"))
            .AddInMemorySecrets(TestCredentials.Secrets);

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        Assert.IsType<InMemoryHmacSecretProvider>(descriptor.ImplementationInstance);
    }

    [Fact]
    public async Task AddSecretsFromConfiguration_FollowsReloads()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Partners:partner-a", "secret-a"),
        ]);
        var services = new ServiceCollection();
        services.AddHmacServer().AddSecretsFromConfiguration(root.GetSection("Partners"));
        await using ServiceProvider provider = services.BuildServiceProvider();
        IHmacSecretProvider secrets = provider.GetRequiredService<IHmacSecretProvider>();

        source.Update("Partners:partner-b", "secret-b");

        Assert.Equal("secret-a", await secrets.GetSecretAsync("partner-a", CancellationToken));
        Assert.Equal("secret-b", await secrets.GetSecretAsync("partner-b", CancellationToken));
    }

    [Fact]
    public async Task ServiceProviderDisposal_DisposesConfigurationProvider()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Partners:partner-a", "secret-a"),
        ]);
        var services = new ServiceCollection();
        services.AddHmacServer().AddSecretsFromConfiguration(root.GetSection("Partners"));
        IHmacSecretProvider secrets;
        await using (ServiceProvider provider = services.BuildServiceProvider())
        {
            secrets = provider.GetRequiredService<IHmacSecretProvider>();
            Assert.Equal("secret-a", await secrets.GetSecretAsync("partner-a", CancellationToken));
        }

        source.Update("Partners:partner-a", "secret-a-rotated");

        // A disposed provider no longer follows reloads, so it must not serve its stale snapshot either.
        await Assert.ThrowsAsync<ObjectDisposedException>(() => secrets.GetSecretAsync("partner-a", CancellationToken).AsTask());
    }

    [Fact]
    public async Task AddSecretsFromConfiguration_AmbiguousClient_IsLoggedThroughTheContainerLoggerFactory()
    {
        var logs = new LogCollector();
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection(
            [
                new KeyValuePair<string, string?>("Partners:partner-a", "secret-a"),
                new KeyValuePair<string, string?>("Partners:partner-b", "secret-b"),
            ])
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Partners:partner-a:Secret", "secret-a-object")])
            .Build();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(logs));
        services.AddHmacServer().AddSecretsFromConfiguration(root.GetSection("Partners"));
        await using ServiceProvider provider = services.BuildServiceProvider();

        IHmacSecretProvider secrets = provider.GetRequiredService<IHmacSecretProvider>();

        Assert.Null(await secrets.GetSecretAsync("partner-a", CancellationToken));
        Assert.Equal("secret-b", await secrets.GetSecretAsync("partner-b", CancellationToken));
        LogRecord log = Assert.Single(logs.Find<ConfigurationHmacSecretProvider>(20));
        Assert.Equal(LogLevel.Error, log.Level);
        Assert.Equal("Partners:partner-a", log.Properties["Path"]);
    }

    [Fact]
    public async Task AddHmacServer_ClientsChildWithAmbiguousClient_LogsAndRejectsItThroughThePipeline()
    {
        var logs = new LogCollector();
        var vault = new ReloadableConfigurationSource(
        [
            new("Safetalk:Clients:" + TestCredentials.ClientId + ":Secret", "secret-from-vault"),
        ]);
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                builder.Logging.AddProvider(logs);
                builder.Configuration.AddInMemoryCollection(
                [
                    new KeyValuePair<string, string?>("Safetalk:Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
                    new KeyValuePair<string, string?>("Safetalk:Clients:" + TestCredentials.OtherClientId, TestCredentials.OtherSecret),
                ]);
                ((IConfigurationBuilder)builder.Configuration).Add(vault);
                builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));
            },
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.MapGet("/b2b", (HttpContext context) => context.GetHmacClientId() ?? "anonymous");
            });

        using HttpResponseMessage ambiguous = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b"));
        using HttpResponseMessage other = await app.SendAsync(app.CreateSignedRequest(
            HttpMethod.Get, "/b2b", clientId: TestCredentials.OtherClientId, secret: TestCredentials.OtherSecret));
        vault.Provider.Replace([]);
        using HttpResponseMessage restored = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b?n=2"));

        Assert.Equal(HttpStatusCode.Unauthorized, ambiguous.StatusCode);
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
        Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await restored.Content.ReadAsStringAsync(CancellationToken));
        Assert.Single(logs.Find<ConfigurationHmacSecretProvider>(20));
    }

    [Fact]
    public void NullArguments_ThrowArgumentNullException()
    {
        IConfiguration configuration = BuildConfiguration();
        IHmacServerBuilder builder = new ServiceCollection().AddHmacServer();

        Assert.Throws<ArgumentNullException>("services", () => HmacServerServiceCollectionExtensions.AddHmacServer(null!, configuration));
        Assert.Throws<ArgumentNullException>("configuration", () => new ServiceCollection().AddHmacServer((IConfiguration)null!));
        Assert.Throws<ArgumentNullException>("builder", () => HmacServerBuilderExtensions.AddSecretsFromConfiguration(null!, configuration));
        Assert.Throws<ArgumentNullException>("clients", () => builder.AddSecretsFromConfiguration(null!));
    }

    [Fact]
    public void ClientsConfigurationKey_IsClients()
    {
        Assert.Equal("Clients", HmacServerServiceCollectionExtensions.ClientsConfigurationKey);
    }

    [Fact]
    public async Task Pipeline_ConfigurationReload_SwitchesEnforcementModeAndRotatesSecrets()
    {
        var source = new ReloadableConfigurationSource(
        [
            new("Safetalk:EnforcementMode", "AllRequests"),
            new("Safetalk:Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
        ]);
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                ((IConfigurationBuilder)builder.Configuration).Add(source);
                builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));
            },
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.MapGet("/plain", (HttpContext context) => context.GetHmacClientId() ?? "anonymous");
                pipeline.MapGet("/b2b", (HttpContext context) => context.GetHmacClientId() ?? "anonymous").RequireHmacValidation();
            });

        using HttpResponseMessage unsignedBefore = await app.SendAsync(Unsigned("/plain"));
        source.Provider.Replace(
        [
            new("Safetalk:EnforcementMode", "MarkedEndpointsOnly"),
            new("Safetalk:Clients:" + TestCredentials.ClientId, "rotated-secret"),
        ]);
        using HttpResponseMessage unsignedAfter = await app.SendAsync(Unsigned("/plain"));
        using HttpResponseMessage oldSecret = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b"));
        using HttpResponseMessage newSecret = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b?n=2", secret: "rotated-secret"));

        Assert.Equal(HttpStatusCode.Unauthorized, unsignedBefore.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unsignedAfter.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, oldSecret.StatusCode);
        Assert.Equal(HttpStatusCode.OK, newSecret.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await newSecret.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task Pipeline_ConfigurationReload_EnablesReplayProtectionAtRuntime()
    {
        var source = new ReloadableConfigurationSource(
        [
            new("Safetalk:Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
        ]);
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                ((IConfigurationBuilder)builder.Configuration).Add(source);
                builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));
            },
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.MapGet("/b2b", (HttpContext context) => context.GetHmacClientId() ?? "anonymous");
            });

        using HttpResponseMessage first = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b"));
        using HttpResponseMessage second = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b"));
        source.Provider.Update("Safetalk:EnableReplayProtection", "true");
        using HttpResponseMessage third = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b"));
        using HttpResponseMessage replay = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b"));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.OK, third.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Pipeline_ClockSkewWidenedByReload_CapturedRequestCannotBeReplayed()
    {
        var source = new ReloadableConfigurationSource(
        [
            new("Safetalk:AllowedClockSkew", "00:01:00"),
            new("Safetalk:EnableReplayProtection", "true"),
            new("Safetalk:Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
        ]);
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                ((IConfigurationBuilder)builder.Configuration).Add(source);
                builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));
            },
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.MapPost("/b2b/transfer", (HttpContext context) => context.GetHmacClientId() ?? "anonymous");
            });
        byte[] body = """{"amount":100}"""u8.ToArray();
        HttpRequestMessage original = app.CreateSignedRequest(HttpMethod.Post, "/b2b/transfer", body);
        HttpRequestMessage captured = app.CreateSignedRequest(HttpMethod.Post, "/b2b/transfer", body);

        using HttpResponseMessage accepted = await app.SendAsync(original);
        source.Provider.Update("Safetalk:AllowedClockSkew", "00:05:00");
        app.Time.Advance(TimeSpan.FromMinutes(2));
        using HttpResponseMessage replay = await app.SendAsync(captured);

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    private static HttpRequestMessage Unsigned(string path) => new(HttpMethod.Get, new Uri(path, UriKind.Relative));

    private static IConfigurationRoot BuildConfiguration(params (string Key, string Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(entry => new KeyValuePair<string, string?>(entry.Key, entry.Value)))
            .Build();

    private static ServiceProvider BuildProvider(params (string Key, string Value)[] entries)
    {
        var services = new ServiceCollection();
        services.AddHmacServer(BuildConfiguration(entries).GetSection("Safetalk"));
        return services.BuildServiceProvider();
    }
}
