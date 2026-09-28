using System.Net;
using System.Net.Http.Json;
using Appouse.Safetalk.Client;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The client-side registration APIs (<c>AddHmacClient</c>, <c>AddHmacSigning</c>) in realistic compositions.
/// </summary>
public sealed class ClientConfigurationTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AddHmacClientWithContractAndImplementation_ResolvesASigningTypedClient(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var services = new ServiceCollection();
        services
            .AddHmacClient<ISafetalkApiClient, SafetalkApiClient>(options =>
            {
                options.ClientId = TestCredentials.ClientId;
                options.Secret = TestCredentials.Secret;
            })
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<ISafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task NamedClientsWithDifferentCredentials_EachAuthenticatesAsItsOwnClient(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var services = new ServiceCollection();
        services.AddHttpClient("partner-a-api")
            .AddHmacSigning(options =>
            {
                options.ClientId = TestCredentials.ClientId;
                options.Secret = TestCredentials.Secret;
            })
            .UseServer(server);
        services.AddHttpClient("partner-b-api")
            .AddHmacSigning(options =>
            {
                options.ClientId = TestCredentials.OtherClientId;
                options.Secret = TestCredentials.OtherSecret;
            })
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        IHttpClientFactory factory = clientServices.GetRequiredService<IHttpClientFactory>();
        using HttpClient partnerA = factory.CreateClient("partner-a-api");
        using HttpClient partnerB = factory.CreateClient("partner-b-api");

        WhoAmIResponse? a = await partnerA.GetFromJsonAsync<WhoAmIResponse>(new Uri("/api/whoami", UriKind.Relative), ct);
        WhoAmIResponse? b = await partnerB.GetFromJsonAsync<WhoAmIResponse>(new Uri("/api/whoami", UriKind.Relative), ct);

        Assert.Equal(TestCredentials.ClientId, a?.ClientId);
        Assert.Equal(TestCredentials.OtherClientId, b?.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task GenericHost_TypedClientResolvedFromHost_SignsRequests(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
        builder.Services
            .AddHmacClient<SafetalkApiClient>(options =>
            {
                options.ClientId = TestCredentials.OtherClientId;
                options.Secret = TestCredentials.OtherSecret;
            })
            .UseServer(server);
        using IHost host = builder.Build();
        await host.StartAsync(ct);

        WhoAmIResponse whoAmI = await host.Services.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);
        await host.StopAsync(ct);

        Assert.Equal(TestCredentials.OtherClientId, whoAmI.ClientId);
    }

    [Fact]
    public async Task GenericHost_InvalidClientOptions_FailsAtStartupInsteadOfOnFirstRequest()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
        builder.Services.AddHmacClient<SafetalkApiClient>(options => options.ClientId = "partner-a");
        using IHost host = builder.Build();

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(ct));

        Assert.Contains(exception.Failures, failure => failure.Contains(nameof(HmacClientOptions.Secret), StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task CredentialsChangedInOptionsMonitor_AreUsedByTheNextRequestOnTheSameHandler(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var current = new HmacClientOptions { ClientId = TestCredentials.ClientId, Secret = TestCredentials.Secret };
        var services = new ServiceCollection();
        services
            .AddHmacClient<SafetalkApiClient>(options =>
            {
                options.ClientId = current.ClientId;
                options.Secret = current.Secret;
            })
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse before = await client.GetWhoAmIAsync(ct);
        current.ClientId = TestCredentials.OtherClientId;
        current.Secret = TestCredentials.OtherSecret;
        clientServices.GetRequiredService<IOptionsMonitorCache<HmacClientOptions>>().Clear(); // What a change notification does.
        WhoAmIResponse after = await client.GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, before.ClientId);
        Assert.Equal(TestCredentials.OtherClientId, after.ClientId);
    }

    /// <summary>
    /// The client sample registers the typed client with <c>AddHmacClient&lt;TClient&gt;(IConfiguration)</c>: the base
    /// address and credentials come from the section, and a reload (a rotated secret) applies to the next request
    /// without a restart.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task CredentialsBoundFromConfigurationAsInTheSample_AreRotatedWhenConfigurationReloads(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Safetalk:BaseAddress"] = server.BaseAddress.AbsoluteUri,
            ["Safetalk:ClientId"] = TestCredentials.ClientId,
            ["Safetalk:Secret"] = TestCredentials.Secret,
        });
        builder.Services
            .AddHmacClient<SafetalkApiClient>(builder.Configuration.GetSection("Safetalk"))
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler); // No UseServer: the base address comes from configuration.
        using IHost host = builder.Build();
        await host.StartAsync(ct);
        SafetalkApiClient client = host.Services.GetRequiredService<SafetalkApiClient>();
        var configuration = (IConfigurationRoot)host.Services.GetRequiredService<IConfiguration>();

        WhoAmIResponse before = await client.GetWhoAmIAsync(ct);
        configuration["Safetalk:ClientId"] = TestCredentials.OtherClientId;
        configuration["Safetalk:Secret"] = TestCredentials.OtherSecret;
        configuration.Reload(); // What a reloadable source (Key Vault with ReloadInterval, JSON file watcher) does.
        using HttpResponseMessage after = await client.GetAsync("/api/whoami", ct);
        await host.StopAsync(ct);

        Assert.Equal(TestCredentials.ClientId, before.ClientId);
        WhoAmIResponse rotated = await after.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(TestCredentials.OtherClientId, rotated.ClientId);
    }

    /// <summary>
    /// A delegate that binds configuration itself is evaluated again when a change token source is registered for the
    /// client's options name: the signing handler resolves the named options on every request.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task CredentialsBoundFromConfiguration_WithChangeTokenSourceForTheClientName_AreRotatedWhenConfigurationReloads(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Safetalk:ClientId"] = TestCredentials.ClientId,
            ["Safetalk:Secret"] = TestCredentials.Secret,
        });
        IHttpClientBuilder clientBuilder = builder.Services
            .AddHmacClient<SafetalkApiClient>(options => builder.Configuration.GetSection("Safetalk").Bind(options))
            .UseServer(server);
        builder.Services.AddSingleton<IOptionsChangeTokenSource<HmacClientOptions>>(
            new ConfigurationChangeTokenSource<HmacClientOptions>(clientBuilder.Name, builder.Configuration));
        using IHost host = builder.Build();
        await host.StartAsync(ct);
        SafetalkApiClient client = host.Services.GetRequiredService<SafetalkApiClient>();
        var configuration = (IConfigurationRoot)host.Services.GetRequiredService<IConfiguration>();

        WhoAmIResponse before = await client.GetWhoAmIAsync(ct);
        configuration["Safetalk:ClientId"] = TestCredentials.OtherClientId;
        configuration["Safetalk:Secret"] = TestCredentials.OtherSecret;
        configuration.Reload();
        WhoAmIResponse after = await client.GetWhoAmIAsync(ct);
        await host.StopAsync(ct);

        Assert.Equal(TestCredentials.ClientId, before.ClientId);
        Assert.Equal(TestCredentials.OtherClientId, after.ClientId);
    }

    /// <summary>
    /// DOCUMENTED: options configured with a plain delegate are evaluated once. A reload of a configuration the delegate
    /// happens to read is not observed; use the <see cref="IConfiguration"/> overload for rotation.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task DelegateConfiguredOptions_AreEvaluatedOnce_AndIgnoreConfigurationReloads(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        IConfigurationRoot configuration = CreateClientConfiguration(server.BaseAddress, TestCredentials.ClientId, TestCredentials.Secret);
        var services = new ServiceCollection();
        services
            .AddHmacClient<SafetalkApiClient>(options => configuration.GetSection("OrdersApi").Bind(options))
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse before = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);
        configuration["OrdersApi:ClientId"] = TestCredentials.OtherClientId;
        configuration["OrdersApi:Secret"] = TestCredentials.OtherSecret;
        configuration.Reload();
        WhoAmIResponse after = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, before.ClientId);
        Assert.Equal(TestCredentials.ClientId, after.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AddHmacClientWithContractAndImplementation_FromConfiguration_UsesItsBaseAddressAndCredentials(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        IConfigurationRoot configuration = CreateClientConfiguration(server.BaseAddress, TestCredentials.OtherClientId, TestCredentials.OtherSecret);
        var services = new ServiceCollection();
        services
            .AddHmacClient<ISafetalkApiClient, SafetalkApiClient>(configuration.GetSection("OrdersApi"))
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<ISafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.OtherClientId, whoAmI.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task NamedClientFromConfiguration_IsCreatedWithItsBaseAddressAndRotatesItsSecretOnReload(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        const string RotatedSecret = "cm90YXRlZC1zZWNyZXQtb2YtcGFydG5lci1hLTIwMjYtMDk=";
        var serverSecrets = new RotatingSecretProvider();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddSecretProvider(_ => serverSecrets, ServiceLifetime.Singleton) },
            ct);
        IConfigurationRoot configuration = CreateClientConfiguration(server.BaseAddress, TestCredentials.ClientId, TestCredentials.Secret);
        var services = new ServiceCollection();
        services
            .AddHmacClient("orders-api", configuration.GetSection("OrdersApi"))
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler);
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        IHttpClientFactory factory = clientServices.GetRequiredService<IHttpClientFactory>();

        using HttpClient beforeClient = factory.CreateClient("orders-api");
        using HttpResponseMessage before = await beforeClient.GetAsync(new Uri("api/whoami", UriKind.Relative), ct);
        serverSecrets.Set(TestCredentials.ClientId, RotatedSecret); // The partner rotated the secret on the server first...
        using HttpResponseMessage stale = await beforeClient.GetAsync(new Uri("api/whoami", UriKind.Relative), ct);
        configuration["OrdersApi:Secret"] = RotatedSecret;           // ...then in the client's configuration store.
        configuration.Reload();
        using HttpResponseMessage rotated = await beforeClient.GetAsync(new Uri("api/whoami", UriKind.Relative), ct);

        Assert.Equal(server.BaseAddress, beforeClient.BaseAddress);
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        stale.AssertUnauthorized();
        WhoAmIResponse whoAmI = await rotated.ReadOkJsonAsync<WhoAmIResponse>(ct); // Same HttpClient, same handler, new secret.
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    /// <summary>
    /// The base address is applied when an <see cref="HttpClient"/> is created, so after a reload newly created clients
    /// target the new address (for example a partner moving its API to another host).
    /// </summary>
    [Fact]
    public async Task BaseAddressChangedOnReload_IsUsedByNewlyCreatedClients()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer first = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using SafetalkServer second = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        IConfigurationRoot configuration = CreateClientConfiguration(first.BaseAddress, TestCredentials.ClientId, TestCredentials.Secret);
        var services = new ServiceCollection();
        services
            .AddHmacClient<SafetalkApiClient>(configuration.GetSection("OrdersApi"))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { UseCookies = false });
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse before = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);
        configuration["OrdersApi:BaseAddress"] = second.BaseAddress.AbsoluteUri;
        configuration.Reload();
        WhoAmIResponse after = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, before.ClientId);
        Assert.Equal(TestCredentials.ClientId, after.ClientId);
        Assert.True(Assert.Single(first.ValidationResults).Succeeded);
        Assert.True(Assert.Single(second.ValidationResults).Succeeded);
    }

    /// <summary>
    /// A configured base address with a path (the API behind <c>UsePathBase("/base")</c>): relative request URIs are
    /// resolved against it and the full path, base included, is signed and verified.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ConfiguredBaseAddressWithPathBase_RelativeRequestsAreSignedIncludingTheBase(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { PathBase = "/base" }, ct);
        IConfigurationRoot configuration = CreateClientConfiguration(new Uri(server.BaseAddress, "base/"), TestCredentials.ClientId, TestCredentials.Secret);
        var services = new ServiceCollection();
        services
            .AddHmacClient("orders-api", configuration.GetSection("OrdersApi"))
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler);
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        using HttpClient client = clientServices.GetRequiredService<IHttpClientFactory>().CreateClient("orders-api");

        using HttpResponseMessage response = await client.GetAsync(new Uri("inspect/orders?id=5", UriKind.Relative), ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("/base", info.PathBase);
        Assert.Equal("/inspect/orders", info.Path);
        Assert.Equal(TestCredentials.ClientId, info.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ConfigureHttpClientCalledAfterAddHmacClient_OverridesTheConfiguredBaseAddress(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        IConfigurationRoot configuration = CreateClientConfiguration(new Uri("http://unreachable.invalid/"), TestCredentials.ClientId, TestCredentials.Secret);
        var services = new ServiceCollection();
        services
            .AddHmacClient<SafetalkApiClient>(configuration.GetSection("OrdersApi"))
            .ConfigureHttpClient(client => client.BaseAddress = server.BaseAddress)
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ConfigurationWithoutBaseAddress_LeavesTheBaseAddressConfiguredElsewhere(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        IConfigurationRoot configuration = CreateClientConfiguration(baseAddress: null, TestCredentials.ClientId, TestCredentials.Secret);
        var services = new ServiceCollection();
        services
            .AddHttpClient<SafetalkApiClient>(client => client.BaseAddress = server.BaseAddress) // Configured BEFORE signing.
            .AddHmacSigning(configuration.GetSection("OrdersApi"))
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    [Theory]
    [InlineData("api/")]
    [InlineData("/relative/path")]
    public async Task GenericHost_RelativeBaseAddressInConfiguration_FailsAtStartup(string baseAddress)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["OrdersApi:BaseAddress"] = baseAddress,
            ["OrdersApi:ClientId"] = TestCredentials.ClientId,
            ["OrdersApi:Secret"] = TestCredentials.Secret,
        });
        builder.Services.AddHmacClient<SafetalkApiClient>(builder.Configuration.GetSection("OrdersApi"));
        using IHost host = builder.Build();

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(ct));

        Assert.Contains(exception.Failures, failure => failure.Contains(nameof(HmacClientOptions.BaseAddress), StringComparison.Ordinal));
    }

    [Fact]
    public async Task GenericHost_MissingSecretInConfiguration_FailsAtStartup()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["OrdersApi:BaseAddress"] = "https://api.example.com/",
            ["OrdersApi:ClientId"] = TestCredentials.ClientId,
        });
        builder.Services.AddHmacClient<SafetalkApiClient>(builder.Configuration.GetSection("OrdersApi"));
        using IHost host = builder.Build();

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(ct));

        Assert.Contains(exception.Failures, failure => failure.Contains(nameof(HmacClientOptions.Secret), StringComparison.Ordinal));
    }

    private static IConfigurationRoot CreateClientConfiguration(Uri? baseAddress, string clientId, string secret)
        => new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OrdersApi:BaseAddress"] = baseAddress?.AbsoluteUri,
                ["OrdersApi:ClientId"] = clientId,
                ["OrdersApi:Secret"] = secret,
            })
            .Build();
}
