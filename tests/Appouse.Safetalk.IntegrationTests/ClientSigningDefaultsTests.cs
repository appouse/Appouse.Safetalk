using Appouse.Safetalk.Client;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// <c>ConfigureHttpClientDefaults(b => b.AddHmacSigning(...))</c> signs every client of the factory; a client with its
/// own <c>AddHmacSigning</c> registration keeps its own credentials whatever the registration order, and a pipeline
/// never has more than one signer.
/// </summary>
public sealed class ClientSigningDefaultsTests
{
    private const string PlainClientName = "plain";
    private const int RequestSignedEventId = 1;
    private const string PartnerClientName = "partner";
    private const string ThirdPartyClientName = "third-party";
    private const string DefaultsClientId = "partner-c";
    private const string DefaultsSecret = "cGFydG5lci1jLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMw==";

    private static readonly Uri WrongBaseAddress = new("http://wrong.invalid/");

    /// <summary>
    /// Round 4: the defaults registration uses a reserved options name, so a registration for the factory's unnamed
    /// client (<c>""</c>) no longer shares (and cumulates) options with it. Defaults, the unnamed client and a named
    /// partner client each sign with their own credentials against the real server, once per request. The defaults'
    /// <see cref="HmacClientOptions.BaseAddress"/> only applies to clients without a registration of their own, and an
    /// explicit <c>ConfigureHttpClient</c> base address beats the options one whatever the registration order.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, true)]
    [InlineData(TestHostKind.TestServer, false)]
    [InlineData(TestHostKind.Kestrel, true)]
    [InlineData(TestHostKind.Kestrel, false)]
    public async Task DefaultsUnnamedClientAndNamedPartnerClient_EachSignWithTheirOwnCredentials(TestHostKind kind, bool defaultsFirst)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithDefaultsClient(), ct);
        var logs = new LogCapture();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
        if (defaultsFirst)
        {
            RegisterDefaults(services, server);

            // Explicit base address registered BEFORE the signing registration that carries a wrong one.
            services.AddHttpClient(PartnerClientName)
                .ConfigureHttpClient(client => client.BaseAddress = server.BaseAddress)
                .AddHmacSigning(ConfigurePartnerBWithWrongBaseAddress);
        }
        else
        {
            // Explicit base address registered AFTER the signing registration that carries a wrong one.
            services.AddHmacClient(PartnerClientName, ConfigurePartnerBWithWrongBaseAddress)
                .ConfigureHttpClient(client => client.BaseAddress = server.BaseAddress);
        }

        services.AddHttpClient(string.Empty).AddHmacSigning(ConfigurePartnerA); // The factory's unnamed client.
        if (!defaultsFirst)
        {
            RegisterDefaults(services, server);
        }

        await using ServiceProvider clientServices = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        IHttpClientFactory factory = clientServices.GetRequiredService<IHttpClientFactory>();
        using HttpClient unnamed = factory.CreateClient();
        using HttpClient partner = factory.CreateClient(PartnerClientName);
        using HttpClient thirdParty = factory.CreateClient(ThirdPartyClientName);

        // The unnamed client has its own registration without a base address: the defaults' one must not leak into it.
        Assert.Null(unnamed.BaseAddress);
        Assert.Equal(server.BaseAddress, partner.BaseAddress);
        Assert.Equal(server.BaseAddress, thirdParty.BaseAddress);

        using HttpResponseMessage unnamedResponse = await unnamed.GetAsync(new Uri(server.BaseAddress, "/api/whoami"), ct);
        using HttpResponseMessage partnerResponse = await partner.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage thirdPartyResponse = await thirdParty.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);

        Assert.Equal(TestCredentials.ClientId, (await unnamedResponse.ReadOkJsonAsync<WhoAmIResponse>(ct)).ClientId);
        Assert.Equal(TestCredentials.OtherClientId, (await partnerResponse.ReadOkJsonAsync<WhoAmIResponse>(ct)).ClientId);
        Assert.Equal(DefaultsClientId, (await thirdPartyResponse.ReadOkJsonAsync<WhoAmIResponse>(ct)).ClientId);
        Assert.Equal(
            new string?[] { TestCredentials.ClientId, TestCredentials.OtherClientId, DefaultsClientId },
            logs.Find<HmacSigningHandler>(RequestSignedEventId).Select(entry => (string?)entry.GetValue("ClientId")));
    }

    /// <summary>
    /// Generic host, both registrations bound from configuration (validated at start-up): rotating the defaults'
    /// credentials is picked up by clients without their own registration and leaves the unnamed client alone, and
    /// rotating the unnamed client's credentials leaves the defaults alone (their change token sources and options no
    /// longer share the empty name).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task GenericHost_DefaultsAndUnnamedClientFromConfiguration_RotateIndependently(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithDefaultsClient(), ct);
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Defaults:BaseAddress"] = server.BaseAddress.AbsoluteUri,
            ["Defaults:ClientId"] = DefaultsClientId,
            ["Defaults:Secret"] = DefaultsSecret,
            ["Unnamed:BaseAddress"] = server.BaseAddress.AbsoluteUri,
            ["Unnamed:ClientId"] = TestCredentials.ClientId,
            ["Unnamed:Secret"] = TestCredentials.Secret,
        });
        builder.Services.ConfigureHttpClientDefaults(http => http
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler)
            .AddHmacSigning(builder.Configuration.GetSection("Defaults")));
        builder.Services.AddHttpClient(string.Empty).AddHmacSigning(builder.Configuration.GetSection("Unnamed"));
        using IHost host = builder.Build();
        await host.StartAsync(ct);
        IHttpClientFactory factory = host.Services.GetRequiredService<IHttpClientFactory>();
        var configuration = (IConfigurationRoot)host.Services.GetRequiredService<IConfiguration>();

        (string? Unnamed, string? ThirdParty) initial = (await WhoAmIAsync(factory, string.Empty, ct), await WhoAmIAsync(factory, ThirdPartyClientName, ct));
        configuration["Defaults:ClientId"] = TestCredentials.OtherClientId;
        configuration["Defaults:Secret"] = TestCredentials.OtherSecret;
        configuration.Reload();
        (string? Unnamed, string? ThirdParty) defaultsRotated = (await WhoAmIAsync(factory, string.Empty, ct), await WhoAmIAsync(factory, ThirdPartyClientName, ct));
        configuration["Unnamed:ClientId"] = DefaultsClientId;
        configuration["Unnamed:Secret"] = DefaultsSecret;
        configuration.Reload();
        (string? Unnamed, string? ThirdParty) unnamedRotated = (await WhoAmIAsync(factory, string.Empty, ct), await WhoAmIAsync(factory, ThirdPartyClientName, ct));
        await host.StopAsync(ct);

        Assert.Equal((TestCredentials.ClientId, DefaultsClientId), initial);
        Assert.Equal((TestCredentials.ClientId, TestCredentials.OtherClientId), defaultsRotated);
        Assert.Equal((DefaultsClientId, TestCredentials.OtherClientId), unnamedRotated);
    }

    /// <summary>
    /// Registering signing twice for one client: a single signer, and cumulative options — the second registration's
    /// credentials with the first registration's base address.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AddHmacSigningTwiceForOneClient_OptionsAreCumulative(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var logs = new LogCapture();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
        services.AddHttpClient<SafetalkApiClient>()
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler)
            .AddHmacSigning(options =>
            {
                ConfigurePartnerA(options);
                options.BaseAddress = server.BaseAddress;
            })
            .AddHmacSigning(ConfigurePartnerB);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.OtherClientId, whoAmI.ClientId);
        Assert.Equal(TestCredentials.OtherClientId, (string?)Assert.Single(logs.Find<HmacSigningHandler>(RequestSignedEventId)).GetValue("ClientId"));
    }

    /// <summary>
    /// The flip side of cumulative options, as documented: a later registration that only sets the client id keeps the
    /// earlier secret, and the server rejects the mismatching credentials.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AddHmacSigningTwiceForOneClient_LaterRegistrationSettingOnlyTheClientId_KeepsTheEarlierSecret(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var services = new ServiceCollection();
        services.AddHttpClient<SafetalkApiClient>()
            .AddHmacSigning(ConfigurePartnerA)
            .AddHmacSigning(options => options.ClientId = TestCredentials.OtherClientId)
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        HmacValidationResult result = Assert.Single(server.ValidationResults);
        Assert.Equal((HmacValidationFailure.InvalidSignature, TestCredentials.OtherClientId), (result.Failure, result.ClientId));
    }

    private static async Task<string?> WhoAmIAsync(IHttpClientFactory factory, string clientName, CancellationToken cancellationToken)
    {
        using HttpClient client = factory.CreateClient(clientName);
        using HttpResponseMessage response = await client.GetAsync(new Uri("/api/whoami", UriKind.Relative), cancellationToken);
        return (await response.ReadOkJsonAsync<WhoAmIResponse>(cancellationToken)).ClientId;
    }

    private static ServerSetup WithDefaultsClient() => new()
    {
        ConfigureHmac = hmac => hmac.AddInMemorySecrets(new Dictionary<string, string>(TestCredentials.All, StringComparer.Ordinal)
        {
            [DefaultsClientId] = DefaultsSecret,
        }),
    };

    private static void RegisterDefaults(IServiceCollection services, SafetalkServer server)
        => services.ConfigureHttpClientDefaults(http => http
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler)
            .AddHmacSigning(options =>
            {
                options.ClientId = DefaultsClientId;
                options.Secret = DefaultsSecret;
                options.BaseAddress = server.BaseAddress;
            }));

    private static void ConfigurePartnerBWithWrongBaseAddress(HmacClientOptions options)
    {
        ConfigurePartnerB(options);
        options.BaseAddress = WrongBaseAddress;
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, true)]
    [InlineData(TestHostKind.TestServer, false)]
    [InlineData(TestHostKind.Kestrel, true)]
    [InlineData(TestHostKind.Kestrel, false)]
    public async Task DefaultSigning_AndNamedClientWithOwnCredentials_ServerSeesEachClientsIdentity_SignedOnce(TestHostKind kind, bool defaultsFirst)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var logs = new LogCapture();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
        if (defaultsFirst)
        {
            services.ConfigureHttpClientDefaults(http => http.AddHmacSigning(ConfigurePartnerA));
        }

        services.AddHmacClient<SafetalkApiClient>(ConfigurePartnerB).UseServer(server);
        services.AddHttpClient(PlainClientName).UseServer(server);
        if (!defaultsFirst)
        {
            services.ConfigureHttpClientDefaults(http => http.AddHmacSigning(ConfigurePartnerA));
        }

        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse own = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);
        using HttpClient plain = clientServices.GetRequiredService<IHttpClientFactory>().CreateClient(PlainClientName);
        using HttpResponseMessage plainResponse = await plain.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        WhoAmIResponse byDefault = await plainResponse.ReadOkJsonAsync<WhoAmIResponse>(ct);

        Assert.Equal(TestCredentials.OtherClientId, own.ClientId);
        Assert.Equal(TestCredentials.ClientId, byDefault.ClientId);

        // One signature per request: the client's own signer replaced the default one instead of running next to it.
        CapturedLog[] signed = logs.Find<HmacSigningHandler>(RequestSignedEventId);
        Assert.Equal(
            new string?[] { TestCredentials.OtherClientId, TestCredentials.ClientId },
            signed.Select(entry => (string?)entry.GetValue("ClientId")));
    }

    /// <summary>
    /// Registering signing twice for one client keeps the last registration and a single signer.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AddHmacSigningTwiceForOneClient_KeepsASingleSigner(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var logs = new LogCapture();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
        services.AddHttpClient<SafetalkApiClient>()
            .AddHmacSigning(ConfigurePartnerA)
            .AddHmacSigning(ConfigurePartnerB)
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse first = await client.GetWhoAmIAsync(ct);
        WhoAmIResponse second = await client.GetWhoAmIAsync(ct);

        Assert.Equal((TestCredentials.OtherClientId, TestCredentials.OtherClientId), (first.ClientId, second.ClientId));
        Assert.Equal(2, logs.Find<HmacSigningHandler>(RequestSignedEventId).Length);
    }

    private static void ConfigurePartnerA(HmacClientOptions options)
    {
        options.ClientId = TestCredentials.ClientId;
        options.Secret = TestCredentials.Secret;
    }

    private static void ConfigurePartnerB(HmacClientOptions options)
    {
        options.ClientId = TestCredentials.OtherClientId;
        options.Secret = TestCredentials.OtherSecret;
    }
}
