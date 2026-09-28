using System.Net;
using Appouse.Safetalk.Client;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// <c>AddHmacServer(IConfiguration)</c> as in the server sample: options and client secrets from a (reloadable)
/// configuration section, secrets served by <see cref="ConfigurationHmacSecretProvider"/>.
/// </summary>
public sealed class ServerConfigurationTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClientsSection_StringAndObjectForms_AuthenticateTheirClients(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server);
        await using ServiceProvider partnerB = TestClientFactory.Create(
            server,
            new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });

        WhoAmIResponse a = await partnerA.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);
        WhoAmIResponse b = await partnerB.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, a.ClientId);
        Assert.Equal(TestCredentials.OtherClientId, b.ClientId);
        Assert.IsType<ConfigurationHmacSecretProvider>(server.Services.GetRequiredService<IHmacSecretProvider>());
    }

    /// <summary>
    /// Configuration keys are case-insensitive, but client identifiers are matched ordinally as written.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, "PARTNER-A")]
    [InlineData(TestHostKind.Kestrel, "PARTNER-A")]
    [InlineData(TestHostKind.TestServer, "Partner-A")]
    [InlineData(TestHostKind.Kestrel, "Partner-A")]
    public async Task ClientIdWithDifferentCaseThanConfiguration_IsRejectedAsUnknownClient(TestHostKind kind, string clientId)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { ClientId = clientId });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnknownClient, server.LastFailure);
    }

    /// <summary>
    /// A secret rotated in the configuration store (Key Vault reload, file watcher) is picked up by the next request:
    /// the old secret is rejected, the new one accepted, without a restart.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SecretRotatedInConfiguration_IsAppliedOnReload_OldSecretRejected_NewSecretAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        const string RotatedSecret = "cm90YXRlZC1zZXJ2ZXItc2VjcmV0LWZvci1wYXJ0bmVyLWE=";
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        await using ServiceProvider oldClient = TestClientFactory.Create(server);
        await using ServiceProvider newClient = TestClientFactory.Create(server, new ClientSetup { Secret = RotatedSecret });

        using HttpResponseMessage oldBefore = await oldClient.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        using HttpResponseMessage newBefore = await newClient.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        configuration["Safetalk:Clients:partner-a"] = RotatedSecret;
        configuration.Reload();
        using HttpResponseMessage oldAfter = await oldClient.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        using HttpResponseMessage newAfter = await newClient.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        Assert.Equal(HttpStatusCode.OK, oldBefore.StatusCode);
        newBefore.AssertUnauthorized();
        oldAfter.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.OK, newAfter.StatusCode);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClientsAddedAndRemovedInConfiguration_AreAppliedOnReload(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        const string NewClientId = "partner-c";
        const string NewSecret = "cGFydG5lci1jLXNlY3JldC0yMDI2LTA5LTI3LXJlbG9hZA==";
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        await using ServiceProvider partnerB = TestClientFactory.Create(server, new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });
        await using ServiceProvider partnerC = TestClientFactory.Create(server, new ClientSetup { ClientId = NewClientId, Secret = NewSecret });

        using HttpResponseMessage cBefore = await partnerC.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        configuration["Safetalk:Clients:partner-b:Secret"] = null; // Disabled.
        configuration[$"Safetalk:Clients:{NewClientId}:Secret"] = NewSecret; // Onboarded.
        configuration.Reload();
        using HttpResponseMessage bAfter = await partnerB.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        HmacValidationFailure bFailure = server.LastFailure;
        using HttpResponseMessage cAfter = await partnerC.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        cBefore.AssertUnauthorized();
        bAfter.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnknownClient, bFailure);
        WhoAmIResponse c = await cAfter.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(NewClientId, c.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MaxBodySizeChangedInConfiguration_IsAppliedToTheNextRequest(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var before = new ByteArrayContent(TestData.CreateBytes(4_096));
        using var after = new ByteArrayContent(TestData.CreateBytes(4_096));

        using HttpResponseMessage accepted = await client.PostAsync("/api/raw", before, ct);
        configuration["Safetalk:MaxBodySize"] = "1024";
        configuration.Reload();
        using HttpResponseMessage rejected = await client.PostAsync("/api/raw", after, ct);

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, rejected.StatusCode);
        Assert.Equal(1024, server.Services.GetRequiredService<IOptionsMonitor<HmacServerOptions>>().CurrentValue.MaxBodySize);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task EnforcementModeChangedInConfiguration_IsAppliedToTheNextRequest(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage protectedResponse = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        configuration["Safetalk:EnforcementMode"] = "markedendpointsonly"; // Enum names are matched case-insensitively.
        configuration.Reload();
        using HttpResponseMessage openResponse = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);

        protectedResponse.AssertUnauthorized();
        WhoAmIResponse whoAmI = await openResponse.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Null(whoAmI.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayProtectionAndClockSkewFromConfiguration_AreEnforced(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration(new Dictionary<string, string?>
        {
            ["Safetalk:EnableReplayProtection"] = "true",
            ["Safetalk:AllowedClockSkew"] = "00:00:30",
        });
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        await using ServiceProvider skewedServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.UtcNow.AddMinutes(-2)) });

        using HttpResponseMessage original = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        using HttpClient attacker = server.CreateUnsignedClient();
        using HttpRequestMessage replay = Assert.Single(capture.Requests).ToRequestMessage();
        using HttpResponseMessage replayed = await attacker.SendAsync(replay, ct);
        HmacValidationFailure replayFailure = server.LastFailure;
        using HttpResponseMessage skewed = await skewedServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        replayed.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, replayFailure);
        skewed.AssertUnauthorized(); // Two minutes is fine for the default window, not for 30 seconds.
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    /// <summary>
    /// Invalid values fail the start-up and name the configuration path, so the operator knows what to fix.
    /// </summary>
    [Theory]
    [InlineData("MaxBodySize", "4MB")]
    [InlineData("MaxBodySize", "99999999999")]
    [InlineData("AllowedClockSkew", "five minutes")]
    [InlineData("EnableReplayProtection", "yes")]
    [InlineData("EnforcementMode", "Everything")]
    [InlineData("EnforcementMode", "7")]
    [InlineData("EnforcementMode", "1")]
    [InlineData("EnforcementMode", "0")]
    [InlineData("EnforcementMode", "AllRequests,MarkedEndpointsOnly")]
    [InlineData("EnforcementMode", "MarkedEndpointsOnly, AllRequests")]
    public async Task InvalidConfigurationValue_FailsAtStartup_NamingTheKeyPath(string key, string value)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration(new Dictionary<string, string?> { [$"Safetalk:{key}"] = value });

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => SafetalkServer.StartAsync(TestHostKind.TestServer, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct));

        Assert.Contains($"Safetalk:{key}", exception.Message, StringComparison.Ordinal);
        Assert.Contains(value, exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Names are matched case-insensitively and trimmed, so a hand-edited value still selects the intended mode.
    /// </summary>
    [Theory]
    [InlineData(" MarkedEndpointsOnly ")]
    [InlineData("MARKEDENDPOINTSONLY")]
    public async Task EnforcementModeName_WithWhitespaceOrOtherCase_IsAccepted(string value)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration(new Dictionary<string, string?> { ["Safetalk:EnforcementMode"] = value });
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.TestServer, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HmacEnforcementMode.MarkedEndpointsOnly, server.Services.GetRequiredService<IOptionsMonitor<HmacServerOptions>>().CurrentValue.EnforcementMode);
    }

    /// <summary>
    /// <c>Enum.TryParse</c> would read "1" or "AllRequests,MarkedEndpointsOnly" as <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/>
    /// and silently open every unmarked endpoint. Such a value arriving by reload must never serve an unsigned request.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, "1")]
    [InlineData(TestHostKind.Kestrel, "1")]
    [InlineData(TestHostKind.TestServer, "AllRequests,MarkedEndpointsOnly")]
    [InlineData(TestHostKind.Kestrel, "AllRequests,MarkedEndpointsOnly")]
    public async Task EnforcementModeReloadedToANumberOrCombinedNames_NeverOpensUnmarkedEndpoints(TestHostKind kind, string value)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        configuration["Safetalk:EnforcementMode"] = value;
        Exception? reloadError = Record.Exception(configuration.Reload);
        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        configuration["Safetalk:EnforcementMode"] = "AllRequests";
        configuration.Reload();
        using HttpResponseMessage recovered = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(reloadError); // The invalid value is reported to whoever triggered the reload.
        recovered.AssertUnauthorized();
    }

    /// <summary>
    /// A client configured both as a string (in one source) and as an object with a <c>Secret</c> key (in another) is
    /// ambiguous: it is ignored (fail closed, even when both secrets are equal) and reported as an error naming the
    /// client, while other clients keep working. Removing one of the forms on reload re-enables it.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClientConfiguredAsStringAndObject_IsIgnoredAndLogged_UntilOneFormIsRemoved(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Safetalk:Clients:partner-a"] = TestCredentials.Secret,
                ["Safetalk:Clients:partner-b:Secret"] = TestCredentials.OtherSecret,
            })
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Safetalk:Clients:partner-a:Secret"] = TestCredentials.Secret })
            .Build();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = configuration.GetSection("Safetalk"), Logs = logs }, ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server);
        await using ServiceProvider partnerB = TestClientFactory.Create(server, new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });

        using HttpResponseMessage ambiguous = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        HmacValidationFailure ambiguousFailure = server.LastFailure;
        using HttpResponseMessage other = await partnerB.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        configuration["Safetalk:Clients:partner-a"] = null; // The string form is removed; the object form remains.
        configuration.Reload();
        using HttpResponseMessage resolved = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        ambiguous.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnknownClient, ambiguousFailure);
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
        Assert.Equal(HttpStatusCode.OK, resolved.StatusCode);
        CapturedLog error = Assert.Single(logs.Find<ConfigurationHmacSecretProvider>(eventId: 20));
        Assert.Equal(
            (Microsoft.Extensions.Logging.LogLevel.Error, (object?)TestCredentials.ClientId, (object?)"Safetalk:Clients:partner-a"),
            (error.Level, error.GetValue("ClientId"), error.GetValue("Path")));
        Assert.DoesNotContain(TestCredentials.Secret, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OutOfRangeClockSkewInConfiguration_FailsAtStartupValidation()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration(new Dictionary<string, string?> { ["Safetalk:AllowedClockSkew"] = "2.00:00:00" });

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(
            () => SafetalkServer.StartAsync(TestHostKind.TestServer, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct));

        Assert.Contains(exception.Failures, failure => failure.Contains(nameof(HmacServerOptions.AllowedClockSkew), StringComparison.Ordinal));
    }

    /// <summary>
    /// Without a <c>Clients</c> child no secret provider is registered, and the application does not start. (In the
    /// Development environment the host's own scope validation reports it at <c>Build()</c>, before the
    /// <c>UseHmacAuthentication()</c> check would.)
    /// </summary>
    [Fact]
    public async Task SectionWithoutClients_AndNoOtherProvider_FailsAtStartupNamingTheMissingSecretProvider()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Safetalk:MaxBodySize"] = "1024" })
            .Build();

        Exception exception = await Assert.ThrowsAnyAsync<Exception>(
            () => SafetalkServer.StartAsync(TestHostKind.TestServer, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct));

        Assert.True(exception is InvalidOperationException or AggregateException, exception.GetType().FullName);
        Assert.Contains(nameof(IHmacSecretProvider), exception.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The start-up error names every way to register secrets, including the configuration-based ones.
    /// </summary>
    [Fact]
    public async Task SectionWithoutClients_StartupErrorExplainsHowToRegisterSecrets()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Safetalk:MaxBodySize"] = "1024" })
            .Build();

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => SafetalkServer.StartAsync(TestHostKind.TestServer, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct));

        Assert.Contains("AddSecretProvider<TProvider>()", exception.Message, StringComparison.Ordinal);
        Assert.Contains("AddSecretsFromConfiguration(section)", exception.Message, StringComparison.Ordinal);
        Assert.Contains("AddInMemorySecrets(...)", exception.Message, StringComparison.Ordinal);
        Assert.Contains("'Clients' child", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A provider chained after <c>AddHmacServer(IConfiguration)</c> replaces the configuration-based one.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ExplicitSecretProviderAfterConfiguration_ReplacesTheClientsSection(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        const string DatabaseSecret = "ZGF0YWJhc2Utc2VjcmV0LWZvci1wYXJ0bmVyLWEtMjAyNg==";
        var provider = new RotatingSecretProvider();
        provider.Set(TestCredentials.ClientId, DatabaseSecret);
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                Configuration = configuration.GetSection("Safetalk"),
                ConfigureHmac = hmac => hmac.AddSecretProvider(_ => provider, ServiceLifetime.Singleton),
            },
            ct);
        await using ServiceProvider configured = TestClientFactory.Create(server);
        await using ServiceProvider database = TestClientFactory.Create(server, new ClientSetup { Secret = DatabaseSecret });

        using HttpResponseMessage configuredResponse = await configured.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        using HttpResponseMessage databaseResponse = await database.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        configuredResponse.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.OK, databaseResponse.StatusCode);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AddSecretsFromConfiguration_OnACustomSection_FollowsItsReloads(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Partners:partner-b"] = TestCredentials.OtherSecret })
            .Build();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddSecretsFromConfiguration(configuration.GetSection("Partners")) },
            ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server);
        await using ServiceProvider partnerB = TestClientFactory.Create(server, new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });

        using HttpResponseMessage aBefore = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        using HttpResponseMessage bBefore = await partnerB.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        configuration["Partners:partner-a"] = TestCredentials.Secret;
        configuration.Reload();
        using HttpResponseMessage aAfter = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        aBefore.AssertUnauthorized(); // AddSecretsFromConfiguration replaced the in-memory secrets of the harness.
        Assert.Equal(HttpStatusCode.OK, bBefore.StatusCode);
        Assert.Equal(HttpStatusCode.OK, aAfter.StatusCode);
    }

    /// <summary>
    /// Coordinated rotation with both sides reading configuration: the client (<c>AddHmacClient(IConfiguration)</c>) and
    /// the server (<c>AddHmacServer(IConfiguration)</c>) each reload their store; no restart on either side.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task CoordinatedRotation_ClientAndServerConfigurationReloads_KeepTheClientAuthenticated(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        const string RotatedSecret = "Y29vcmRpbmF0ZWQtcm90YXRpb24tc2VjcmV0LTIwMjYtMDktMjc=";
        IConfigurationRoot serverConfiguration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { Configuration = serverConfiguration.GetSection("Safetalk") }, ct);
        IConfigurationRoot clientConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OrdersApi:BaseAddress"] = server.BaseAddress.AbsoluteUri,
                ["OrdersApi:ClientId"] = TestCredentials.ClientId,
                ["OrdersApi:Secret"] = TestCredentials.Secret,
            })
            .Build();
        var services = new ServiceCollection();
        services.AddHmacClient<SafetalkApiClient>(clientConfiguration.GetSection("OrdersApi")).ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler);
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage before = await client.GetAsync("/api/whoami", ct);
        serverConfiguration["Safetalk:Clients:partner-a"] = RotatedSecret;
        serverConfiguration.Reload();
        using HttpResponseMessage inBetween = await client.GetAsync("/api/whoami", ct);
        clientConfiguration["OrdersApi:Secret"] = RotatedSecret;
        clientConfiguration.Reload();
        using HttpResponseMessage after = await client.GetAsync("/api/whoami", ct);

        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        inBetween.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
        Assert.Equal(RotatedSecret, clientServices.GetRequiredService<IOptionsMonitor<HmacClientOptions>>().Get(nameof(SafetalkApiClient)).Secret);
    }

    /// <summary>
    /// Secrets are served from an immutable snapshot swapped on reload: requests of a client whose secret does not
    /// change keep verifying while another client's secret is rotated over and over.
    /// </summary>
    [Fact]
    public async Task ConcurrentRequestsDuringRepeatedReloads_OfAnotherClientsSecret_AreAllAccepted()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration();
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var stop = new CancellationTokenSource();

        Task reloads = Task.Run(
            () =>
            {
                for (int i = 0; !stop.IsCancellationRequested; i++)
                {
                    configuration["Safetalk:Clients:partner-b:Secret"] = $"rotating-secret-{i}";
                    configuration.Reload();
                }
            },
            ct);

        HttpStatusCode[] statuses = await Task.WhenAll(Enumerable.Range(0, 64).Select(async i =>
        {
            using HttpResponseMessage response = await client.GetAsync($"/inspect/orders?n={i}", ct);
            return response.StatusCode;
        }));
        await stop.CancelAsync();
        await reloads;

        Assert.All(statuses, status => Assert.Equal(HttpStatusCode.OK, status));
    }

    /// <summary>
    /// The provider is disposed with the application: it stops following reloads (no callback into a disposed app) and,
    /// instead of serving a stale snapshot forever, fails loudly when a leaked reference is still used.
    /// </summary>
    [Fact]
    public async Task ConfigurationSecretProvider_DisposedWithTheApplication_ThrowsObjectDisposedExceptionInsteadOfServingStaleSecrets()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration();
        SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.TestServer, new ServerSetup { Configuration = configuration.GetSection("Safetalk") }, ct);
        IHmacSecretProvider provider = server.Services.GetRequiredService<IHmacSecretProvider>();
        string? before = await provider.GetSecretAsync(TestCredentials.ClientId, ct);

        await server.DisposeAsync();
        configuration["Safetalk:Clients:partner-a"] = "rotated-after-shutdown";
        configuration.Reload(); // Must not call back into the disposed provider (would throw here otherwise).

        Assert.Equal(TestCredentials.Secret, before);
        Assert.IsType<ConfigurationHmacSecretProvider>(provider);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => provider.GetSecretAsync(TestCredentials.ClientId, ct).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => provider.GetSecretAsync(TestCredentials.OtherClientId, ct).AsTask());
    }

    /// <summary>
    /// The misuse the <c>AddSecretProvider(factory)</c> documentation warns about: a shared, disposable provider returned
    /// from a scoped factory is disposed by the first request scope. Later requests then fail closed (never 200 with a
    /// frozen snapshot of the secrets).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SharedConfigurationProviderFromScopedFactory_IsDisposedByTheFirstScope_AndLaterRequestsFailClosed(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = CreateServerConfiguration();
        using var shared = new ConfigurationHmacSecretProvider(configuration.GetSection("Safetalk:Clients"));
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddSecretProvider(_ => shared) }, // Scoped by default.
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage first = await client.GetAsync("/api/whoami", ct);
        using HttpResponseMessage second = await client.GetAsync("/api/whoami", ct);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.InternalServerError, second.StatusCode);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => shared.GetSecretAsync(TestCredentials.ClientId, ct).AsTask());
    }

    private static IConfigurationRoot CreateServerConfiguration(IDictionary<string, string?>? overrides = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["Safetalk:AllowedClockSkew"] = "00:05:00",
            ["Safetalk:MaxBodySize"] = "1048576",
            ["Safetalk:EnableReplayProtection"] = "false",
            ["Safetalk:EnforcementMode"] = "AllRequests",
            ["Safetalk:Clients:partner-a"] = TestCredentials.Secret,
            ["Safetalk:Clients:partner-b:Secret"] = TestCredentials.OtherSecret,
        };

        foreach ((string key, string? value) in overrides ?? new Dictionary<string, string?>())
        {
            values[key] = value;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }
}
