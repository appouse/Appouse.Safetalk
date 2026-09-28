using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// The <see cref="IConfiguration"/> overloads bind <c>ClientId</c>, <c>Secret</c> and <c>BaseAddress</c>, validate
/// them at start-up and follow configuration reloads (credential rotation without a restart).
/// </summary>
public sealed class HmacClientConfigurationTests : IDisposable
{
    private const string MissingClientId = "ClientId must be provided.";
    private const string MissingSecret = "Secret must be provided.";

    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly CapturingHandler _transport = new();
    private readonly ServiceCollection _services = new();
    private readonly IConfigurationRoot _configuration = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["OrdersApi:ClientId"] = "orders-client",
            ["OrdersApi:Secret"] = "orders-secret-v1",
            ["OrdersApi:BaseAddress"] = "https://orders.example.com/v1/",
            ["BillingApi:ClientId"] = "billing-client",
            ["BillingApi:Secret"] = "billing-secret",
            ["BillingApi:BaseAddress"] = "https://billing.example.com/",
        })
        .Build();

    public HmacClientConfigurationTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    public static TheoryData<string> RegistrationKinds => ["typed", "typed-contract", "named", "signing"];

    public void Dispose() => _transport.Dispose();

    [Theory]
    [MemberData(nameof(RegistrationKinds))]
    public async Task ConfigurationOverload_BindsClientIdSecretAndBaseAddress(string kind)
    {
        Registration registration = Register(kind, _configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();
        HttpClient client = registration.Resolve(provider);

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders?id=5", UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Equal(new Uri("https://orders.example.com/v1/"), client.BaseAddress);
        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("orders-client", sent.ClientId);
        Assert.Equal("1790000000", sent.Timestamp);
        Assert.Equal(ReferenceSigner.Sign("orders-secret-v1", "GET", "/v1/orders?id=5", "1790000000", []), sent.Signature);

        HmacClientOptions options = provider.GetRequiredService<IOptionsMonitor<HmacClientOptions>>().Get(registration.Builder.Name);
        Assert.Equal("orders-client", options.ClientId);
        Assert.Equal("orders-secret-v1", options.Secret);
    }

    [Theory]
    [InlineData("typed", nameof(OrdersApiClient))]
    [InlineData("typed-contract", nameof(IInventoryApi))]
    [InlineData("named", "orders")]
    [InlineData("signing", "orders-signing")]
    public void ConfigurationOverload_ReturnsBuilderWithTheClientName(string kind, string expectedName)
    {
        Registration registration = Register(kind, _configuration.GetSection("OrdersApi"));

        Assert.Equal(expectedName, registration.Builder.Name);
        Assert.Contains(_services, descriptor => descriptor.ServiceType == typeof(IOptionsChangeTokenSource<HmacClientOptions>));
    }

    [Theory]
    [MemberData(nameof(RegistrationKinds))]
    public void ConfigurationOverload_MissingSection_FailsStartupValidation(string kind)
    {
        Registration registration = Register(kind, _configuration.GetSection("DoesNotExist"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal(registration.Builder.Name, exception.OptionsName);
        Assert.Equal([MissingClientId, MissingSecret], exception.Failures);
        Assert.Equal(0, _transport.InvocationCount);
    }

    [Theory]
    [MemberData(nameof(RegistrationKinds))]
    public void ConfigurationOverload_MissingSecretOnly_FailsStartupValidationWithOnlyThatFailure(string kind)
    {
        _configuration["OrdersApi:Secret"] = null;
        Registration registration = Register(kind, _configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal(registration.Builder.Name, exception.OptionsName);
        Assert.Equal(MissingSecret, Assert.Single(exception.Failures));
    }

    [Theory]
    [MemberData(nameof(RegistrationKinds))]
    public async Task ConfigurationOverload_Reloaded_NextRequestOfTheSameClientUsesTheRotatedClientIdAndSecret(string kind)
    {
        Registration registration = Register(kind, _configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = registration.Resolve(provider);

        CapturedRequest before = await GetAsync(client);
        _configuration["OrdersApi:ClientId"] = "orders-client-2027";
        _configuration["OrdersApi:Secret"] = "orders-secret-v2";
        _configuration.Reload();
        CapturedRequest after = await GetAsync(client);

        Assert.Equal("orders-client", before.ClientId);
        Assert.Equal(ReferenceSigner.Sign("orders-secret-v1", before), before.Signature);
        Assert.Equal("orders-client-2027", after.ClientId);
        Assert.Equal(ReferenceSigner.Sign("orders-secret-v2", after), after.Signature);
        Assert.NotEqual(ReferenceSigner.Sign("orders-secret-v1", after), after.Signature);
    }

    [Fact]
    public void ConfigurationOverload_ReloadedThenSentSynchronously_UsesTheRotatedSecret()
    {
        _services.AddHmacClient<OrdersApiClient>(_configuration.GetSection("OrdersApi")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        _configuration["OrdersApi:Secret"] = "orders-secret-v2";
        _configuration.Reload();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("orders", UriKind.Relative));
        using HttpResponseMessage response = client.Send(request, TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal(ReferenceSigner.Sign("orders-secret-v2", sent), sent.Signature);
    }

    [Fact]
    public async Task ConfigurationOverload_ReloadOfOneSection_DoesNotAffectOtherClients()
    {
        var billingTransport = new CapturingHandler();
        var staticTransport = new CapturingHandler();
        _services.AddHmacClient("orders", _configuration.GetSection("OrdersApi")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        _services.AddHmacClient("billing", _configuration.GetSection("BillingApi")).ConfigurePrimaryHttpMessageHandler(() => billingTransport);
        _services.AddHmacClient("static", options =>
            {
                options.ClientId = "static-client";
                options.Secret = "static-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => staticTransport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();
        using HttpClient orders = factory.CreateClient("orders");
        using HttpClient billing = factory.CreateClient("billing");
        using HttpClient fixedClient = factory.CreateClient("static");

        _configuration["OrdersApi:ClientId"] = "orders-client-2027";
        _configuration["OrdersApi:Secret"] = "orders-secret-v2";
        _configuration.Reload();
        await SendGetAsync(orders);
        await SendGetAsync(billing);
        await SendGetAsync(fixedClient, new Uri("https://static.example.com/"));

        CapturedRequest ordersSent = _transport.SingleRequest;
        CapturedRequest billingSent = billingTransport.SingleRequest;
        CapturedRequest staticSent = staticTransport.SingleRequest;
        Assert.Equal("orders-client-2027", ordersSent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("orders-secret-v2", ordersSent), ordersSent.Signature);
        Assert.Equal("billing-client", billingSent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("billing-secret", billingSent), billingSent.Signature);
        Assert.Equal("static-client", staticSent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("static-secret", staticSent), staticSent.Signature);
    }

    [Fact]
    public async Task ConfigurationOverload_TwoClientsFromSeparateSections_UseIsolatedCredentialsAndBaseAddresses()
    {
        var billingTransport = new CapturingHandler();
        _services.AddHmacClient<OrdersApiClient>(_configuration.GetSection("OrdersApi")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        _services.AddHmacClient<BillingApiClient>(_configuration.GetSection("BillingApi")).ConfigurePrimaryHttpMessageHandler(() => billingTransport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        await GetAsync(provider.GetRequiredService<OrdersApiClient>().HttpClient);
        await SendGetAsync(provider.GetRequiredService<BillingApiClient>().HttpClient);

        Assert.Equal("orders.example.com", _transport.SingleRequest.RequestUri.Host);
        Assert.Equal(ReferenceSigner.Sign("orders-secret-v1", _transport.SingleRequest), _transport.SingleRequest.Signature);
        Assert.Equal("billing.example.com", billingTransport.SingleRequest.RequestUri.Host);
        Assert.Equal("billing-client", billingTransport.SingleRequest.ClientId);
        Assert.Equal(ReferenceSigner.Sign("billing-secret", billingTransport.SingleRequest), billingTransport.SingleRequest.Signature);
    }

    [Fact]
    public async Task ConfigurationOverload_ReloadedToInvalidValuesThenFixed_ExistingClientFailsBeforeTransportThenRecovers()
    {
        _services.AddHmacClient<OrdersApiClient>(_configuration.GetSection("OrdersApi")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        _configuration["OrdersApi:Secret"] = string.Empty;
        AggregateException reloadFailure = Assert.Throws<AggregateException>(_configuration.Reload);
        Assert.IsType<OptionsValidationException>(Assert.Single(reloadFailure.InnerExceptions));
        await Assert.ThrowsAsync<OptionsValidationException>(() => client.GetAsync(new Uri("orders", UriKind.Relative), cancellationToken));
        Assert.Equal(0, _transport.InvocationCount);

        _configuration["OrdersApi:Secret"] = "orders-secret-v3";
        _configuration.Reload();
        CapturedRequest sent = await GetAsync(client);

        Assert.Equal(ReferenceSigner.Sign("orders-secret-v3", sent), sent.Signature);
    }

    [Fact]
    public async Task ConfigurationOverload_SectionCompletedByReload_ClientsCreatedAfterwardsWork()
    {
        _services.AddHmacClient<OrdersApiClient>(_configuration.GetSection("PartnerApi")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<OrdersApiClient>());

        _configuration["PartnerApi:ClientId"] = "late-client";
        _configuration["PartnerApi:Secret"] = "late-secret";
        _configuration.Reload();
        CapturedRequest sent = await GetAsync(provider.GetRequiredService<OrdersApiClient>().HttpClient, new Uri("https://api.example.com/"));

        Assert.Equal("late-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("late-secret", sent), sent.Signature);
    }

    [Fact]
    public async Task ConfigurationOverload_KeysAreMatchedCaseInsensitively()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["partner:CLIENTID"] = "upper-client",
                ["partner:secret"] = "lower-secret",
                ["partner:baseaddress"] = "https://case.example.com/",
            })
            .Build();
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("Partner")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        CapturedRequest sent = await GetAsync(provider.GetRequiredService<OrdersApiClient>().HttpClient);

        Assert.Equal("upper-client", sent.ClientId);
        Assert.Equal("case.example.com", sent.RequestUri.Host);
        Assert.Equal(ReferenceSigner.Sign("lower-secret", sent), sent.Signature);
    }

    [Fact]
    public async Task ConfigurationOverload_ConfigurationRootWithTopLevelKeys_IsBoundAndReloaded()
    {
        IConfigurationRoot root = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ClientId"] = "root-client", ["Secret"] = "root-secret" })
            .Build();
        _services.AddHmacClient<OrdersApiClient>(root).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        CapturedRequest before = await GetAsync(client, new Uri("https://api.example.com/"));
        root["Secret"] = "root-secret-v2";
        root.Reload();
        CapturedRequest after = await GetAsync(client, new Uri("https://api.example.com/"));

        Assert.Equal(ReferenceSigner.Sign("root-secret", before), before.Signature);
        Assert.Equal(ReferenceSigner.Sign("root-secret-v2", after), after.Signature);
    }

    [Theory]
    [MemberData(nameof(RegistrationKinds))]
    public void ConfigurationOverload_RegistersOneChangeTokenSourceNamedAfterTheClient(string kind)
    {
        Registration registration = Register(kind, _configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IOptionsChangeTokenSource<HmacClientOptions> source = Assert.Single(provider.GetServices<IOptionsChangeTokenSource<HmacClientOptions>>());

        Assert.Equal(registration.Builder.Name, source.Name);
    }

    [Fact]
    public async Task ConfigurationOverload_ConcurrentRequestsDuringSecretRotation_EveryRequestIsSignedWithOneOfTheRotatedSecrets()
    {
        const int rotations = 25;
        const int requests = 96;
        var rotating = new RotatingConfigurationProvider(Credentials(0));
        IConfigurationRoot root = new ConfigurationBuilder().Add(rotating).Build();
        _services.AddHmacClient<OrdersApiClient>(root.GetSection("Api")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        Task rotation = Task.Run(
            () =>
            {
                for (int i = 1; i <= rotations; i++)
                {
                    rotating.Rotate(Credentials(i));
                }
            },
            cancellationToken);
        IEnumerable<Task> sends = Enumerable.Range(0, requests).Select(i => Task.Run(
            () => SendGetAsync(client, new Uri($"https://api.example.com/api/items/{i}")),
            cancellationToken));
        await Task.WhenAll([rotation, .. sends]);
        CapturedRequest final = await GetAsync(client, new Uri("https://api.example.com/api/final"));

        string[] secrets = [.. Enumerable.Range(0, rotations + 1).Select(i => $"secret-{i}")];
        Assert.Equal(requests + 1, _transport.Requests.Count);
        Assert.All(_transport.Requests, sent => Assert.Contains(secrets, secret => ReferenceSigner.Sign(secret, sent) == sent.Signature));
        Assert.Equal(ReferenceSigner.Sign($"secret-{rotations}", final), final.Signature);

        static Dictionary<string, string?> Credentials(int version) => new()
        {
            ["Api:ClientId"] = "rotating-client",
            ["Api:Secret"] = $"secret-{version}",
        };
    }

    [Fact]
    public async Task DelegateOverload_IsEvaluatedOnceAcrossRequestsClientsAndConfigurationReloads()
    {
        int evaluations = 0;
        _services.AddHmacClient<OrdersApiClient>(options =>
            {
                Interlocked.Increment(ref evaluations);
                options.ClientId = "delegate-client";
                options.Secret = _configuration["OrdersApi:Secret"]!;
                options.BaseAddress = new Uri("https://delegate.example.com/");
            })
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        _services.AddHmacClient<BillingApiClient>(_configuration.GetSection("BillingApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();

        await GetAsync(provider.GetRequiredService<OrdersApiClient>().HttpClient);
        _configuration["OrdersApi:Secret"] = "orders-secret-v2";
        _configuration.Reload();
        await GetAsync(provider.GetRequiredService<OrdersApiClient>().HttpClient);
        using (var request = new HttpRequestMessage(HttpMethod.Get, new Uri("orders", UriKind.Relative)))
        using (provider.GetRequiredService<OrdersApiClient>().HttpClient.Send(request, TestContext.Current.CancellationToken))
        {
        }

        Assert.Equal(1, evaluations);
        Assert.Equal(3, _transport.InvocationCount);
        Assert.All(_transport.Requests, sent => Assert.Equal(ReferenceSigner.Sign("orders-secret-v1", sent), sent.Signature));
    }

    private Registration Register(string kind, IConfiguration section)
    {
        IHttpClientBuilder builder = kind switch
        {
            "typed" => _services.AddHmacClient<OrdersApiClient>(section),
            "typed-contract" => _services.AddHmacClient<IInventoryApi, InventoryApiClient>(section),
            "named" => _services.AddHmacClient("orders", section),
            "signing" => _services.AddHttpClient("orders-signing").AddHmacSigning(section),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
        };
        builder.ConfigurePrimaryHttpMessageHandler(() => _transport);

        Func<IServiceProvider, HttpClient> resolve = kind switch
        {
            "typed" => provider => provider.GetRequiredService<OrdersApiClient>().HttpClient,
            "typed-contract" => provider => provider.GetRequiredService<IInventoryApi>().HttpClient,
            "named" => provider => provider.GetRequiredService<IHttpClientFactory>().CreateClient("orders"),
            _ => provider => provider.GetRequiredService<IHttpClientFactory>().CreateClient("orders-signing"),
        };

        return new Registration(builder, resolve);
    }

    /// <summary>
    /// Sends a GET through a client whose primary handler is <see cref="_transport"/> and returns what it captured.
    /// </summary>
    private async Task<CapturedRequest> GetAsync(HttpClient client, Uri? uri = null)
    {
        await SendGetAsync(client, uri);
        return _transport.LastRequest;
    }

    private static async Task SendGetAsync(HttpClient client, Uri? uri = null)
    {
        using HttpResponseMessage response = await client.GetAsync(uri ?? new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken);
    }

    private sealed record Registration(IHttpClientBuilder Builder, Func<IServiceProvider, HttpClient> Resolve);
}
