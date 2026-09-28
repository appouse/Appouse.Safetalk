using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

public sealed class HmacClientServiceCollectionExtensionsTests
{
    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly ServiceCollection _services = new();

    public HmacClientServiceCollectionExtensionsTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    [Fact]
    public async Task AddHmacClient_TypedClient_SignsRequests()
    {
        var transport = new CapturingHandler();
        _services.AddHmacClient<OrdersApiClient>(options =>
            {
                options.ClientId = "orders-client";
                options.Secret = "orders-secret";
            })
            .ConfigureHttpClient(client => client.BaseAddress = new Uri("https://orders.example.com/"))
            .ConfigurePrimaryHttpMessageHandler(() => transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OrdersApiClient client = provider.GetRequiredService<OrdersApiClient>();
        using HttpResponseMessage response = await client.HttpClient.GetAsync(new Uri("api/orders?id=5", UriKind.Relative), TestContext.Current.CancellationToken);

        CapturedRequest sent = transport.SingleRequest;
        Assert.Equal("orders-client", sent.ClientId);
        Assert.Equal("1790000000", sent.Timestamp);
        Assert.Equal(ReferenceSigner.Sign("orders-secret", "GET", "/api/orders?id=5", "1790000000", []), sent.Signature);
    }

    [Fact]
    public async Task AddHmacClient_ContractAndImplementation_ResolvesContractAndSignsRequests()
    {
        var transport = new CapturingHandler();
        IHttpClientBuilder builder = _services.AddHmacClient<IInventoryApi, InventoryApiClient>(options =>
            {
                options.ClientId = "inventory-client";
                options.Secret = "inventory-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IInventoryApi client = provider.GetRequiredService<IInventoryApi>();
        using var content = new StringContent("{\"sku\":\"TEA-1\",\"quantity\":3}");
        using HttpResponseMessage response = await client.HttpClient.PostAsync(new Uri("https://inventory.example.com/api/stock"), content, TestContext.Current.CancellationToken);

        Assert.IsType<InventoryApiClient>(client);
        CapturedRequest sent = transport.SingleRequest;
        Assert.Equal("inventory-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("inventory-secret", sent), sent.Signature);
        Assert.Equal("inventory-client", provider.GetRequiredService<IOptionsMonitor<HmacClientOptions>>().Get(builder.Name).ClientId);
    }

    [Fact]
    public async Task AddHmacClient_TwoTypedClients_UseIsolatedCredentials()
    {
        var ordersTransport = new CapturingHandler();
        var billingTransport = new CapturingHandler();
        _services.AddHmacClient<OrdersApiClient>(options =>
            {
                options.ClientId = "orders-client";
                options.Secret = "orders-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => ordersTransport);
        _services.AddHmacClient<BillingApiClient>(options =>
            {
                options.ClientId = "billing-client";
                options.Secret = "billing-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => billingTransport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (await provider.GetRequiredService<OrdersApiClient>().HttpClient.GetAsync(new Uri("https://api.example.com/orders"), cancellationToken))
        using (await provider.GetRequiredService<BillingApiClient>().HttpClient.GetAsync(new Uri("https://api.example.com/invoices"), cancellationToken))
        {
        }

        CapturedRequest orders = ordersTransport.SingleRequest;
        CapturedRequest billing = billingTransport.SingleRequest;
        Assert.Equal("orders-client", orders.ClientId);
        Assert.Equal(ReferenceSigner.Sign("orders-secret", orders), orders.Signature);
        Assert.NotEqual(ReferenceSigner.Sign("billing-secret", orders), orders.Signature);
        Assert.Equal("billing-client", billing.ClientId);
        Assert.Equal(ReferenceSigner.Sign("billing-secret", billing), billing.Signature);
        Assert.NotEqual(ReferenceSigner.Sign("orders-secret", billing), billing.Signature);
    }

    [Fact]
    public void AddHmacClient_ReturnsBuilderNamedAfterTypedClient()
    {
        IHttpClientBuilder typed = _services.AddHmacClient<OrdersApiClient>(ConfigureValid);
        IHttpClientBuilder contract = _services.AddHmacClient<IInventoryApi, InventoryApiClient>(ConfigureValid);

        Assert.Equal(nameof(OrdersApiClient), typed.Name);
        Assert.Equal(nameof(IInventoryApi), contract.Name);
    }

    [Fact]
    public void AddHmacClient_RegistersDefaultSignatureServiceAndSystemClock()
    {
        var services = new ServiceCollection();
        services.AddHmacClient<OrdersApiClient>(ConfigureValid);
        using ServiceProvider provider = services.BuildServiceProvider(validateScopes: true);

        Assert.Same(HmacSha256SignatureService.Instance, provider.GetRequiredService<IHmacSignatureService>());
        Assert.Same(TimeProvider.System, provider.GetRequiredService<TimeProvider>());
        Assert.IsType<HmacClientOptionsValidator>(Assert.Single(provider.GetServices<IValidateOptions<HmacClientOptions>>()));
    }

    [Fact]
    public async Task AddHmacClient_ExistingSignatureServiceAndClock_AreNotReplaced()
    {
        var recorder = new RecordingSignatureService("custom-signature");
        var transport = new CapturingHandler();
        _services.AddSingleton<IHmacSignatureService>(recorder);
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid).ConfigurePrimaryHttpMessageHandler(() => transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Same(_time, provider.GetRequiredService<TimeProvider>());
        CapturedRequest sent = transport.SingleRequest;
        Assert.Equal("custom-signature", sent.Signature);
        Assert.Equal("1790000000", sent.Timestamp);
        Assert.Equal(ReferenceSigner.BuildCanonicalRequest("GET", "/api/orders", "1790000000", []), Assert.Single(recorder.CanonicalRequests));
    }

    [Fact]
    public void AddHmacClient_NullArguments_ThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("services", () => HmacClientServiceCollectionExtensions.AddHmacClient<OrdersApiClient>(null!, ConfigureValid));
        Assert.Throws<ArgumentNullException>("configureOptions", () => _services.AddHmacClient<OrdersApiClient>((Action<HmacClientOptions>)null!));
        Assert.Throws<ArgumentNullException>("services", () => HmacClientServiceCollectionExtensions.AddHmacClient<IInventoryApi, InventoryApiClient>(null!, ConfigureValid));
        Assert.Throws<ArgumentNullException>("configureOptions", () => _services.AddHmacClient<IInventoryApi, InventoryApiClient>((Action<HmacClientOptions>)null!));
    }

    [Fact]
    public void AddHmacClient_NullArgumentsForConfigurationAndNamedOverloads_Throw()
    {
        IConfiguration configuration = new ConfigurationBuilder().Build();

        Assert.Throws<ArgumentNullException>("services", () => HmacClientServiceCollectionExtensions.AddHmacClient<OrdersApiClient>(null!, configuration));
        Assert.Throws<ArgumentNullException>("configuration", () => _services.AddHmacClient<OrdersApiClient>((IConfiguration)null!));
        Assert.Throws<ArgumentNullException>("services", () => HmacClientServiceCollectionExtensions.AddHmacClient<IInventoryApi, InventoryApiClient>(null!, configuration));
        Assert.Throws<ArgumentNullException>("configuration", () => _services.AddHmacClient<IInventoryApi, InventoryApiClient>((IConfiguration)null!));
        Assert.Throws<ArgumentNullException>("services", () => HmacClientServiceCollectionExtensions.AddHmacClient(null!, "partner", ConfigureValid));
        Assert.Throws<ArgumentNullException>("services", () => HmacClientServiceCollectionExtensions.AddHmacClient(null!, "partner", configuration));
        Assert.Throws<ArgumentNullException>("name", () => _services.AddHmacClient(null!, ConfigureValid));
        Assert.Throws<ArgumentException>("name", () => _services.AddHmacClient(string.Empty, ConfigureValid));
        Assert.Throws<ArgumentNullException>("name", () => _services.AddHmacClient(null!, configuration));
        Assert.Throws<ArgumentException>("name", () => _services.AddHmacClient(string.Empty, configuration));
        Assert.Throws<ArgumentNullException>("configureOptions", () => _services.AddHmacClient("partner", (Action<HmacClientOptions>)null!));
        Assert.Throws<ArgumentNullException>("configuration", () => _services.AddHmacClient("partner", (IConfiguration)null!));
    }

    /// <summary>
    /// The registration reads <see cref="HmacClientOptions.BaseAddress"/> when the <see cref="HttpClient"/> is created,
    /// so invalid options (without the host's start-up validation) now fail when the client is created — still before
    /// anything reaches the transport.
    /// </summary>
    [Fact]
    public void AddHmacClient_InvalidOptionsWithoutStartupValidation_ClientCreationFailsBeforeReachingTransport()
    {
        var transport = new CapturingHandler();
        _services.AddHmacClient<OrdersApiClient>(options =>
            {
                options.ClientId = "orders client ";
                options.Secret = string.Empty;
            })
            .ConfigurePrimaryHttpMessageHandler(() => transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<OrdersApiClient>());

        Assert.Equal(nameof(OrdersApiClient), exception.OptionsName);
        Assert.Equal(2, exception.Failures.Count());
        Assert.Equal(0, transport.InvocationCount);
    }

    [Fact]
    public async Task AddHmacClient_NamedClient_CreateClientByNameSignsAndOtherClientsDoNot()
    {
        var signedTransport = new CapturingHandler();
        var plainTransport = new CapturingHandler();
        IHttpClientBuilder builder = _services.AddHmacClient("partner", options =>
            {
                options.ClientId = "named-client";
                options.Secret = "named-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => signedTransport);
        _services.AddHttpClient("plain").ConfigurePrimaryHttpMessageHandler(() => plainTransport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (HttpClient signed = factory.CreateClient("partner"))
        using (HttpClient plain = factory.CreateClient("plain"))
        using (var content = new StringContent("{\"ping\":1}"))
        using (await signed.PostAsync(new Uri("https://api.example.com/api/ping"), content, cancellationToken))
        using (await plain.GetAsync(new Uri("https://api.example.com/api/ping"), cancellationToken))
        {
        }

        Assert.Equal("partner", builder.Name);
        CapturedRequest sent = signedTransport.SingleRequest;
        Assert.Equal("named-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("named-secret", "POST", "/api/ping", "1790000000", "{\"ping\":1}"u8), sent.Signature);
        Assert.False(plainTransport.SingleRequest.HasHeader(CapturedRequest.SignatureHeader));
    }

    [Fact]
    public void AddHmacClient_NamedClient_ValidatesAtStartupUnderItsName()
    {
        _services.AddHmacClient("partner", options => options.ClientId = "named-client");
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal("partner", exception.OptionsName);
        Assert.Equal("Secret must be provided.", Assert.Single(exception.Failures));
    }

    [Fact]
    public async Task AddHmacClient_TwoNamedClientsWithDifferentNames_UseIsolatedCredentials()
    {
        var firstTransport = new CapturingHandler();
        var secondTransport = new CapturingHandler();
        _services.AddHmacClient("first", options =>
            {
                options.ClientId = "first-client";
                options.Secret = "first-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => firstTransport);
        _services.AddHmacClient("second", options =>
            {
                options.ClientId = "second-client";
                options.Secret = "second-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => secondTransport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (HttpClient first = factory.CreateClient("first"))
        using (HttpClient second = factory.CreateClient("second"))
        using (await first.GetAsync(new Uri("https://api.example.com/x"), cancellationToken))
        using (await second.GetAsync(new Uri("https://api.example.com/x"), cancellationToken))
        {
        }

        Assert.Equal(ReferenceSigner.Sign("first-secret", firstTransport.SingleRequest), firstTransport.SingleRequest.Signature);
        Assert.Equal(ReferenceSigner.Sign("second-secret", secondTransport.SingleRequest), secondTransport.SingleRequest.Signature);
        Assert.NotEqual(firstTransport.SingleRequest.Signature, secondTransport.SingleRequest.Signature);
    }

    private static void ConfigureValid(HmacClientOptions options)
    {
        options.ClientId = "partner-a";
        options.Secret = "secret";
    }
}
