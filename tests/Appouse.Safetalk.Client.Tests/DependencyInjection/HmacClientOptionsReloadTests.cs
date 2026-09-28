using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// Credentials are resolved through <see cref="IOptionsMonitor{TOptions}"/> on every request, so a rotated secret is
/// used by the very next request of an existing <see cref="HttpClient"/> (no new client, no restart).
/// </summary>
public sealed class HmacClientOptionsReloadTests : IDisposable
{
    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly CapturingHandler _transport = new();
    private readonly ServiceCollection _services = new();
    private readonly IConfigurationRoot _configuration = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Safetalk:ClientId"] = "partner-a",
            ["Safetalk:Secret"] = "secret-v1",
        })
        .Build();

    public HmacClientOptionsReloadTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    public void Dispose() => _transport.Dispose();

    [Fact]
    public async Task SendAsync_ConfigurationBoundOptionsReloaded_NextRequestUsesRotatedSecret()
    {
        IHttpClientBuilder builder = _services.AddHmacClient<OrdersApiClient>(_ => { })
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        _services.Configure<HmacClientOptions>(builder.Name, _configuration.GetSection("Safetalk"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        CapturedRequest before = await GetAsync(client);
        _configuration["Safetalk:Secret"] = "secret-v2";
        _configuration.Reload();
        CapturedRequest after = await GetAsync(client);

        Assert.Equal(ReferenceSigner.Sign("secret-v1", before), before.Signature);
        Assert.Equal(ReferenceSigner.Sign("secret-v2", after), after.Signature);
    }

    [Fact]
    public async Task SendAsync_ConfigurationBoundClientIdReloaded_NextRequestUsesNewClientId()
    {
        IHttpClientBuilder builder = _services.AddHmacClient<OrdersApiClient>(_ => { })
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        _services.Configure<HmacClientOptions>(builder.Name, _configuration.GetSection("Safetalk"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        CapturedRequest before = await GetAsync(client);
        _configuration["Safetalk:ClientId"] = "partner-b";
        _configuration["Safetalk:Secret"] = "secret-b";
        _configuration.Reload();
        CapturedRequest after = await GetAsync(client);

        Assert.Equal("partner-a", before.ClientId);
        Assert.Equal("partner-b", after.ClientId);
        Assert.Equal(ReferenceSigner.Sign("secret-b", after), after.Signature);
    }

    [Fact]
    public async Task SendAsync_ReloadedToInvalidOptions_NextRequestFailsBeforeReachingTransport()
    {
        IHttpClientBuilder builder = _services.AddHmacClient<OrdersApiClient>(_ => { })
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        _services.Configure<HmacClientOptions>(builder.Name, _configuration.GetSection("Safetalk"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        await GetAsync(client);
        _configuration["Safetalk:Secret"] = string.Empty;

        // OptionsMonitor re-creates (and therefore re-validates) the options as soon as the change token fires.
        AggregateException reloadFailure = Assert.Throws<AggregateException>(_configuration.Reload);
        Assert.IsType<OptionsValidationException>(Assert.Single(reloadFailure.InnerExceptions));

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(
            () => client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken));

        Assert.Equal(builder.Name, exception.OptionsName);
        Assert.Equal(1, _transport.InvocationCount);
    }

    [Fact]
    public async Task SendAsync_ReloadOfOneClient_DoesNotAffectAnotherClient()
    {
        var billingTransport = new CapturingHandler();
        IHttpClientBuilder orders = _services.AddHmacClient<OrdersApiClient>(_ => { })
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        _services.Configure<HmacClientOptions>(orders.Name, _configuration.GetSection("Safetalk"));
        _services.AddHmacClient<BillingApiClient>(options =>
            {
                options.ClientId = "billing-client";
                options.Secret = "billing-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => billingTransport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient billing = provider.GetRequiredService<BillingApiClient>().HttpClient;

        _configuration["Safetalk:Secret"] = "secret-v2";
        _configuration.Reload();
        using HttpResponseMessage response = await billing.GetAsync(new Uri("https://api.example.com/api/invoices"), TestContext.Current.CancellationToken);

        CapturedRequest sent = billingTransport.SingleRequest;
        Assert.Equal("billing-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("billing-secret", sent), sent.Signature);
    }

    /// <summary>
    /// Follows the delegate usage documented on <c>AddHmacClient</c>
    /// (<c>options.Secret = configuration["Safetalk:Secret"]!</c>). Delegate-configured options are documented as
    /// evaluated once, so a reload does not rotate them; the <see cref="IConfiguration"/> overload is the rotation path.
    /// </summary>
    [Fact]
    public async Task SendAsync_ConfigureDelegateReadingReloadableConfiguration_IsEvaluatedOnceAndKeepsOriginalSecret()
    {
        int evaluations = 0;
        _services.AddHmacClient<OrdersApiClient>(options =>
            {
                Interlocked.Increment(ref evaluations);
                options.ClientId = _configuration["Safetalk:ClientId"]!;
                options.Secret = _configuration["Safetalk:Secret"]!;
            })
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        CapturedRequest before = await GetAsync(client);
        _configuration["Safetalk:Secret"] = "secret-v2";
        _configuration.Reload();
        CapturedRequest after = await GetAsync(client);
        CapturedRequest fromNewClient = await GetAsync(provider.GetRequiredService<OrdersApiClient>().HttpClient);

        Assert.Equal(ReferenceSigner.Sign("secret-v1", before), before.Signature);
        Assert.Equal(ReferenceSigner.Sign("secret-v1", after), after.Signature);
        Assert.Equal(ReferenceSigner.Sign("secret-v1", fromNewClient), fromNewClient.Signature);
        Assert.Equal(1, evaluations);
    }

    [Fact]
    public async Task SendAsync_ConfigurationOverloadReloaded_NextRequestOfExistingClientUsesRotatedSecret()
    {
        _services.AddHmacClient<OrdersApiClient>(_configuration.GetSection("Safetalk"))
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        CapturedRequest before = await GetAsync(client);
        _configuration["Safetalk:Secret"] = "secret-v2";
        _configuration.Reload();
        CapturedRequest after = await GetAsync(client);

        Assert.Equal(ReferenceSigner.Sign("secret-v1", before), before.Signature);
        Assert.Equal(ReferenceSigner.Sign("secret-v2", after), after.Signature);
    }

    private async Task<CapturedRequest> GetAsync(HttpClient client)
    {
        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);
        return _transport.LastRequest;
    }
}
