using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// Round 4: registering signing for the same client (or for the defaults) more than once leaves exactly one signer in the
/// pipeline — the earlier signing and signing-state handlers are removed and disposed — while the options registrations
/// are cumulative: a later registration overrides only the values it sets.
/// </summary>
public sealed class HmacSigningRepeatedRegistrationTests : IDisposable
{
    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly CapturingHandler _transport = new();
    private readonly ServiceCollection _services = new();

    public HmacSigningRepeatedRegistrationTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    public void Dispose() => _transport.Dispose();

    [Fact]
    public async Task AddHmacSigningTwice_SecondSetsOnlyTheSecret_KeepsTheFirstClientIdAndBaseAddress()
    {
        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options =>
            {
                options.ClientId = "first-client";
                options.Secret = "first-secret";
                options.BaseAddress = new Uri("https://first.example.com/v1/");
            })
            .AddHmacSigning(options => options.Secret = "second-secret");
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Equal(new Uri("https://first.example.com/v1/"), client.BaseAddress);
        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("/v1/orders", sent.PathAndQuery);
        Assert.Equal("first-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("second-secret", sent), sent.Signature);
        AssertSingleSigner(provider, "partner");
    }

    [Fact]
    public async Task AddHmacSigningTwice_BothSetTheBaseAddress_TheLastOneIsUsed()
    {
        _services.AddHmacClient("partner", options =>
            {
                options.ClientId = "partner-a";
                options.Secret = "secret";
                options.BaseAddress = new Uri("https://first.example.com/");
            })
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => options.BaseAddress = new Uri("https://second.example.com/"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Equal(new Uri("https://second.example.com/"), client.BaseAddress);
        Assert.Equal(new Uri("https://second.example.com/orders"), _transport.SingleRequest.RequestUri);
    }

    [Fact]
    public async Task AddHmacClientThenAddHmacSigningWithoutValues_KeepsTheFirstCredentialsAndPassesValidation()
    {
        _services.AddHmacClient<OrdersApiClient>(options =>
            {
                options.ClientId = "typed-client";
                options.Secret = "typed-secret";
            })
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        _services.AddHttpClient<OrdersApiClient>().AddHmacSigning(_ => { });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("typed-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("typed-secret", sent), sent.Signature);
        AssertSingleSigner(provider, nameof(OrdersApiClient));
    }

    [Fact]
    public void AddHmacSigningTwice_SecondSetsAnInvalidValue_ItOverridesTheFirstAndFailsValidation()
    {
        _services.AddHmacClient("partner", options =>
            {
                options.ClientId = "partner-a";
                options.Secret = "secret";
            })
            .AddHmacSigning(options => options.Secret = string.Empty);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal("partner", exception.OptionsName);
        Assert.Equal("Secret must be provided.", Assert.Single(exception.Failures));
    }

    [Fact]
    public async Task AddHmacSigningTwice_ConfigurationThenDelegateWithOnlyTheBaseAddress_KeepsFollowingTheSectionReloads()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Partner:ClientId"] = "config-client",
                ["Partner:Secret"] = "secret-v1",
            })
            .Build();
        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(configuration.GetSection("Partner"))
            .AddHmacSigning(options => options.BaseAddress = new Uri("https://partner.example.com/"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (await client.GetAsync(new Uri("orders", UriKind.Relative), cancellationToken))
        {
        }

        configuration["Partner:Secret"] = "secret-v2";
        configuration.Reload();
        using (await client.GetAsync(new Uri("orders", UriKind.Relative), cancellationToken))
        {
        }

        Assert.Equal(new Uri("https://partner.example.com/"), client.BaseAddress);
        IReadOnlyList<CapturedRequest> sent = _transport.Requests;
        Assert.Equal(2, sent.Count);
        Assert.All(sent, request => Assert.Equal("config-client", request.ClientId));
        Assert.Equal(ReferenceSigner.Sign("secret-v1", sent[0]), sent[0].Signature);
        Assert.Equal(ReferenceSigner.Sign("secret-v2", sent[1]), sent[1].Signature);
        AssertSingleSigner(provider, "partner");
    }

    [Fact]
    public async Task AddHmacSigningTwice_SecondFromConfigurationWithoutBaseAddress_KeepsTheFirstBaseAddress()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Partner:Secret"] = "config-secret" })
            .Build();
        _services.AddHmacClient("partner", options =>
            {
                options.ClientId = "partner-a";
                options.Secret = "delegate-secret";
                options.BaseAddress = new Uri("https://partner.example.com/api/");
            })
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(configuration.GetSection("Partner"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal(new Uri("https://partner.example.com/api/orders"), sent.RequestUri);
        Assert.Equal("partner-a", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("config-secret", sent), sent.Signature);
    }

    [Fact]
    public async Task AddHmacSigningOnSeparateBuildersForTheSameName_OneSignerWithCumulativeOptions()
    {
        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => options.ClientId = "partner-a");
        _services.AddHttpClient("partner").AddHmacSigning(options => options.Secret = "partner-secret");
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("partner-a", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("partner-secret", sent), sent.Signature);
        AssertSingleSigner(provider, "partner");
    }

    [Fact]
    public async Task ConfigureHttpClientDefaultsTwice_SecondSetsOnlyTheSecret_KeepsTheFirstClientIdAndBaseAddress()
    {
        _services.ConfigureHttpClientDefaults(builder => builder
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options =>
            {
                options.ClientId = "defaults-client";
                options.Secret = "first-secret";
                options.BaseAddress = new Uri("https://defaults.example.com/");
            }));
        _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options => options.Secret = "second-secret"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("any");

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal(new Uri("https://defaults.example.com/orders"), sent.RequestUri);
        Assert.Equal("defaults-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("second-secret", sent), sent.Signature);
        AssertSingleSigner(provider, "any");
    }

    /// <summary>
    /// Sensitivity check for <see cref="HandlerAdditionRecorder"/> (used to prove that the defaults create no handler
    /// for a client with its own registration): a repeated registration does create handlers and replace them, and the
    /// recorder sees every one of them; the replaced ones are disposed.
    /// </summary>
    [Fact]
    public async Task AddHmacSigningThreeTimesWithUserHandlersBetween_OneSignerAndTheReplacedHandlersAreDisposed()
    {
        var additions = new HandlerAdditionRecorder();
        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => options.ClientId = "partner-a")
            .AddHttpMessageHandler(() => new RequestMutatingHandler("tenant=7"))
            .AddHmacSigning(options => options.Secret = "partner-secret")
            .AddHttpMessageHandler(() => new CountingRetryHandler(2))
            .AddHmacSigning(_ => { });
        _services.AddSingleton<IHttpMessageHandlerBuilderFilter>(additions);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        IReadOnlyList<DelegatingHandler> pipeline = HandlerChain.ContributedHandlers(provider, "partner", _transport);
        IReadOnlyList<DelegatingHandler> added = additions.AddedTo("partner");
        Assert.Equal(
            [typeof(HmacSigningStateHandler), typeof(RequestMutatingHandler), typeof(CountingRetryHandler), typeof(HmacSigningHandler)],
            pipeline.Select(h => h.GetType()));
        Assert.Equal(3, added.OfType<HmacSigningHandler>().Count());
        Assert.Equal(3, added.OfType<HmacSigningStateHandler>().Count());
        DelegatingHandler[] replaced = [.. added.Where(h => h is HmacSigningHandler or HmacSigningStateHandler).Except(pipeline)];
        Assert.Equal(4, replaced.Length);
        Assert.All(replaced, handler =>
        {
            using var probe = new CapturingHandler();
            Assert.Throws<ObjectDisposedException>(() => handler.InnerHandler = probe);
        });

        Assert.Equal(["1790000000", "1790000001"], _transport.Requests.Select(r => r.Timestamp));
        Assert.All(_transport.Requests, attempt =>
        {
            Assert.Equal("/api/orders?tenant=7", attempt.PathAndQuery);
            Assert.Equal("partner-a", attempt.ClientId);
            Assert.Equal(ReferenceSigner.Sign("partner-secret", attempt), attempt.Signature);
        });
    }

    private static void AssertSingleSigner(IServiceProvider provider, string name)
    {
        IReadOnlyList<HttpMessageHandler> chain = HandlerChain.Walk(provider, name);
        Assert.Single(chain.OfType<HmacSigningStateHandler>());
        Assert.Single(chain.OfType<HmacSigningHandler>());
    }
}
