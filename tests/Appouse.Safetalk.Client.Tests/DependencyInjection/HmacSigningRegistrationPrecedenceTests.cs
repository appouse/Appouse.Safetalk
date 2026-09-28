using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// A pipeline has exactly one signer: <see cref="HmacSigningStateHandler"/> first and <see cref="HmacSigningHandler"/>
/// last among the additional handlers. A client's own <c>AddHmacSigning</c> registration beats
/// <c>ConfigureHttpClientDefaults(b =&gt; b.AddHmacSigning(...))</c> whatever the registration order: the defaults do
/// nothing at all for such a client (no handlers, no base address). Registering the same client twice keeps one signer
/// (the earlier handlers are removed and disposed) while the options registrations are cumulative.
/// </summary>
public sealed class HmacSigningRegistrationPrecedenceTests : IDisposable
{
    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly CapturingHandler _transport = new();
    private readonly ServiceCollection _services = new();

    public HmacSigningRegistrationPrecedenceTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    public void Dispose() => _transport.Dispose();

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaultsAndNamedClient_AnyOrder_NamedClientUsesItsOwnCredentialsWithASingleSigner(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret"));

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();

        CapturedRequest orders = await SendAsync(provider, "orders");
        CapturedRequest other = await SendAsync(provider, "other");
        CapturedRequest unnamed = await SendAsync(provider, Options.DefaultName);

        Assert.Equal("orders-client", orders.ClientId);
        Assert.Equal(ReferenceSigner.Sign("orders-secret", orders), orders.Signature);
        Assert.Equal("defaults-client", other.ClientId);
        Assert.Equal(ReferenceSigner.Sign("defaults-secret", other), other.Signature);
        Assert.Equal("defaults-client", unnamed.ClientId);
        AssertSingleSigner(provider, "orders");
        AssertSingleSigner(provider, "other");
        AssertSingleSigner(provider, Options.DefaultName);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaultsAndTypedClient_AnyOrder_TypedClientUsesItsOwnCredentials(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, "typed-client", "typed-secret"));
        _services.AddHttpClient<BillingApiClient>();

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (await provider.GetRequiredService<OrdersApiClient>().HttpClient.GetAsync(new Uri("https://api.example.com/orders"), cancellationToken))
        using (await provider.GetRequiredService<BillingApiClient>().HttpClient.GetAsync(new Uri("https://api.example.com/invoices"), cancellationToken))
        {
        }

        Assert.Collection(
            _transport.Requests,
            typed =>
            {
                Assert.Equal("typed-client", typed.ClientId);
                Assert.Equal(ReferenceSigner.Sign("typed-secret", typed), typed.Signature);
            },
            billing =>
            {
                Assert.Equal("defaults-client", billing.ClientId);
                Assert.Equal(ReferenceSigner.Sign("defaults-secret", billing), billing.Signature);
            });
        AssertSingleSigner(provider, nameof(OrdersApiClient));
        AssertSingleSigner(provider, nameof(BillingApiClient));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaultsAndNamedClientWithRetry_AnyOrder_RetriesAreSignedOnceEachWithTheNamedCredentials(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret"))
            .AddHttpMessageHandler(() => new CountingRetryHandler(3));

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        await SendAsync(provider, "orders");

        Assert.Equal(["1790000000", "1790000001", "1790000002"], _transport.Requests.Select(r => r.Timestamp));
        Assert.All(_transport.Requests, attempt =>
        {
            Assert.Equal("orders-client", attempt.ClientId);
            Assert.Equal(ReferenceSigner.Sign("orders-secret", attempt), attempt.Signature);
        });
    }

    [Fact]
    public async Task ConfigureHttpClientDefaultsFromConfiguration_ReloadedSecret_OtherClientsUseTheRotatedSecret()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Defaults:ClientId"] = "defaults-client",
                ["Defaults:Secret"] = "old-secret",
            })
            .Build();
        _services.ConfigureHttpClientDefaults(builder => builder
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(configuration.GetSection("Defaults")));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        CapturedRequest before = await SendAsync(provider, "any");
        configuration["Defaults:Secret"] = "new-secret";
        configuration.Reload();
        CapturedRequest after = await SendAsync(provider, "any");

        Assert.Equal(ReferenceSigner.Sign("old-secret", before), before.Signature);
        Assert.Equal(ReferenceSigner.Sign("new-secret", after), after.Signature);
    }

    /// <summary>
    /// Round 4: the defaults registration uses the reserved options name, so it can no longer collide with the options
    /// of the factory's unnamed client (<see cref="Options.DefaultName"/>).
    /// </summary>
    [Fact]
    public void ConfigureHttpClientDefaultsWithInvalidCredentials_FailsStartupValidationUnderTheReservedDefaultsName()
    {
        _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options => options.ClientId = "defaults-client"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal("Appouse.Safetalk.HttpClientDefaults", exception.OptionsName);
        Assert.Equal(HmacHttpClientBuilderExtensions.DefaultsOptionsName, exception.OptionsName);
        Assert.Equal("Secret must be provided.", Assert.Single(exception.Failures));
    }

    [Fact]
    public async Task ConfigureHttpClientDefaultsRegisteredTwice_HasASingleSignerWithTheLastCredentials()
    {
        _services.ConfigureHttpClientDefaults(builder => builder
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => Configure(options, "first-client", "first-secret")));
        _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options => Configure(options, "second-client", "second-secret")));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        CapturedRequest sent = await SendAsync(provider, "any");

        Assert.Equal("second-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("second-secret", sent), sent.Signature);
        AssertSingleSigner(provider, "any");
    }

    [Theory]
    [InlineData("delegate", "delegate")]
    [InlineData("delegate", "configuration")]
    [InlineData("configuration", "delegate")]
    [InlineData("configuration", "configuration")]
    public async Task AddHmacSigningTwice_SameClient_OneSignerWithTheLastCredentials(string first, string second)
    {
        IHttpClientBuilder builder = _services.AddHttpClient("partner").ConfigurePrimaryHttpMessageHandler(() => _transport);
        AddSigning(builder, first, "first-client", "first-secret");
        builder.AddHttpMessageHandler(() => new CountingRetryHandler(2));
        AddSigning(builder, second, "second-client", "second-secret");
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();

        await SendAsync(provider, "partner");

        Assert.Equal(["1790000000", "1790000001"], _transport.Requests.Select(r => r.Timestamp));
        Assert.All(_transport.Requests, attempt =>
        {
            Assert.Equal("second-client", attempt.ClientId);
            Assert.Equal(ReferenceSigner.Sign("second-secret", attempt), attempt.Signature);
        });
        AssertSingleSigner(provider, "partner");
    }

    [Fact]
    public async Task AddHmacClientThenAddHmacSigningOnTheSameBuilder_OneSignerWithTheLastCredentials()
    {
        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, "first-client", "first-secret"))
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => Configure(options, "second-client", "second-secret"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using (await provider.GetRequiredService<OrdersApiClient>().HttpClient.GetAsync(new Uri("https://api.example.com/"), TestContext.Current.CancellationToken))
        {
        }

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("second-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("second-secret", sent), sent.Signature);
        AssertSingleSigner(provider, nameof(OrdersApiClient));
    }

    [Fact]
    public void AddHmacSigningTwice_ReplacedHandlersAreRemovedAndDisposed()
    {
        var replaced = new List<DelegatingHandler>();
        IHttpClientBuilder builder = _services.AddHttpClient("partner").ConfigurePrimaryHttpMessageHandler(() => _transport);
        builder.AddHmacSigning(options => Configure(options, "first-client", "first-secret"));

        // Runs between the two registrations' actions: it sees the handlers the first registration attached.
        _services.PostConfigure<HttpClientFactoryOptions>("partner", options => options.HttpMessageHandlerBuilderActions.Add(
            handlerBuilder => replaced.AddRange(handlerBuilder.AdditionalHandlers.Where(h => h is HmacSigningHandler or HmacSigningStateHandler))));
        builder.AddHmacSigning(options => Configure(options, "second-client", "second-secret"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IReadOnlyList<DelegatingHandler> handlers = HandlerChain.ContributedHandlers(provider, "partner", _transport);

        Assert.Equal(2, replaced.Count);
        Assert.Single(replaced.OfType<HmacSigningStateHandler>());
        Assert.Single(replaced.OfType<HmacSigningHandler>());
        Assert.All(replaced, handler =>
        {
            Assert.DoesNotContain(handler, handlers);
            using var probe = new CapturingHandler();
            Assert.Throws<ObjectDisposedException>(() => handler.InnerHandler = probe);
        });
        Assert.IsType<HmacSigningStateHandler>(handlers[0]);
        Assert.IsType<HmacSigningHandler>(handlers[^1]);
    }

    /// <summary>
    /// Round 4: the defaults registration no longer creates handlers that the client's own registration then replaces;
    /// it attaches nothing to a client that has its own registration.
    /// </summary>
    [Fact]
    public async Task ConfigureHttpClientDefaultsThenNamedClient_DefaultsAttachNoHandlersToTheNamedPipeline()
    {
        var seenBetween = new List<DelegatingHandler>();
        var additions = new HandlerAdditionRecorder();
        RegisterSigningDefaults();

        // Registered between the defaults and the named client's own registration.
        _services.PostConfigure<HttpClientFactoryOptions>("orders", options => options.HttpMessageHandlerBuilderActions.Add(
            handlerBuilder => seenBetween.AddRange(handlerBuilder.AdditionalHandlers.Where(h => h is HmacSigningHandler or HmacSigningStateHandler))));
        _services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret"));
        _services.AddSingleton<IHttpMessageHandlerBuilderFilter>(additions);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IReadOnlyList<DelegatingHandler> handlers = HandlerChain.ContributedHandlers(provider, "orders", _transport);
        CapturedRequest sent = await SendAsync(provider, "orders");

        Assert.Empty(seenBetween);
        Assert.Equal(handlers, additions.AddedTo("orders"));
        Assert.Equal([typeof(HmacSigningStateHandler), typeof(HmacSigningHandler)], handlers.Select(h => h.GetType()));
        Assert.Equal("orders-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("orders-secret", sent), sent.Signature);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ConfigureHttpClientDefaultsAndNamedClient_AnyOrder_DefaultsHandlersAreNeverAttachedToTheNamedPipeline(bool defaultsRegisteredFirst)
    {
        var attached = new List<DelegatingHandler>();
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret"));

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        // Runs after both registrations' actions.
        _services.PostConfigure<HttpClientFactoryOptions>("orders", options => options.HttpMessageHandlerBuilderActions.Add(
            handlerBuilder => attached.AddRange(handlerBuilder.AdditionalHandlers)));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IReadOnlyList<DelegatingHandler> handlers = HandlerChain.ContributedHandlers(provider, "orders", _transport);

        Assert.Equal(handlers, attached);
        Assert.Equal([typeof(HmacSigningStateHandler), typeof(HmacSigningHandler)], handlers.Select(h => h.GetType()));
    }

    [Fact]
    public void PipelineShape_UserHandlersAddedBeforeAndAfter_StateHandlerFirstAndSignerLastInAdditionalHandlers()
    {
        var recorder = new AdditionalHandlersRecorder();
        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new CountingRetryHandler(1))
            .AddHmacSigning(options => Configure(options, "partner-a", "secret"))
            .AddHttpMessageHandler(() => new CloningHedgingHandler(1))
            .ConfigureAdditionalHttpMessageHandlers((handlers, _) => handlers.Add(new RetryOnceHandler(() => { })));
        _services.AddSingleton<IHttpMessageHandlerBuilderFilter>(recorder);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IReadOnlyList<DelegatingHandler> handlers = HandlerChain.ContributedHandlers(provider, "partner", _transport);

        Assert.Equal(
            [typeof(HmacSigningStateHandler), typeof(CountingRetryHandler), typeof(CloningHedgingHandler), typeof(RetryOnceHandler), typeof(HmacSigningHandler)],
            handlers.Select(h => h.GetType()));
        Assert.Equal(handlers, recorder.For("partner"));
    }

    [Fact]
    public void PipelineShape_ClientWithoutSigning_HasNoSigningHandlers()
    {
        _services.AddHmacClient("signed", options => Configure(options, "partner-a", "secret"));
        _services.AddHttpClient("plain").ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IReadOnlyList<DelegatingHandler> handlers = HandlerChain.ContributedHandlers(provider, "plain", _transport);

        Assert.DoesNotContain(handlers, h => h is HmacSigningHandler or HmacSigningStateHandler);
    }

    /// <summary>
    /// A client with its own signing registration uses its own credentials; it should not silently inherit the base
    /// address of the <c>ConfigureHttpClientDefaults</c> signing registration either, otherwise requests signed with its
    /// credentials are sent to the host configured for the defaults' client.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ConfigureHttpClientDefaultsWithBaseAddress_NamedClientWithOwnRegistrationWithoutBaseAddress_DoesNotInheritTheDefaultsBaseAddress(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options =>
            {
                Configure(options, "defaults-client", "defaults-secret");
                options.BaseAddress = new Uri("https://defaults-partner.example.com/");
            }));
        }

        _services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret"));

        if (!defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options =>
            {
                Configure(options, "defaults-client", "defaults-secret");
                options.BaseAddress = new Uri("https://defaults-partner.example.com/");
            }));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();

        using HttpClient orders = factory.CreateClient("orders");
        using HttpClient other = factory.CreateClient("other");

        Assert.Equal(new Uri("https://defaults-partner.example.com/"), other.BaseAddress);
        Assert.Null(orders.BaseAddress);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ConfigureHttpClientDefaultsWithBaseAddress_NamedClientWithItsOwnBaseAddress_UsesItsOwn(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options =>
            {
                Configure(options, "defaults-client", "defaults-secret");
                options.BaseAddress = new Uri("https://defaults-partner.example.com/");
            }));
        }

        _services.AddHmacClient("orders", options =>
        {
            Configure(options, "orders-client", "orders-secret");
            options.BaseAddress = new Uri("https://orders.example.com/");
        });

        if (!defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options =>
            {
                Configure(options, "defaults-client", "defaults-secret");
                options.BaseAddress = new Uri("https://defaults-partner.example.com/");
            }));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpClient orders = provider.GetRequiredService<IHttpClientFactory>().CreateClient("orders");

        Assert.Equal(new Uri("https://orders.example.com/"), orders.BaseAddress);
    }

    /// <summary>
    /// The factory's unnamed client (<c>CreateClient()</c>) is named <see cref="Options.DefaultName"/>. Its own
    /// registration must win for it, and must not leak into the other clients (the defaults registration uses the
    /// reserved options name <see cref="HmacHttpClientBuilderExtensions.DefaultsOptionsName"/>).
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaultsAndUnnamedClientRegistration_AnyOrder_EachKeepsItsOwnCredentials(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddHttpClient(Options.DefaultName).AddHmacSigning(options => Configure(options, "unnamed-client", "unnamed-secret"));

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        CapturedRequest unnamed = await SendAsync(provider, Options.DefaultName);
        CapturedRequest other = await SendAsync(provider, "other");

        Assert.Equal("unnamed-client", unnamed.ClientId);
        Assert.Equal(ReferenceSigner.Sign("unnamed-secret", unnamed), unnamed.Signature);
        Assert.Equal("defaults-client", other.ClientId);
        Assert.Equal(ReferenceSigner.Sign("defaults-secret", other), other.Signature);
    }

    private static void Configure(HmacClientOptions options, string clientId, string secret)
    {
        options.ClientId = clientId;
        options.Secret = secret;
    }

    private static void AddSigning(IHttpClientBuilder builder, string kind, string clientId, string secret)
    {
        if (kind == "delegate")
        {
            builder.AddHmacSigning(options => Configure(options, clientId, secret));
            return;
        }

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ClientId"] = clientId, ["Secret"] = secret })
            .Build();
        builder.AddHmacSigning(configuration);
    }

    private static void AssertSingleSigner(IServiceProvider provider, string name)
    {
        IReadOnlyList<HttpMessageHandler> chain = HandlerChain.Walk(provider, name);
        Assert.Single(chain.OfType<HmacSigningStateHandler>());
        Assert.Single(chain.OfType<HmacSigningHandler>());
        int state = chain.ToList().FindIndex(h => h is HmacSigningStateHandler);
        int signer = chain.ToList().FindIndex(h => h is HmacSigningHandler);
        Assert.True(state < signer, "The signing state handler must run before the signer.");
    }

    private void RegisterSigningDefaults() =>
        _services.ConfigureHttpClientDefaults(builder => builder
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => Configure(options, "defaults-client", "defaults-secret")));

    private async Task<CapturedRequest> SendAsync(IServiceProvider provider, string name)
    {
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(name);
        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/" + name), TestContext.Current.CancellationToken);
        return _transport.LastRequest;
    }
}
