using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// Round 4: <c>ConfigureHttpClientDefaults(b =&gt; b.AddHmacSigning(...))</c> keeps its options under the reserved name
/// <see cref="HmacHttpClientBuilderExtensions.DefaultsOptionsName"/>, so it never shares options, validation or reloads
/// with any client — including the factory's unnamed client (<see cref="Options.DefaultName"/>). Its precedence is
/// decided when the factory options of a client are built: for a client with a signing registration of its own it
/// contributes nothing at all (no handler, no base address, no factory action).
/// </summary>
public sealed class HmacSigningDefaultsIsolationTests : IDisposable
{
    private const string DefaultsBaseAddress = "https://defaults.example.com/";

    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly CapturingHandler _transport = new();
    private readonly ServiceCollection _services = new();

    public HmacSigningDefaultsIsolationTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    public void Dispose() => _transport.Dispose();

    [Fact]
    public void DefaultsOptionsName_IsTheDocumentedReservedName()
    {
        Assert.Equal("Appouse.Safetalk.HttpClientDefaults", HmacHttpClientBuilderExtensions.DefaultsOptionsName);
        Assert.NotEqual(HmacHttpClientBuilderExtensions.DefaultsOptionsName, Options.DefaultName);
    }

    [Fact]
    public void ConfigureHttpClientDefaults_Options_AreRegisteredUnderTheReservedNameAndNotUnderTheDefaultName()
    {
        RegisterSigningDefaults(baseAddress: new Uri(DefaultsBaseAddress));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IOptionsMonitor<HmacClientOptions> monitor = provider.GetRequiredService<IOptionsMonitor<HmacClientOptions>>();

        HmacClientOptions defaults = monitor.Get(HmacHttpClientBuilderExtensions.DefaultsOptionsName);

        Assert.Equal("defaults-client", defaults.ClientId);
        Assert.Equal("defaults-secret", defaults.Secret);
        Assert.Equal(new Uri(DefaultsBaseAddress), defaults.BaseAddress);

        // Nothing is configured under the unnamed options, which therefore stay invalid.
        OptionsValidationException unnamed = Assert.Throws<OptionsValidationException>(() => monitor.Get(Options.DefaultName));
        Assert.Equal(Options.DefaultName, unnamed.OptionsName);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UnnamedClientRegistrationAndDefaults_AnyOrder_EachUsesItsOwnCredentialsAndBaseAddress(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults(baseAddress: new Uri(DefaultsBaseAddress));
        }

        RegisterUnnamedClient("unnamed-client", "unnamed-secret", new Uri("https://unnamed.example.com/v1/"));

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults(baseAddress: new Uri(DefaultsBaseAddress));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();

        using HttpClient unnamedClient = factory.CreateClient();
        using HttpClient otherClient = factory.CreateClient("other");
        CapturedRequest unnamed = await SendRelativeAsync(unnamedClient);
        CapturedRequest other = await SendRelativeAsync(otherClient);

        Assert.Equal(new Uri("https://unnamed.example.com/v1/"), unnamedClient.BaseAddress);
        Assert.Equal(new Uri("https://unnamed.example.com/v1/orders"), unnamed.RequestUri);
        Assert.Equal("unnamed-client", unnamed.ClientId);
        Assert.Equal(ReferenceSigner.Sign("unnamed-secret", "GET", "/v1/orders", unnamed.Timestamp, []), unnamed.Signature);

        Assert.Equal(new Uri(DefaultsBaseAddress), otherClient.BaseAddress);
        Assert.Equal(new Uri("https://defaults.example.com/orders"), other.RequestUri);
        Assert.Equal("defaults-client", other.ClientId);
        Assert.Equal(ReferenceSigner.Sign("defaults-secret", "GET", "/orders", other.Timestamp, []), other.Signature);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UnnamedClientRegistrationWithoutBaseAddressAndDefaultsWithBaseAddress_AnyOrder_UnnamedClientDoesNotInheritIt(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults(baseAddress: new Uri(DefaultsBaseAddress));
        }

        RegisterUnnamedClient("unnamed-client", "unnamed-secret", baseAddress: null);

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults(baseAddress: new Uri(DefaultsBaseAddress));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();

        using HttpClient unnamedClient = factory.CreateClient();
        using HttpClient otherClient = factory.CreateClient("other");
        using HttpResponseMessage response = await unnamedClient.GetAsync(new Uri("https://own.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Null(unnamedClient.BaseAddress);
        Assert.Equal(new Uri(DefaultsBaseAddress), otherClient.BaseAddress);
        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("unnamed-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("unnamed-secret", sent), sent.Signature);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TypedClientRegistrationWithoutBaseAddressAndDefaultsWithBaseAddress_AnyOrder_TypedClientDoesNotInheritIt(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults(baseAddress: new Uri(DefaultsBaseAddress));
        }

        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, "typed-client", "typed-secret"));
        _services.AddHttpClient<BillingApiClient>();

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults(baseAddress: new Uri(DefaultsBaseAddress));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        Assert.Null(provider.GetRequiredService<OrdersApiClient>().HttpClient.BaseAddress);
        Assert.Equal(new Uri(DefaultsBaseAddress), provider.GetRequiredService<BillingApiClient>().HttpClient.BaseAddress);
    }

    /// <summary>
    /// Before round 4 both registrations shared the options named <see cref="Options.DefaultName"/>, so an incomplete
    /// registration of the unnamed client silently borrowed the defaults' secret. Each is now validated on its own.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UnnamedClientRegistrationWithoutSecretAndValidDefaults_AnyOrder_FailsValidationInsteadOfBorrowingTheDefaultsSecret(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddHttpClient(Options.DefaultName)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => options.ClientId = "unnamed-client");

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal(Options.DefaultName, exception.OptionsName);
        Assert.Equal("Secret must be provided.", Assert.Single(exception.Failures));
        await Assert.ThrowsAsync<OptionsValidationException>(() => SendAbsoluteAsync(factory, Options.DefaultName));
        Assert.Equal(0, _transport.InvocationCount);

        // The other clients keep using the (valid) defaults.
        CapturedRequest other = await SendAbsoluteAsync(factory, "other");
        Assert.Equal("defaults-client", other.ClientId);
        Assert.Equal(ReferenceSigner.Sign("defaults-secret", other), other.Signature);
        Assert.Equal(1, _transport.InvocationCount);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InvalidDefaultsAndValidUnnamedClientRegistration_AnyOrder_OnlyTheDefaultsFailAndTheUnnamedClientStillSigns(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder
                .ConfigurePrimaryHttpMessageHandler(() => _transport)
                .AddHmacSigning(options => options.ClientId = "defaults-client"));
        }

        RegisterUnnamedClient("unnamed-client", "unnamed-secret", baseAddress: null);

        if (!defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder
                .ConfigurePrimaryHttpMessageHandler(() => _transport)
                .AddHmacSigning(options => options.ClientId = "defaults-client"));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);
        using HttpClient unnamedClient = factory.CreateClient();
        using HttpResponseMessage response = await unnamedClient.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(HmacHttpClientBuilderExtensions.DefaultsOptionsName, exception.OptionsName);
        Assert.Equal("Secret must be provided.", Assert.Single(exception.Failures));
        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("unnamed-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("unnamed-secret", sent), sent.Signature);

        // A client without a registration of its own is signed by the (invalid) defaults, so it fails.
        await Assert.ThrowsAsync<OptionsValidationException>(() => SendAbsoluteAsync(factory, "other"));
        Assert.Equal(1, _transport.InvocationCount);
    }

    [Fact]
    public void InvalidDefaultsAndInvalidUnnamedClientRegistration_StartupValidation_ReportsBothOptionsNames()
    {
        _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options => options.Secret = "defaults-secret"));
        _services.AddHttpClient(Options.DefaultName).AddHmacSigning(options => options.ClientId = "unnamed-client");
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        AggregateException exception = Assert.Throws<AggregateException>(provider.GetRequiredService<IStartupValidator>().Validate);

        OptionsValidationException[] failures = [.. exception.InnerExceptions.Cast<OptionsValidationException>().OrderBy(e => e.OptionsName, StringComparer.Ordinal)];
        Assert.Equal([Options.DefaultName, HmacHttpClientBuilderExtensions.DefaultsOptionsName], failures.Select(f => f.OptionsName));
        Assert.Equal("Secret must be provided.", Assert.Single(failures[0].Failures));
        Assert.Equal("ClientId must be provided.", Assert.Single(failures[1].Failures));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UnnamedClientAndDefaultsFromConfiguration_AnyOrder_EachSectionReloadsOnlyItsOwnClients(bool defaultsRegisteredFirst)
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Defaults:ClientId"] = "defaults-client",
                ["Defaults:Secret"] = "defaults-v1",
                ["Unnamed:ClientId"] = "unnamed-client",
                ["Unnamed:Secret"] = "unnamed-v1",
            })
            .Build();
        if (defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder
                .ConfigurePrimaryHttpMessageHandler(() => _transport)
                .AddHmacSigning(configuration.GetSection("Defaults")));
        }

        _services.AddHttpClient(Options.DefaultName).AddHmacSigning(configuration.GetSection("Unnamed"));

        if (!defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder
                .ConfigurePrimaryHttpMessageHandler(() => _transport)
                .AddHmacSigning(configuration.GetSection("Defaults")));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();
        using HttpClient unnamedClient = factory.CreateClient();
        using HttpClient otherClient = factory.CreateClient("other");

        CapturedRequest unnamedBefore = await SendAbsoluteAsync(unnamedClient);
        CapturedRequest otherBefore = await SendAbsoluteAsync(otherClient);
        configuration["Defaults:Secret"] = "defaults-v2";
        configuration.Reload();
        CapturedRequest unnamedAfterDefaultsRotation = await SendAbsoluteAsync(unnamedClient);
        CapturedRequest otherAfterDefaultsRotation = await SendAbsoluteAsync(otherClient);
        configuration["Unnamed:Secret"] = "unnamed-v2";
        configuration.Reload();
        CapturedRequest unnamedAfterOwnRotation = await SendAbsoluteAsync(unnamedClient);
        CapturedRequest otherAfterOwnRotation = await SendAbsoluteAsync(otherClient);

        Assert.Equal(ReferenceSigner.Sign("unnamed-v1", unnamedBefore), unnamedBefore.Signature);
        Assert.Equal(ReferenceSigner.Sign("defaults-v1", otherBefore), otherBefore.Signature);
        Assert.Equal(ReferenceSigner.Sign("unnamed-v1", unnamedAfterDefaultsRotation), unnamedAfterDefaultsRotation.Signature);
        Assert.Equal(ReferenceSigner.Sign("defaults-v2", otherAfterDefaultsRotation), otherAfterDefaultsRotation.Signature);
        Assert.Equal(ReferenceSigner.Sign("unnamed-v2", unnamedAfterOwnRotation), unnamedAfterOwnRotation.Signature);
        Assert.Equal(ReferenceSigner.Sign("defaults-v2", otherAfterOwnRotation), otherAfterOwnRotation.Signature);
        Assert.Equal("unnamed-client", unnamedAfterOwnRotation.ClientId);
        Assert.Equal("defaults-client", otherAfterOwnRotation.ClientId);
    }

    /// <summary>
    /// Every handler ever added to the pipeline is recorded: the defaults must not create a signer that the client's
    /// own registration then replaces (they must not create one at all).
    /// </summary>
    [Theory]
    [InlineData("named", true)]
    [InlineData("named", false)]
    [InlineData("typed", true)]
    [InlineData("typed", false)]
    [InlineData("unnamed", true)]
    [InlineData("unnamed", false)]
    public async Task ConfigureHttpClientDefaultsAndOwnRegistration_AnyOrder_DefaultsCreateNoHandlerForTheClient(string kind, bool defaultsRegisteredFirst)
    {
        var additions = new HandlerAdditionRecorder();
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        string name = RegisterOwnClient(kind);

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddSingleton<IHttpMessageHandlerBuilderFilter>(additions);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IReadOnlyList<DelegatingHandler> pipeline = HandlerChain.ContributedHandlers(provider, name, _transport);
        CapturedRequest sent = await SendAbsoluteAsync(provider.GetRequiredService<IHttpClientFactory>(), name);
        IReadOnlyList<DelegatingHandler> added = additions.AddedTo(name);

        Assert.Equal([typeof(HmacSigningStateHandler), typeof(HmacSigningHandler)], added.Select(h => h.GetType()));
        Assert.Equal(pipeline, added);
        Assert.All(added, AssertStartedAndNotDisposed);
        Assert.NotEqual("defaults-client", sent.ClientId);
    }

    [Fact]
    public void ConfigureHttpClientDefaults_ClientWithoutOwnRegistration_DefaultsCreateExactlyOneSigner()
    {
        var additions = new HandlerAdditionRecorder();
        RegisterSigningDefaults();
        _services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret"));
        _services.AddSingleton<IHttpMessageHandlerBuilderFilter>(additions);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IReadOnlyList<DelegatingHandler> pipeline = HandlerChain.ContributedHandlers(provider, "other", _transport);

        Assert.Equal([typeof(HmacSigningStateHandler), typeof(HmacSigningHandler)], additions.AddedTo("other").Select(h => h.GetType()));
        Assert.Equal(pipeline, additions.AddedTo("other"));
    }

    /// <summary>
    /// Structural check of "the defaults do nothing": the factory options of a client with its own registration have
    /// exactly the same actions whether or not a signing defaults registration exists.
    /// </summary>
    [Theory]
    [InlineData("named", true)]
    [InlineData("named", false)]
    [InlineData("typed", true)]
    [InlineData("typed", false)]
    [InlineData("unnamed", true)]
    [InlineData("unnamed", false)]
    public void ConfigureHttpClientDefaults_ClientWithOwnRegistration_AddsNoFactoryActions(string kind, bool defaultsRegisteredFirst)
    {
        (int handlerActions, int clientActions) withoutDefaults = CountFactoryActions(kind, defaults: null);
        (int handlerActions, int clientActions) withDefaults = CountFactoryActions(kind, defaultsRegisteredFirst);
        (int handlerActions, int clientActions) otherWithDefaults = CountFactoryActions("other", defaultsRegisteredFirst);

        Assert.Equal(withoutDefaults, withDefaults);

        // Control: a client without a registration of its own does get the defaults' actions.
        Assert.Equal((1, 1), otherWithDefaults);
    }

    /// <summary>
    /// <c>ConfigureHttpClientDefaults</c> hands its callback a wrapping service collection; the defaults registration must
    /// still find (or create) the one registration set that the clients' own registrations fill, whatever the order.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AddHmacSigning_DefaultsAndClientsInAnyOrder_ShareASingleRegistrationSet(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret"));
        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, "typed-client", "typed-secret"));
        _services.AddHttpClient(Options.DefaultName).AddHmacSigning(options => Configure(options, "unnamed-client", "unnamed-secret"));
        _services.AddHttpClient("plain");

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        // One immutable marker per own registration, resolved from the provider being used.
        string[] registered = [.. provider.GetServices<HmacSigningClientRegistration>().Select(registration => registration.ClientName)];
        Assert.Contains("orders", registered);
        Assert.Contains(nameof(OrdersApiClient), registered);
        Assert.Contains(Options.DefaultName, registered);
        Assert.DoesNotContain("plain", registered);
        Assert.DoesNotContain(HmacHttpClientBuilderExtensions.DefaultsOptionsName, registered);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ServiceProvider_ValidateOnBuildWithDefaultsAndOwnRegistrations_BuildsAndEveryClientSignsWithItsCredentials(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        RegisterOwnClient("named");
        RegisterOwnClient("typed");
        RegisterOwnClient("unnamed");

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        provider.GetRequiredService<IStartupValidator>().Validate();
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();

        (string Name, string ClientId, string Secret)[] expectations =
        [
            ("orders", "orders-client", "orders-secret"),
            (nameof(OrdersApiClient), "typed-client", "typed-secret"),
            (Options.DefaultName, "unnamed-client", "unnamed-secret"),
            ("other", "defaults-client", "defaults-secret"),
        ];
        foreach ((string name, string clientId, string secret) in expectations)
        {
            CapturedRequest sent = await SendAbsoluteAsync(factory, name);
            Assert.Equal(clientId, sent.ClientId);
            Assert.Equal(ReferenceSigner.Sign(secret, sent), sent.Signature);
        }
    }

    /// <summary>
    /// The set of clients that have their own registration must be the one of the service provider being used. When the
    /// same collection is built again after a client registration is added, the provider built earlier has no signing
    /// registration for that client, so the defaults must still sign it — it must not send the request unsigned.
    /// </summary>
    /// <remarks>
    /// Known defect (round 4): <c>HmacSigningRegistrations</c> is a mutable instance singleton shared by every provider
    /// built from the collection (and by copies of it), so a later <c>AddHmacSigning</c> makes the defaults skip that
    /// client in providers that do not contain the client's own registration: the request goes out unsigned.
    /// </remarks>
    [Fact]
    public async Task ConfigureHttpClientDefaults_ProviderBuiltBeforeAClientRegistrationWasAdded_StillSignsThatClientWithTheDefaults()
    {
        RegisterSigningDefaults();
        using ServiceProvider earlier = _services.BuildServiceProvider(validateScopes: true);
        _services.AddHmacClient("partner", options => Configure(options, "partner-client", "partner-secret"));
        using ServiceProvider later = _services.BuildServiceProvider(validateScopes: true);

        using HttpClient client = earlier.GetRequiredService<IHttpClientFactory>().CreateClient("partner");
        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.True(sent.HasHeader(CapturedRequest.SignatureHeader), "The earlier provider sent the request unsigned.");
        Assert.Equal("defaults-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("defaults-secret", sent), sent.Signature);
    }

    /// <summary>
    /// A signing handler added explicitly to one client's pipeline carries credentials chosen for that client; the
    /// signing defaults must not silently swap them for the defaults' credentials.
    /// </summary>
    /// <remarks>
    /// Known defect (pre-existing, not introduced by round 4): the "one signer per pipeline" clean-up removes and disposes
    /// every <see cref="HmacSigningHandler"/> in the pipeline, including one the application added itself, so the
    /// defaults' credentials (client id and signature) are sent to this client's partner instead.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaults_ClientWithAnExplicitlyAddedSigningHandler_AnyOrder_KeepsItsCredentials(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        _services.AddHttpClient("partner").AddHttpMessageHandler(serviceProvider => new HmacSigningHandler(
            new HmacClientOptions { ClientId = "explicit-client", Secret = "explicit-secret" },
            serviceProvider.GetRequiredService<IHmacSignatureService>(),
            serviceProvider.GetRequiredService<TimeProvider>(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<HmacSigningHandler>.Instance));

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://partner.example.com/api/orders"), TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("explicit-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("explicit-secret", sent), sent.Signature);
    }

    private static void Configure(HmacClientOptions options, string clientId, string secret, Uri? baseAddress = null)
    {
        options.ClientId = clientId;
        options.Secret = secret;
        options.BaseAddress = baseAddress;
    }

    /// <summary>
    /// Call only after a request went through <paramref name="handler"/>: setting <see cref="DelegatingHandler.InnerHandler"/>
    /// then throws <see cref="ObjectDisposedException"/> for a disposed handler and <see cref="InvalidOperationException"/>
    /// (operation already started) for a live one, and never changes the pipeline.
    /// </summary>
    private static void AssertStartedAndNotDisposed(DelegatingHandler handler)
    {
        using var probe = new CapturingHandler();
        HttpMessageHandler? inner = handler.InnerHandler;

        Assert.Throws<InvalidOperationException>(() => handler.InnerHandler = probe);
        Assert.Same(inner, handler.InnerHandler);
    }

    private static (int HandlerActions, int ClientActions) CountFactoryActions(string kind, bool? defaults)
    {
        var services = new ServiceCollection();
        if (defaults == true)
        {
            services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options => Configure(options, "defaults-client", "defaults-secret")));
        }

        string name = kind switch
        {
            "named" => services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret")).Name,
            "typed" => services.AddHmacClient<OrdersApiClient>(options => Configure(options, "typed-client", "typed-secret")).Name,
            "unnamed" => services.AddHttpClient(Options.DefaultName).AddHmacSigning(options => Configure(options, "unnamed-client", "unnamed-secret")).Name,
            _ => services.AddHttpClient(kind).Name,
        };

        if (defaults == false)
        {
            services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options => Configure(options, "defaults-client", "defaults-secret")));
        }

        using ServiceProvider provider = services.BuildServiceProvider(validateScopes: true);
        HttpClientFactoryOptions options = provider.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>().Get(name);
        return (options.HttpMessageHandlerBuilderActions.Count, options.HttpClientActions.Count);
    }

    private string RegisterOwnClient(string kind) => kind switch
    {
        "named" => _services.AddHmacClient("orders", options => Configure(options, "orders-client", "orders-secret"))
            .ConfigurePrimaryHttpMessageHandler(() => _transport).Name,
        "typed" => _services.AddHmacClient<OrdersApiClient>(options => Configure(options, "typed-client", "typed-secret"))
            .ConfigurePrimaryHttpMessageHandler(() => _transport).Name,
        "unnamed" => _services.AddHttpClient(Options.DefaultName)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => Configure(options, "unnamed-client", "unnamed-secret")).Name,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };

    private void RegisterUnnamedClient(string clientId, string secret, Uri? baseAddress) =>
        _services.AddHttpClient(Options.DefaultName)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => Configure(options, clientId, secret, baseAddress));

    private void RegisterSigningDefaults(Uri? baseAddress = null) =>
        _services.ConfigureHttpClientDefaults(builder => builder
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options => Configure(options, "defaults-client", "defaults-secret", baseAddress)));

    private async Task<CapturedRequest> SendRelativeAsync(HttpClient client)
    {
        using HttpResponseMessage response = await client.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken);
        return _transport.LastRequest;
    }

    private async Task<CapturedRequest> SendAbsoluteAsync(IHttpClientFactory factory, string name)
    {
        using HttpClient client = factory.CreateClient(name);
        return await SendAbsoluteAsync(client);
    }

    private async Task<CapturedRequest> SendAbsoluteAsync(HttpClient client)
    {
        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);
        return _transport.LastRequest;
    }
}
