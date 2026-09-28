using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// <see cref="HmacClientOptions.BaseAddress"/> is applied to the <see cref="HttpClient"/> by the registration only when
/// no base address was set explicitly: a <c>ConfigureHttpClient</c> that sets one always wins, whether it is registered
/// before or after the signing registration. A relative value fails validation.
/// </summary>
public sealed class HmacClientBaseAddressTests : IDisposable
{
    private const string BaseAddressFailure = "BaseAddress must be an absolute http or https URI, for example https://api.example.com/.";

    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly CapturingHandler _transport = new();
    private readonly ServiceCollection _services = new();

    public HmacClientBaseAddressTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    public void Dispose() => _transport.Dispose();

    [Fact]
    public async Task AddHmacClient_DelegateBaseAddress_IsAppliedAndRelativeRequestsAreSignedAgainstIt()
    {
        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, new Uri("https://orders.example.com/v1/")))
            .ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders?id=5", UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Equal(new Uri("https://orders.example.com/v1/"), client.BaseAddress);
        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal(new Uri("https://orders.example.com/v1/orders?id=5"), sent.RequestUri);
        Assert.Equal(ReferenceSigner.Sign("secret", "GET", "/v1/orders?id=5", sent.Timestamp, []), sent.Signature);
    }

    [Fact]
    public async Task AddHmacClient_ConfigurationBaseAddress_IsApplied()
    {
        IConfigurationRoot configuration = CreateConfiguration("https://config.example.com/api/");
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Equal(new Uri("https://config.example.com/api/"), client.BaseAddress);
        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("/api/orders", sent.PathAndQuery);
        Assert.Equal(ReferenceSigner.Sign("config-secret", sent), sent.Signature);
    }

    [Fact]
    public void AddHmacClient_NamedClientBaseAddress_IsAppliedToEveryCreatedClient()
    {
        _services.AddHmacClient("partner", options => Configure(options, new Uri("https://partner.example.com/")));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();

        using HttpClient first = factory.CreateClient("partner");
        using HttpClient second = factory.CreateClient("partner");
        using HttpClient other = factory.CreateClient("other");

        Assert.Equal(new Uri("https://partner.example.com/"), first.BaseAddress);
        Assert.Equal(new Uri("https://partner.example.com/"), second.BaseAddress);
        Assert.Null(other.BaseAddress);
    }

    [Fact]
    public void AddHmacClient_ConfigureHttpClientRegisteredAfterwards_Wins()
    {
        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, new Uri("https://options.example.com/")))
            .ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        Assert.Equal(new Uri("https://user.example.com/"), provider.GetRequiredService<OrdersApiClient>().HttpClient.BaseAddress);
    }

    [Fact]
    public void AddHmacClient_ConfigureHttpClientRegisteredAfterwardsWithoutBaseAddress_KeepsOptionsBaseAddress()
    {
        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, new Uri("https://options.example.com/")))
            .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(7));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        Assert.Equal(new Uri("https://options.example.com/"), client.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(7), client.Timeout);
    }

    [Fact]
    public void AddHmacSigning_ConfigureHttpClientRegisteredBeforeAndOptionsWithoutBaseAddress_KeepsTheUserBaseAddress()
    {
        _services.AddHttpClient<OrdersApiClient>()
            .ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"))
            .AddHmacSigning(options => Configure(options, baseAddress: null));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        Assert.Equal(new Uri("https://user.example.com/"), provider.GetRequiredService<OrdersApiClient>().HttpClient.BaseAddress);
    }

    /// <summary>
    /// Round 4: the options' base address is only a fallback, so an explicit <c>ConfigureHttpClient</c> wins even when it
    /// is registered before <c>AddHmacSigning</c> (previously the last registration won).
    /// </summary>
    [Fact]
    public void AddHmacSigning_ConfigureHttpClientRegisteredBeforeAndOptionsWithBaseAddress_UserBaseAddressWins()
    {
        _services.AddHttpClient<OrdersApiClient>()
            .ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"))
            .AddHmacSigning(options => Configure(options, new Uri("https://options.example.com/")));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        Assert.Equal(new Uri("https://user.example.com/"), provider.GetRequiredService<OrdersApiClient>().HttpClient.BaseAddress);
    }

    [Fact]
    public void AddHmacSigning_ConfigureHttpClientRegisteredBeforeWithoutBaseAddress_KeepsOptionsBaseAddress()
    {
        _services.AddHttpClient<OrdersApiClient>()
            .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(7))
            .AddHmacSigning(options => Configure(options, new Uri("https://options.example.com/")));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        Assert.Equal(new Uri("https://options.example.com/"), client.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(7), client.Timeout);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task AddHmacSigning_ExplicitBaseAddress_AnyOrderAndOverload_UserBaseAddressWinsAndRequestsAreSignedAgainstIt(bool configureHttpClientFirst, bool withServiceProvider)
    {
        IHttpClientBuilder builder = _services.AddHttpClient("partner").ConfigurePrimaryHttpMessageHandler(() => _transport);
        if (configureHttpClientFirst)
        {
            ConfigureUserBaseAddress(builder, withServiceProvider);
        }

        builder.AddHmacSigning(options => Configure(options, new Uri("https://options.example.com/v1/")));

        if (!configureHttpClientFirst)
        {
            ConfigureUserBaseAddress(builder, withServiceProvider);
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders?id=5", UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Equal(new Uri("https://user.example.com/v2/"), client.BaseAddress);
        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal(new Uri("https://user.example.com/v2/orders?id=5"), sent.RequestUri);
        Assert.Equal(ReferenceSigner.Sign("secret", "GET", "/v2/orders?id=5", sent.Timestamp, []), sent.Signature);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AddHmacClient_ConfigureHttpClientOnASeparateBuilderForTheSameTypedClient_AnyOrder_UserBaseAddressWins(bool configureHttpClientFirst)
    {
        if (configureHttpClientFirst)
        {
            _services.AddHttpClient<OrdersApiClient>().ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"));
        }

        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, new Uri("https://options.example.com/")));

        if (!configureHttpClientFirst)
        {
            _services.AddHttpClient<OrdersApiClient>().ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        Assert.Equal(new Uri("https://user.example.com/"), provider.GetRequiredService<OrdersApiClient>().HttpClient.BaseAddress);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ConfigureHttpClientDefaults_ExplicitBaseAddressAndSigningWithBaseAddress_AnyOrder_UserBaseAddressWins(bool configureHttpClientFirst)
    {
        _services.ConfigureHttpClientDefaults(builder =>
        {
            if (configureHttpClientFirst)
            {
                builder.ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"));
            }

            builder.AddHmacSigning(options => Configure(options, new Uri("https://options.example.com/")));

            if (!configureHttpClientFirst)
            {
                builder.ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"));
            }
        });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("any");

        Assert.Equal(new Uri("https://user.example.com/"), client.BaseAddress);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaultsSigningWithBaseAddress_ClientWithOnlyAnExplicitBaseAddress_AnyOrder_UserBaseAddressWinsAndTheDefaultsSign(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            RegisterSigningDefaultsWithBaseAddress();
        }

        _services.AddHttpClient("partner").ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"));

        if (!defaultsRegisteredFirst)
        {
            RegisterSigningDefaultsWithBaseAddress();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken);

        Assert.Equal(new Uri("https://user.example.com/"), client.BaseAddress);
        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal(new Uri("https://user.example.com/orders"), sent.RequestUri);
        Assert.Equal("defaults-client", sent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("defaults-secret", sent), sent.Signature);
    }

    [Fact]
    public void AddHmacClient_ExplicitBaseAddressAndOptionsBaseAddressReloaded_NewClientsKeepTheUserBaseAddress()
    {
        IConfigurationRoot configuration = CreateConfiguration("https://config.example.com/");
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi"))
            .ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient before = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        configuration["OrdersApi:BaseAddress"] = "https://reloaded.example.com/";
        configuration.Reload();
        HttpClient after = provider.GetRequiredService<OrdersApiClient>().HttpClient;

        Assert.Equal(new Uri("https://user.example.com/"), before.BaseAddress);
        Assert.Equal(new Uri("https://user.example.com/"), after.BaseAddress);
    }

    [Fact]
    public void AddHmacClient_WithoutBaseAddress_LeavesHttpClientBaseAddressUnset()
    {
        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, baseAddress: null));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        Assert.Null(provider.GetRequiredService<OrdersApiClient>().HttpClient.BaseAddress);
    }

    [Fact]
    public void AddHmacClient_RelativeBaseAddressFromDelegate_FailsStartupValidation()
    {
        _services.AddHmacClient<OrdersApiClient>(options => Configure(options, new Uri("api/v1/", UriKind.Relative)));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal(nameof(OrdersApiClient), exception.OptionsName);
        Assert.Equal(BaseAddressFailure, Assert.Single(exception.Failures));
    }

    [Fact]
    public void AddHmacClient_RelativeBaseAddressFromConfiguration_FailsStartupValidation()
    {
        IConfigurationRoot configuration = CreateConfiguration("api/v1/");
        _services.AddHmacClient("partner", configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal("partner", exception.OptionsName);
        Assert.Equal(BaseAddressFailure, Assert.Single(exception.Failures));
    }

    [Theory]
    [InlineData("localhost:5080")]
    [InlineData("ftp://x/")]
    [InlineData("file:///api/")]
    public void AddHmacClient_NonHttpBaseAddressFromConfiguration_FailsStartupValidation(string baseAddress)
    {
        IConfigurationRoot configuration = CreateConfiguration(baseAddress);
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal(nameof(OrdersApiClient), exception.OptionsName);
        Assert.Equal(BaseAddressFailure, Assert.Single(exception.Failures));
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<OrdersApiClient>());
        Assert.Equal(0, _transport.InvocationCount);
    }

    [Theory]
    [InlineData("localhost:5080")]
    [InlineData("ftp://x/")]
    [InlineData("file:///api/")]
    public void AddHmacClient_NonHttpBaseAddressFromDelegate_FailsStartupValidation(string baseAddress)
    {
        _services.AddHmacClient("partner", options => Configure(options, new Uri(baseAddress, UriKind.RelativeOrAbsolute)));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Equal("partner", exception.OptionsName);
        Assert.Equal(BaseAddressFailure, Assert.Single(exception.Failures));
    }

    [Theory]
    [InlineData("http://orders.example.com/")]
    [InlineData("https://orders.example.com/")]
    public void AddHmacClient_HttpOrHttpsBaseAddressFromConfiguration_PassesStartupValidation(string baseAddress)
    {
        IConfigurationRoot configuration = CreateConfiguration(baseAddress);
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        provider.GetRequiredService<IStartupValidator>().Validate();

        Assert.Equal(new Uri(baseAddress), provider.GetRequiredService<OrdersApiClient>().HttpClient.BaseAddress);
    }

    [Fact]
    public void AddHmacClient_BaseAddressReloadedToNonHttpValue_NewClientsFailInsteadOfUsingIt()
    {
        IConfigurationRoot configuration = CreateConfiguration("https://valid.example.com/");
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<IStartupValidator>().Validate();

        configuration["OrdersApi:BaseAddress"] = "localhost:5080";

        // The options monitor re-validates on reload (standard Options behaviour), and every new client fails as well.
        AggregateException reloadFailure = Assert.Throws<AggregateException>(configuration.Reload);
        Assert.IsType<OptionsValidationException>(Assert.Single(reloadFailure.InnerExceptions));
        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<OrdersApiClient>());
        Assert.Equal(BaseAddressFailure, Assert.Single(exception.Failures));
    }

    [Theory]
    [InlineData(256, true)]
    [InlineData(257, false)]
    public void AddHmacClient_ClientIdLengthFromConfiguration_IsValidatedAtStartup(int length, bool valid)
    {
        IConfigurationRoot configuration = CreateConfiguration("https://orders.example.com/");
        configuration["OrdersApi:ClientId"] = HmacClientOptionsValidatorTests.CreateClientId(length);
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IStartupValidator validator = provider.GetRequiredService<IStartupValidator>();

        if (valid)
        {
            validator.Validate();
        }
        else
        {
            OptionsValidationException exception = Assert.Throws<OptionsValidationException>(validator.Validate);
            Assert.Equal(
                "ClientId must consist of at most 256 printable ASCII characters without leading or trailing whitespace.",
                Assert.Single(exception.Failures));
        }
    }

    [Fact]
    public void AddHmacClient_UnparsableBaseAddressInConfiguration_ThrowsInvalidOperationExceptionNamingTheKey()
    {
        IConfigurationRoot configuration = CreateConfiguration("http://exa mple.com/");
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Contains("BaseAddress", exception.Message, StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<OrdersApiClient>());
    }

    [Fact]
    public void AddHmacClient_EmptyBaseAddressInConfiguration_IsIgnored()
    {
        IConfigurationRoot configuration = CreateConfiguration(string.Empty);
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        provider.GetRequiredService<IStartupValidator>().Validate();

        Assert.Null(provider.GetRequiredService<OrdersApiClient>().HttpClient.BaseAddress);
    }

    [Fact]
    public async Task AddHmacClient_BaseAddressReloaded_NewClientsUseTheNewAddressAndExistingClientsKeepTheirs()
    {
        IConfigurationRoot configuration = CreateConfiguration("https://old.example.com/");
        _services.AddHmacClient<OrdersApiClient>(configuration.GetSection("OrdersApi")).ConfigurePrimaryHttpMessageHandler(() => _transport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient existing = provider.GetRequiredService<OrdersApiClient>().HttpClient;
        using (await existing.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken))
        {
        }

        configuration["OrdersApi:BaseAddress"] = "https://new.example.com/v2/";
        configuration.Reload();
        HttpClient created = provider.GetRequiredService<OrdersApiClient>().HttpClient;
        using (await created.GetAsync(new Uri("orders", UriKind.Relative), TestContext.Current.CancellationToken))
        {
        }

        Assert.Equal(new Uri("https://old.example.com/"), existing.BaseAddress);
        Assert.Equal(new Uri("https://new.example.com/v2/"), created.BaseAddress);
        Assert.Equal(["/orders", "/v2/orders"], _transport.Requests.Select(r => r.PathAndQuery));
        Assert.All(_transport.Requests, sent => Assert.Equal(ReferenceSigner.Sign("config-secret", sent), sent.Signature));
    }

    [Fact]
    public async Task HmacSigningHandler_ConstructedManuallyWithBaseAddress_IgnoresIt()
    {
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret", BaseAddress = new Uri("https://ignored.example.com/") };
        using var handler = new HmacSigningHandler(options, HmacSha256SignatureService.Instance, _time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = _transport,
        };
        using var client = new HttpClient(handler, disposeHandler: false);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAsync(new Uri("api/orders", UriKind.Relative), cancellationToken));
        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), cancellationToken);

        Assert.Null(client.BaseAddress);
        Assert.Equal("https://api.example.com/api/orders", _transport.SingleRequest.RequestUri.AbsoluteUri);
    }

    [Fact]
    public void HmacSigningHandler_ConstructedManuallyWithRelativeBaseAddress_ThrowsOptionsValidationException()
    {
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret", BaseAddress = new Uri("/api/", UriKind.Relative) };

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(() => new HmacSigningHandler(options));

        Assert.Equal(BaseAddressFailure, Assert.Single(exception.Failures));
    }

    private static void ConfigureUserBaseAddress(IHttpClientBuilder builder, bool withServiceProvider)
    {
        if (withServiceProvider)
        {
            builder.ConfigureHttpClient((_, client) => client.BaseAddress = new Uri("https://user.example.com/v2/"));
        }
        else
        {
            builder.ConfigureHttpClient(client => client.BaseAddress = new Uri("https://user.example.com/v2/"));
        }
    }

    private static void Configure(HmacClientOptions options, Uri? baseAddress)
    {
        options.ClientId = "partner-a";
        options.Secret = "secret";
        options.BaseAddress = baseAddress;
    }

    private void RegisterSigningDefaultsWithBaseAddress() =>
        _services.ConfigureHttpClientDefaults(builder => builder
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHmacSigning(options =>
            {
                options.ClientId = "defaults-client";
                options.Secret = "defaults-secret";
                options.BaseAddress = new Uri("https://defaults.example.com/");
            }));

    private static IConfigurationRoot CreateConfiguration(string baseAddress) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["OrdersApi:ClientId"] = "config-client",
            ["OrdersApi:Secret"] = "config-secret",
            ["OrdersApi:BaseAddress"] = baseAddress,
        })
        .Build();
}
