using System.Collections.Concurrent;
using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

public sealed class HmacHttpClientBuilderExtensionsTests
{
    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly ServiceCollection _services = new();

    public HmacHttpClientBuilderExtensionsTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    [Fact]
    public async Task AddHmacSigning_NamedClient_SignsRequests()
    {
        var transport = new CapturingHandler();
        _services.AddHttpClient("partner-x")
            .ConfigurePrimaryHttpMessageHandler(() => transport)
            .AddHmacSigning(options =>
            {
                options.ClientId = "partner-x";
                options.Secret = "partner-x-secret";
            });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner-x");
        using var content = new StringContent("{\"ping\":true}");

        using HttpResponseMessage response = await client.PostAsync(new Uri("https://api.example.com/api/ping?v=2"), content, TestContext.Current.CancellationToken);

        CapturedRequest sent = transport.SingleRequest;
        Assert.Equal("partner-x", sent.ClientId);
        Assert.Equal("1790000000", sent.Timestamp);
        Assert.Equal(ReferenceSigner.Sign("partner-x-secret", "POST", "/api/ping?v=2", "1790000000", "{\"ping\":true}"u8), sent.Signature);
    }

    [Fact]
    public async Task AddHmacSigning_OnlyConfiguredClient_IsSigned()
    {
        var signedTransport = new CapturingHandler();
        var plainTransport = new CapturingHandler();
        _services.AddHttpClient("signed").ConfigurePrimaryHttpMessageHandler(() => signedTransport).AddHmacSigning(ConfigureValid);
        _services.AddHttpClient("plain").ConfigurePrimaryHttpMessageHandler(() => plainTransport);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (HttpClient signed = factory.CreateClient("signed"))
        using (HttpClient plain = factory.CreateClient("plain"))
        using (await signed.GetAsync(new Uri("https://api.example.com/a"), cancellationToken))
        using (await plain.GetAsync(new Uri("https://api.example.com/b"), cancellationToken))
        {
        }

        Assert.True(signedTransport.SingleRequest.HasHeader("X-Signature"));
        CapturedRequest plainRequest = plainTransport.SingleRequest;
        Assert.False(plainRequest.HasHeader("X-Signature"));
        Assert.False(plainRequest.HasHeader("X-Timestamp"));
        Assert.False(plainRequest.HasHeader("X-Client-Id"));
    }

    [Fact]
    public async Task AddHmacSigning_TwoNamedClients_UseIsolatedCredentials()
    {
        var firstTransport = new CapturingHandler();
        var secondTransport = new CapturingHandler();
        IHttpClientBuilder first = _services.AddHttpClient("first").ConfigurePrimaryHttpMessageHandler(() => firstTransport).AddHmacSigning(options =>
        {
            options.ClientId = "first-client";
            options.Secret = "first-secret";
        });
        IHttpClientBuilder second = _services.AddHttpClient("second").ConfigurePrimaryHttpMessageHandler(() => secondTransport).AddHmacSigning(options =>
        {
            options.ClientId = "second-client";
            options.Secret = "second-secret";
        });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (HttpClient firstClient = factory.CreateClient("first"))
        using (HttpClient secondClient = factory.CreateClient("second"))
        using (await firstClient.GetAsync(new Uri("https://api.example.com/x"), cancellationToken))
        using (await secondClient.GetAsync(new Uri("https://api.example.com/x"), cancellationToken))
        {
        }

        IOptionsMonitor<HmacClientOptions> monitor = provider.GetRequiredService<IOptionsMonitor<HmacClientOptions>>();
        Assert.Equal("first-client", monitor.Get(first.Name).ClientId);
        Assert.Equal("second-client", monitor.Get(second.Name).ClientId);

        // Nothing leaks into the unnamed (default) options instance, which therefore stays unconfigured and invalid.
        Assert.Throws<OptionsValidationException>(() => monitor.Get(Options.DefaultName));

        CapturedRequest firstSent = firstTransport.SingleRequest;
        CapturedRequest secondSent = secondTransport.SingleRequest;
        Assert.Equal("first-client", firstSent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("first-secret", firstSent), firstSent.Signature);
        Assert.Equal("second-client", secondSent.ClientId);
        Assert.Equal(ReferenceSigner.Sign("second-secret", secondSent), secondSent.Signature);
    }

    [Fact]
    public void AddHmacSigning_CalledForSeveralClients_RegistersValidatorOnce()
    {
        _services.AddHttpClient("a").AddHmacSigning(ConfigureValid);
        _services.AddHttpClient("b").AddHmacSigning(ConfigureValid);
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        Assert.Single(provider.GetServices<IValidateOptions<HmacClientOptions>>());
        Assert.Single(provider.GetServices<IHmacSignatureService>());
        Assert.Single(provider.GetServices<TimeProvider>());
    }

    [Fact]
    public void AddHmacSigning_ReturnsSameBuilder()
    {
        IHttpClientBuilder builder = _services.AddHttpClient("partner");

        Assert.Same(builder, builder.AddHmacSigning(ConfigureValid));
    }

    [Fact]
    public void AddHmacSigning_NullArguments_ThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("builder", () => HmacHttpClientBuilderExtensions.AddHmacSigning(null!, ConfigureValid));
        Assert.Throws<ArgumentNullException>("configureOptions", () => _services.AddHttpClient("partner").AddHmacSigning((Action<HmacClientOptions>)null!));
        Assert.Throws<ArgumentNullException>("builder", () => HmacHttpClientBuilderExtensions.AddHmacSigning(null!, new ConfigurationBuilder().Build()));
        Assert.Throws<ArgumentNullException>("configuration", () => _services.AddHttpClient("partner").AddHmacSigning((IConfiguration)null!));
    }

    /// <summary>
    /// The signing handler is always the innermost delegating handler, so a handler added after
    /// <c>AddHmacSigning</c> still runs before signing and sees the unsigned request.
    /// </summary>
    [Fact]
    public async Task AddHmacSigning_HandlerAddedAfterSigning_RunsBeforeSigningAndSeesUnsignedRequest()
    {
        var observations = new ConcurrentQueue<bool>();
        var transport = new CapturingHandler();
        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => transport)
            .AddHmacSigning(ConfigureValid)
            .AddHttpMessageHandler(() => new HeaderProbeHandler(observations));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/"), TestContext.Current.CancellationToken);

        Assert.False(Assert.Single(observations));
        CapturedRequest sent = transport.SingleRequest;
        Assert.Equal(ReferenceSigner.Sign("secret", sent), sent.Signature);
    }

    [Fact]
    public async Task AddHmacSigning_HandlerAddedBeforeSigning_SeesUnsignedRequest()
    {
        var observations = new ConcurrentQueue<bool>();
        var transport = new CapturingHandler();
        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => transport)
            .AddHttpMessageHandler(() => new HeaderProbeHandler(observations))
            .AddHmacSigning(ConfigureValid);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/"), TestContext.Current.CancellationToken);

        Assert.False(Assert.Single(observations));
        Assert.True(transport.SingleRequest.HasHeader("X-Signature"));
    }

    [Fact]
    public async Task AddHmacSigning_RetryHandlerAddedBeforeSigning_ReSignsEachAttemptWithFreshTimestamp()
    {
        var transport = new CapturingHandler();
        _services.AddHttpClient<OrdersApiClient>()
            .ConfigurePrimaryHttpMessageHandler(() => transport)
            .AddHttpMessageHandler(() => new RetryOnceHandler(() => _time.Advance(TimeSpan.FromSeconds(5))))
            .AddHmacSigning(ConfigureValid);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StreamContent(new NonSeekableReadStream("{\"order\":42}"u8.ToArray(), maxChunkSize: 5));

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        IReadOnlyList<CapturedRequest> attempts = transport.Requests;
        Assert.Equal(2, attempts.Count);
        Assert.Equal("1790000000", attempts[0].Timestamp);
        Assert.Equal("1790000005", attempts[1].Timestamp);
        Assert.All(attempts, attempt =>
        {
            Assert.Equal("{\"order\":42}"u8.ToArray(), attempt.Body);
            Assert.Equal(ReferenceSigner.Sign("secret", attempt), attempt.Signature);
        });
    }

    private static void ConfigureValid(HmacClientOptions options)
    {
        options.ClientId = "partner-a";
        options.Secret = "secret";
    }
}
