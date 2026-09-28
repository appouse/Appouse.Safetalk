using System.Collections.Concurrent;
using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// The <c>IHttpClientFactory</c> integration always places the signing handler innermost (closest to the network),
/// whatever the order in which other handlers are registered. Retries are therefore re-signed and request rewrites are
/// covered by the signature; only a handler wrapping the primary handler runs after signing.
/// </summary>
public sealed class HmacSigningHandlerOrderingTests : IDisposable
{
    private const string Secret = "ordering-secret";

    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly CapturingHandler _transport = new();
    private readonly ServiceCollection _services = new();

    public HmacSigningHandlerOrderingTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    public void Dispose() => _transport.Dispose();

    [Fact]
    public async Task AddHmacClient_RetryHandlerAddedAfterRegistration_ReSignsEachAttemptWithDistinctTimestampsAndSignatures()
    {
        CountingRetryHandler? retry = null;
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => retry = new CountingRetryHandler(3));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StreamContent(new NonSeekableReadStream("{\"order\":42}"u8.ToArray(), maxChunkSize: 5));

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.NotNull(retry);
        Assert.Equal(3, retry.AttemptCount);
        IReadOnlyList<CapturedRequest> attempts = _transport.Requests;
        Assert.Equal(["1790000000", "1790000001", "1790000002"], attempts.Select(a => a.Timestamp));
        Assert.Equal(3, attempts.Select(a => a.Signature).Distinct(StringComparer.Ordinal).Count());
        Assert.All(attempts, attempt =>
        {
            Assert.Equal("{\"order\":42}"u8.ToArray(), attempt.Body);
            Assert.Equal(ReferenceSigner.Sign(Secret, attempt), attempt.Signature);
        });
    }

    [Fact]
    public void AddHmacClient_RetryHandlerAddedAfterRegistration_SynchronousSendReSignsEachAttempt()
    {
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new CountingRetryHandler(2));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders?id=1");

        using HttpResponseMessage response = provider.GetRequiredService<OrdersApiClient>().HttpClient.Send(request, TestContext.Current.CancellationToken);

        Assert.Equal(2, _transport.SynchronousInvocationCount);
        Assert.Equal(["1790000000", "1790000001"], _transport.Requests.Select(a => a.Timestamp));
        Assert.All(_transport.Requests, attempt => Assert.Equal(ReferenceSigner.Sign(Secret, attempt), attempt.Signature));
    }

    [Fact]
    public async Task AddHmacClient_RetryHandlerWithClockAdvancingBetweenAttempts_EachAttemptUsesTheCurrentTime()
    {
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new CountingRetryHandler(3, attempt =>
            {
                if (attempt > 1)
                {
                    _time.Advance(TimeSpan.FromSeconds(3));
                }
            }));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(["1790000000", "1790000003", "1790000006"], _transport.Requests.Select(a => a.Timestamp));
    }

    [Fact]
    public async Task AddHmacClient_MutatingHandlerAddedAfterRegistration_SignatureCoversTheMutatedTargetAndBody()
    {
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new RequestMutatingHandler("tenant=42", "{\"mutated\":true}"));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StringContent("{}");

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders?id=5"), content, TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("/api/orders?id=5&tenant=42", sent.PathAndQuery);
        Assert.Equal("{\"mutated\":true}"u8.ToArray(), sent.Body);
        Assert.Equal(ReferenceSigner.Sign(Secret, "POST", "/api/orders?id=5&tenant=42", sent.Timestamp, "{\"mutated\":true}"u8), sent.Signature);
    }

    [Fact]
    public async Task AddHmacSigning_MutatingHandlerAddedBeforeSigning_SignatureCoversTheMutation()
    {
        _services.AddHttpClient<OrdersApiClient>()
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new RequestMutatingHandler("tenant=7"))
            .AddHmacSigning(ConfigureValid);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("/api/orders?tenant=7", sent.PathAndQuery);
        Assert.Equal(ReferenceSigner.Sign(Secret, sent), sent.Signature);
    }

    [Fact]
    public async Task AddHmacClient_HandlerWrappingThePrimaryHandler_RunsAfterSigningSoItsTamperingBreaksTheSignature()
    {
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => new RequestMutatingHandler("evil=1", "{\"amount\":900}") { InnerHandler = _transport });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StringContent("{\"amount\":100}");

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/payments"), content, TestContext.Current.CancellationToken);

        CapturedRequest sent = _transport.SingleRequest;
        Assert.Equal("/api/payments?evil=1", sent.PathAndQuery);
        Assert.NotEqual(ReferenceSigner.Sign(Secret, sent), sent.Signature);
        Assert.Equal(ReferenceSigner.Sign(Secret, "POST", "/api/payments", sent.Timestamp, "{\"amount\":100}"u8), sent.Signature);
    }

    [Fact]
    public async Task AddHmacSigning_HandlersAddedBeforeAndAfter_AllRunBeforeSigning()
    {
        var before = new ConcurrentQueue<bool>();
        var after = new ConcurrentQueue<bool>();
        _services.AddHttpClient<OrdersApiClient>()
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new HeaderProbeHandler(before))
            .AddHmacSigning(ConfigureValid)
            .AddHttpMessageHandler(() => new HeaderProbeHandler(after));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/"), TestContext.Current.CancellationToken);

        Assert.False(Assert.Single(before));
        Assert.False(Assert.Single(after));
        Assert.True(_transport.SingleRequest.HasHeader(CapturedRequest.SignatureHeader));
    }

    [Fact]
    public async Task AddHmacClient_ConfigureAdditionalHttpMessageHandlersAfterRegistration_RunsBeforeSigning()
    {
        var observations = new ConcurrentQueue<bool>();
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .ConfigureAdditionalHttpMessageHandlers((handlers, _) => handlers.Add(new HeaderProbeHandler(observations)));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/"), TestContext.Current.CancellationToken);

        Assert.False(Assert.Single(observations));
        Assert.Equal(ReferenceSigner.Sign(Secret, _transport.SingleRequest), _transport.SingleRequest.Signature);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaults_RetryHandler_RunsOutsideSigningAndReSignsEachAttempt(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHttpMessageHandler(() => new CountingRetryHandler(2)));
        }

        _services.AddHmacClient<OrdersApiClient>(ConfigureValid).ConfigurePrimaryHttpMessageHandler(() => _transport);

        if (!defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHttpMessageHandler(() => new CountingRetryHandler(2)));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(["1790000000", "1790000001"], _transport.Requests.Select(a => a.Timestamp));
        Assert.NotEqual(_transport.Requests[0].Signature, _transport.Requests[1].Signature);
        Assert.All(_transport.Requests, attempt => Assert.Equal(ReferenceSigner.Sign(Secret, attempt), attempt.Signature));
    }

    [Fact]
    public async Task AddHmacClient_NamedClientWithRetryAddedAfterRegistration_ReSignsEachAttempt()
    {
        _services.AddHmacClient("partner", ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new CountingRetryHandler(2));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(["1790000000", "1790000001"], _transport.Requests.Select(a => a.Timestamp));
    }

    private static void ConfigureValid(HmacClientOptions options)
    {
        options.ClientId = "partner-a";
        options.Secret = Secret;
    }
}
