using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Time.Testing;
using Polly;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// Every attempt a resilience handler sends through an <c>IHttpClientFactory</c> pipeline — retries of the same message
/// and hedging clones alike — must be re-signed with its own timestamp, so that no two attempts share a signature (a
/// server with replay protection would reject all but one) and every attempt verifies. Unless a test advances it, the
/// fake clock stands still, so every attempt is signed within the same second.
/// </summary>
public sealed class HmacSigningResilienceTests : IDisposable
{
    private const string Secret = "resilience-secret-0123456789abcdef";
    private const string OrderJson = "{\"order\":42}";

    private readonly FakeTimeProvider _time = new(SigningPipeline.StartTime);
    private readonly CapturingHandler _transport = new();
    private readonly ServiceCollection _services = new();

    public HmacSigningResilienceTests()
    {
        _services.AddSingleton<TimeProvider>(_time);
    }

    public void Dispose() => _transport.Dispose();

    [Fact]
    public async Task AddHmacClient_CloningHedgingHandlerAddedAfterRegistration_EachAttemptHasADistinctVerifiableSignature()
    {
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new CloningHedgingHandler(3));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        AssertDistinctVerifiableAttempts(expectedAttempts: 3, OrderJson);
        Assert.Equal(["1790000000", "1790000001", "1790000002"], _transport.Requests.Select(r => r.Timestamp));
    }

    [Fact]
    public async Task AddHmacSigning_CloningHedgingHandlerAddedBeforeSigning_EachAttemptHasADistinctVerifiableSignature()
    {
        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddHttpMessageHandler(() => new CloningHedgingHandler(2))
            .AddHmacSigning(ConfigureValid);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders?id=1"), TestContext.Current.CancellationToken);

        AssertDistinctVerifiableAttempts(expectedAttempts: 2, expectedBody: null);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaults_CloningHedgingHandler_EachAttemptOfASigningClientHasADistinctSignature(bool defaultsRegisteredFirst)
    {
        if (defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHttpMessageHandler(() => new CloningHedgingHandler(3)));
        }

        _services.AddHmacClient<OrdersApiClient>(ConfigureValid).ConfigurePrimaryHttpMessageHandler(() => _transport);

        if (!defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHttpMessageHandler(() => new CloningHedgingHandler(3)));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        AssertDistinctVerifiableAttempts(expectedAttempts: 3, OrderJson);
    }

    [Fact]
    public async Task AddStandardHedgingHandler_FailingAttempts_EveryHedgedAttemptHasADistinctVerifiableSignature()
    {
        var failures = new TransientFailureHandler(3) { InnerHandler = _transport };
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardHedgingHandler()
            .Configure(options => options.Hedging.MaxHedgedAttempts = 3);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders?id=42"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 4, OrderJson);
        Assert.Equal(["1790000000", "1790000001", "1790000002", "1790000003"], _transport.Requests.Select(r => r.Timestamp));
        Assert.All(_transport.Requests, attempt => Assert.Equal("/api/orders?id=42", attempt.PathAndQuery));
    }

    /// <summary>
    /// In parallel mode (no hedging delay) every attempt is started before any completes, so clones sharing the signing
    /// state are signed while the others are still in flight.
    /// </summary>
    [Fact]
    public async Task AddStandardHedgingHandler_ParallelMode_ConcurrentAttemptsHaveDistinctVerifiableSignatures()
    {
        const int attempts = 5;
        var barrier = new ArrivalBarrierHandler(attempts, TimeSpan.FromSeconds(15)) { InnerHandler = _transport };
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => barrier)
            .AddStandardHedgingHandler()
            .Configure(options =>
            {
                options.Hedging.MaxHedgedAttempts = attempts - 1;
                options.Hedging.Delay = TimeSpan.Zero;
            });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(attempts, barrier.Arrivals);
        AssertDistinctVerifiableAttempts(attempts, OrderJson);
        Assert.Equal(
            Enumerable.Range(0, attempts).Select(offset => (1_790_000_000 + offset).ToString(CultureInfo.InvariantCulture)),
            _transport.Requests.Select(r => r.Timestamp).Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// JSON content cannot be replayed as is, so the signing handler replaces the content of every attempt with the
    /// bytes it signed; the hedging clones share the original content, which must stay serializable for later clones.
    /// </summary>
    [Fact]
    public async Task AddStandardHedgingHandler_JsonContent_EveryAttemptSendsExactlyTheBytesItSigned()
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardHedgingHandler()
            .Configure(options => options.Hedging.MaxHedgedAttempts = 2);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsJsonAsync(new Uri("https://api.example.com/api/orders"), new { order = 42, item = "tea" }, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, "{\"order\":42,\"item\":\"tea\"}");
        Assert.All(_transport.Contents, sentContent => Assert.IsType<SignedRequestContent>(sentContent));
    }

    [Fact]
    public async Task AddStandardHedgingHandler_ClientRegisteredWithHmacSigningAfterwards_EveryAttemptHasADistinctSignature()
    {
        var failures = new TransientFailureHandler(1) { InnerHandler = _transport };
        _services.AddHttpClient<OrdersApiClient>()
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardHedgingHandler()
            .Configure(options => options.Hedging.MaxHedgedAttempts = 1);
        _services.AddHttpClient<OrdersApiClient>().AddHmacSigning(ConfigureValid);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 2, expectedBody: null);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaults_StandardHedgingHandler_EveryAttemptOfASigningClientHasADistinctSignature(bool defaultsRegisteredFirst)
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        if (defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddStandardHedgingHandler().Configure(options => options.Hedging.MaxHedgedAttempts = 2));
        }

        _services.AddHmacClient<OrdersApiClient>(ConfigureValid).ConfigurePrimaryHttpMessageHandler(() => failures);

        if (!defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddStandardHedgingHandler().Configure(options => options.Hedging.MaxHedgedAttempts = 2));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, OrderJson);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfigureHttpClientDefaultsSigning_ClientWithStandardHedgingHandler_EveryAttemptHasADistinctSignature(bool defaultsRegisteredFirst)
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        if (defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(ConfigureValid));
        }

        _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardHedgingHandler()
            .Configure(options => options.Hedging.MaxHedgedAttempts = 2);

        if (!defaultsRegisteredFirst)
        {
            _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(ConfigureValid));
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, expectedBody: null);
    }

    [Fact]
    public async Task AddStandardHedgingHandler_ClockAdvancingBetweenAttempts_EveryAttemptUsesTheLaterOfTheClockAndTheNextTimestamp()
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        IHttpClientBuilder builder = _services.AddHmacClient<OrdersApiClient>(ConfigureValid).ConfigurePrimaryHttpMessageHandler(() => failures);
        builder.AddStandardHedgingHandler().Configure(options =>
        {
            options.Hedging.MaxHedgedAttempts = 2;
            options.Hedging.Delay = Timeout.InfiniteTimeSpan;
        });
        builder.AddHttpMessageHandler(() => new ClockAdvancingHandler(_time, TimeSpan.FromSeconds(5)));
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(["1790000005", "1790000010", "1790000015"], _transport.Requests.Select(r => r.Timestamp));
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, expectedBody: null);
    }

    [Fact]
    public async Task AddStandardResilienceHandler_TransientFailures_EveryRetryIsReSignedWithADistinctTimestamp()
    {
        var failures = new TransientFailureHandler(3) { InnerHandler = _transport };
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardResilienceHandler(ConfigureImmediateRetries);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StreamContent(new NonSeekableReadStream(System.Text.Encoding.UTF8.GetBytes(OrderJson), maxChunkSize: 3));

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 4, OrderJson);
        Assert.Equal(["1790000000", "1790000001", "1790000002", "1790000003"], _transport.Requests.Select(r => r.Timestamp));
    }

    [Fact]
    public async Task AddStandardResilienceHandler_RegisteredBeforeAddHmacSigning_EveryRetryIsReSigned()
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        IHttpClientBuilder builder = _services.AddHttpClient("partner").ConfigurePrimaryHttpMessageHandler(() => failures);
        builder.AddStandardResilienceHandler(ConfigureImmediateRetries);
        builder.AddHmacSigning(ConfigureValid);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, expectedBody: null);
    }

    [Fact]
    public void AddStandardResilienceHandler_SynchronousSend_EveryRetryIsReSignedWithADistinctTimestamp()
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardResilienceHandler(ConfigureImmediateRetries);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var request = new HttpRequestMessage(HttpMethod.Put, "https://api.example.com/api/orders/42") { Content = new StringContent(OrderJson) };

        using HttpResponseMessage response = provider.GetRequiredService<OrdersApiClient>().HttpClient.Send(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, OrderJson);
    }

    [Fact]
    public async Task AddStandardHedgingHandlerAndResilience_IndependentRequestsInTheSameSecond_EachStartsAtTheCurrentTime()
    {
        var failures = new TransientFailureHandler(1) { InnerHandler = _transport };
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardHedgingHandler()
            .Configure(options => options.Hedging.MaxHedgedAttempts = 1);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (await client.GetAsync(new Uri("https://api.example.com/api/orders?id=1"), cancellationToken))
        using (await client.GetAsync(new Uri("https://api.example.com/api/orders?id=2"), cancellationToken))
        {
        }

        // The first request needed two attempts; the second, independent request is not pushed into the future.
        Assert.Equal(
            [("/api/orders?id=1", "1790000000"), ("/api/orders?id=1", "1790000001"), ("/api/orders?id=2", "1790000000")],
            _transport.Requests.Select(r => (r.PathAndQuery, r.Timestamp)));
    }

    [Fact]
    public void AddStandardHedgingHandler_PipelineShape_StateHandlerOutermostAndSignerInnermost()
    {
        var recorder = new AdditionalHandlersRecorder();
        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => _transport)
            .AddStandardHedgingHandler();
        _services.AddHttpClient<OrdersApiClient>().AddStandardResilienceHandler();
        _services.AddSingleton<Microsoft.Extensions.Http.IHttpMessageHandlerBuilderFilter>(recorder);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        IReadOnlyList<DelegatingHandler> handlers = HandlerChain.ContributedHandlers(provider, nameof(OrdersApiClient), _transport);

        Assert.IsType<HmacSigningStateHandler>(handlers[0]);
        Assert.IsType<HmacSigningHandler>(handlers[^1]);
        Assert.Single(handlers.OfType<HmacSigningStateHandler>());
        Assert.Single(handlers.OfType<HmacSigningHandler>());
        // The standard hedging handler contributes two resilience handlers (hedging and per-endpoint), the standard
        // resilience handler one; all of them sit between the signing state handler and the signer.
        Assert.Equal(3, handlers.Count(handler => handler.GetType().Name == "ResilienceHandler"));
        Assert.Equal(handlers, recorder.For(nameof(OrdersApiClient)));
    }

    /// <summary>
    /// Round 4: the defaults registration does nothing for a client with its own registration, so the client's hedged
    /// attempts go through exactly one signer, with the client's own credentials.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SigningDefaultsAndOwnRegistrationWithStandardHedgingHandler_AnyOrder_EveryAttemptIsSignedDistinctlyWithTheOwnCredentials(bool defaultsRegisteredFirst)
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        if (defaultsRegisteredFirst)
        {
            RegisterOtherSigningDefaults();
        }

        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardHedgingHandler()
            .Configure(options => options.Hedging.MaxHedgedAttempts = 2);

        if (!defaultsRegisteredFirst)
        {
            RegisterOtherSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, OrderJson);
        Assert.Equal(["1790000000", "1790000001", "1790000002"], _transport.Requests.Select(r => r.Timestamp));
        AssertSingleSigner(provider, nameof(OrdersApiClient));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SigningDefaultsAndUnnamedClientRegistrationWithStandardHedgingHandler_AnyOrder_EveryAttemptIsSignedDistinctlyWithTheOwnCredentials(bool defaultsRegisteredFirst)
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        if (defaultsRegisteredFirst)
        {
            RegisterOtherSigningDefaults();
        }

        IHttpClientBuilder builder = _services.AddHttpClient(Microsoft.Extensions.Options.Options.DefaultName)
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddHmacSigning(ConfigureValid);
        builder.AddStandardHedgingHandler().Configure(options => options.Hedging.MaxHedgedAttempts = 2);

        if (!defaultsRegisteredFirst)
        {
            RegisterOtherSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient();

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, expectedBody: null);
        AssertSingleSigner(provider, Microsoft.Extensions.Options.Options.DefaultName);
    }

    [Fact]
    public async Task AddHmacSigningTwiceAroundStandardHedgingHandler_EveryAttemptIsSignedDistinctlyWithTheCumulativeCredentials()
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        IHttpClientBuilder builder = _services.AddHttpClient("partner")
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddHmacSigning(options =>
            {
                options.ClientId = "partner-a";
                options.Secret = "outdated-secret";
            });
        builder.AddStandardHedgingHandler().Configure(options => options.Hedging.MaxHedgedAttempts = 2);
        builder.AddHmacSigning(options => options.Secret = Secret);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await client.PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, OrderJson);
        AssertSingleSigner(provider, "partner");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SigningDefaultsWithStandardHedgingHandlerInTheDefaults_ClientWithoutOwnRegistration_AnyOrder_EveryAttemptIsSignedDistinctly(bool signingFirst)
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        _services.ConfigureHttpClientDefaults(builder =>
        {
            if (signingFirst)
            {
                builder.AddHmacSigning(ConfigureValid);
            }

            builder.AddStandardHedgingHandler().Configure(options => options.Hedging.MaxHedgedAttempts = 2);

            if (!signingFirst)
            {
                builder.AddHmacSigning(ConfigureValid);
            }
        });
        _services.AddHttpClient("partner").ConfigurePrimaryHttpMessageHandler(() => failures);
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await client.PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, OrderJson);
        AssertSingleSigner(provider, "partner");
    }

    [Fact]
    public async Task AddStandardHedgingHandler_ParallelModeWithSigningDefaultsAndOwnRegistration_ConcurrentAttemptsHaveDistinctSignaturesWithTheOwnCredentials()
    {
        const int attempts = 4;
        var barrier = new ArrivalBarrierHandler(attempts, TimeSpan.FromSeconds(15)) { InnerHandler = _transport };
        RegisterOtherSigningDefaults();
        _services.AddHmacClient("partner", ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => barrier)
            .AddStandardHedgingHandler()
            .Configure(options =>
            {
                options.Hedging.MaxHedgedAttempts = attempts - 1;
                options.Hedging.Delay = TimeSpan.Zero;
            });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("partner");
        using var content = new StringContent(OrderJson);

        using HttpResponseMessage response = await client.PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(attempts, barrier.Arrivals);
        AssertDistinctVerifiableAttempts(attempts, OrderJson);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AddStandardResilienceHandler_SigningDefaultsAndOwnRegistration_AnyOrder_EveryRetryIsReSignedWithTheOwnCredentials(bool defaultsRegisteredFirst)
    {
        var failures = new TransientFailureHandler(2) { InnerHandler = _transport };
        if (defaultsRegisteredFirst)
        {
            RegisterOtherSigningDefaults();
        }

        _services.AddHmacClient<OrdersApiClient>(ConfigureValid)
            .ConfigurePrimaryHttpMessageHandler(() => failures)
            .AddStandardResilienceHandler(ConfigureImmediateRetries);

        if (!defaultsRegisteredFirst)
        {
            RegisterOtherSigningDefaults();
        }

        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        using var content = new StreamContent(new NonSeekableReadStream(System.Text.Encoding.UTF8.GetBytes(OrderJson), maxChunkSize: 4));

        using HttpResponseMessage response = await provider.GetRequiredService<OrdersApiClient>().HttpClient
            .PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertDistinctVerifiableAttempts(expectedAttempts: 3, OrderJson);
        AssertSingleSigner(provider, nameof(OrdersApiClient));
    }

    private static void AssertSingleSigner(IServiceProvider provider, string name)
    {
        IReadOnlyList<HttpMessageHandler> chain = HandlerChain.Walk(provider, name);
        Assert.Single(chain.OfType<HmacSigningStateHandler>());
        Assert.Single(chain.OfType<HmacSigningHandler>());
        int state = chain.ToList().FindIndex(h => h is HmacSigningStateHandler);
        int signer = chain.ToList().FindIndex(h => h is HmacSigningHandler);
        int[] resilience = [.. chain.Select((handler, index) => (handler, index)).Where(x => x.handler.GetType().Name == "ResilienceHandler").Select(x => x.index)];
        Assert.NotEmpty(resilience);
        Assert.All(resilience, index => Assert.InRange(index, state + 1, signer - 1));
    }

    /// <summary>
    /// Signing defaults with credentials that differ from <see cref="ConfigureValid"/>: a request signed with them fails
    /// <see cref="AssertDistinctVerifiableAttempts"/>.
    /// </summary>
    private void RegisterOtherSigningDefaults() =>
        _services.ConfigureHttpClientDefaults(builder => builder.AddHmacSigning(options =>
        {
            options.ClientId = "defaults-client";
            options.Secret = "defaults-secret";
        }));

    private static void ConfigureValid(HmacClientOptions options)
    {
        options.ClientId = "partner-a";
        options.Secret = Secret;
    }

    private static void ConfigureImmediateRetries(HttpStandardResilienceOptions options)
    {
        options.Retry.MaxRetryAttempts = 3;
        options.Retry.Delay = TimeSpan.Zero;
        options.Retry.BackoffType = DelayBackoffType.Constant;
        options.Retry.UseJitter = false;
    }

    /// <summary>
    /// Advances the fake clock before every attempt that passes through it (it sits between the hedging handler and
    /// the signer, so it sees every clone).
    /// </summary>
    private sealed class ClockAdvancingHandler(FakeTimeProvider time, TimeSpan step) : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            time.Advance(step);
            return base.SendAsync(request, cancellationToken);
        }
    }

    private void AssertDistinctVerifiableAttempts(int expectedAttempts, string? expectedBody)
    {
        IReadOnlyList<CapturedRequest> attempts = _transport.Requests;
        Assert.Equal(expectedAttempts, attempts.Count);
        Assert.Equal(expectedAttempts, attempts.Select(a => a.Timestamp).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(expectedAttempts, attempts.Select(a => a.Signature).Distinct(StringComparer.Ordinal).Count());
        Assert.All(attempts, attempt =>
        {
            Assert.Equal("partner-a", attempt.ClientId);
            Assert.Equal(expectedBody is null ? null : System.Text.Encoding.UTF8.GetBytes(expectedBody), attempt.Body);
            Assert.Equal(ReferenceSigner.Sign(Secret, attempt), attempt.Signature);
            Assert.True(HmacSha256SignatureService.Instance.VerifySignature(
                Secret, attempt.Method, attempt.PathAndQuery, attempt.Timestamp, attempt.BodyOrEmpty, attempt.Signature));
        });
    }
}
