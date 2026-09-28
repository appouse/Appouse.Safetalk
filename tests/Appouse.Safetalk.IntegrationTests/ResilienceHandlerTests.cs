using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The real <c>AddStandardHedgingHandler()</c> and <c>AddStandardResilienceHandler()</c> of
/// Microsoft.Extensions.Http.Resilience chained after <c>AddHmacClient</c>, against a server with replay protection.
/// </summary>
/// <remarks>
/// The hedging handler does not re-send the message: it snapshots the request before the first attempt and sends
/// clones that share the content and copy the options. The clones only get distinct timestamps when the signing
/// state is attached to the request before the snapshot is taken, which the <c>IHttpClientFactory</c> integration does
/// by adding its state handler outermost. A client clock frozen within one second makes every assertion on
/// "distinct signatures" depend on that shared state rather than on the wall clock.
/// </remarks>
public sealed class ResilienceHandlerTests
{
    private static readonly OrderRequest Order = new("SKU-7", 2, "resilient");

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task StandardHedgingHandler_PrimaryFailsWith503_HedgedCloneIsReSignedAndSucceeds_WithReplayProtection(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, UnavailableServer(received, failures: 1), ct);
        FakeTimeProvider clientClock = CreateFrozenClock();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clientClock);
        services.AddHmacClient<SafetalkApiClient>(ConfigurePartnerA)
            .UseServer(server)
            .AddStandardHedgingHandler();
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/resilience/unavailable", Order, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal((TestCredentials.ClientId, Order), (echo.ClientId, echo.Order));
        AssertDistinctlySignedAttempts(server, received, clientClock, expectedAttempts: 2);
    }

    /// <summary>
    /// The primary attempt hangs; after the hedging delay a clone is sent while the primary is still in flight. Both
    /// reach the endpoint, so both passed replay protection: the clone was signed with its own timestamp although the
    /// client clock never left the second in which the primary was signed.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task StandardHedgingHandler_SlowPrimary_HedgedCloneInTheSameSecondWins_WithReplayProtection(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        var firstArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureHmac = hmac => hmac.AddReplayProtection(),
                ConfigureEndpoints = endpoints => endpoints.MapPost("/resilience/slow", async (HttpContext context, OrderRequest order) =>
                {
                    if (received.Add(context) == 1)
                    {
                        firstArrived.TrySetResult();
                        await releaseFirst.Task.WaitAsync(TimeSpan.FromSeconds(30), context.RequestAborted);
                    }

                    return new OrderEchoResponse(context.GetHmacClientId(), order);
                }),
            },
            ct);
        FakeTimeProvider clientClock = CreateFrozenClock(); // Also drives the hedging delay (Polly uses the DI clock).
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clientClock);
        services.AddHmacClient<SafetalkApiClient>(ConfigurePartnerA)
            .UseServer(server)
            .AddStandardHedgingHandler()
            .Configure(options => options.Hedging.Delay = TimeSpan.FromMilliseconds(100));
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        try
        {
            Task<HttpResponseMessage> sending = clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/resilience/slow", Order, ct);
            await firstArrived.Task.WaitAsync(TimeSpan.FromSeconds(30), ct);

            // Let the hedging delay elapse without leaving the second the primary was signed in.
            for (int step = 0; received.Count < 2 && step < 90; step++)
            {
                clientClock.Advance(TimeSpan.FromMilliseconds(10));
                await Task.Delay(TimeSpan.FromMilliseconds(20), ct);
            }

            using HttpResponseMessage response = await sending.WaitAsync(TimeSpan.FromSeconds(30), ct);

            OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
            Assert.Equal((TestCredentials.ClientId, Order), (echo.ClientId, echo.Order));
            AssertDistinctlySignedAttempts(server, received, clientClock, expectedAttempts: 2);
        }
        finally
        {
            releaseFirst.TrySetResult();
        }
    }

    /// <summary>
    /// The standard resilience handler re-sends the same message; every retry is re-signed with a strictly increasing
    /// timestamp, also when the client clock does not move between attempts.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task StandardResilienceHandler_EndpointFailsTwiceWith503_RetriesAreReSignedAndSucceed_WithReplayProtection(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, UnavailableServer(received, failures: 2), ct);
        FakeTimeProvider clientClock = CreateFrozenClock();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clientClock);
        services.AddHmacClient<SafetalkApiClient>(ConfigurePartnerA)
            .UseServer(server)
            .AddStandardResilienceHandler(options => options.Retry.Delay = TimeSpan.Zero);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/resilience/unavailable", Order, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal(Order, echo.Order);
        AssertDistinctlySignedAttempts(server, received, clientClock, expectedAttempts: 3);
    }

    /// <summary>
    /// Synchronous <see cref="HttpClient.Send(HttpRequestMessage, CancellationToken)"/> through the real handlers
    /// (Kestrel only: the TestServer handler has no synchronous send): every attempt is re-signed as well.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SynchronousSend_ThroughRetryOrHedgingHandler_EveryAttemptIsReSigned(bool hedging)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, UnavailableServer(received, failures: 1), ct);
        FakeTimeProvider clientClock = CreateFrozenClock();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clientClock);
        IHttpClientBuilder builder = services.AddHmacClient<SafetalkApiClient>(ConfigurePartnerA).UseServer(server);
        if (hedging)
        {
            builder.AddStandardHedgingHandler();
        }
        else
        {
            builder.AddStandardResilienceHandler(options => options.Retry.Delay = TimeSpan.Zero);
        }

        await using ServiceProvider clientServices = services.BuildServiceProvider();
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/resilience/unavailable", UriKind.Relative))
        {
            Content = JsonContent.Create(Order),
        };

        using HttpClient client = clientServices.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(SafetalkApiClient));

        using HttpResponseMessage response = await Task.Run(() => client.Send(request, ct), ct);

        Assert.Equal(Order, (await response.ReadOkJsonAsync<OrderEchoResponse>(ct)).Order);
        AssertDistinctlySignedAttempts(server, received, clientClock, expectedAttempts: 2);
    }

    /// <summary>
    /// The .NET Aspire "service defaults" shape: the resilience handler comes from <c>ConfigureHttpClientDefaults</c>
    /// (configured before any client), the signing from the typed client's own <c>AddHmacClient</c>.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ResilienceHandlerFromConfigureHttpClientDefaults_WithAddHmacClient_RetriesAreReSigned(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, UnavailableServer(received, failures: 1), ct);
        FakeTimeProvider clientClock = CreateFrozenClock();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clientClock);
        services.ConfigureHttpClientDefaults(http => http.AddStandardResilienceHandler(options => options.Retry.Delay = TimeSpan.Zero));
        services.AddHmacClient<SafetalkApiClient>(ConfigurePartnerA).UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/resilience/unavailable", Order, ct);

        Assert.Equal(Order, (await response.ReadOkJsonAsync<OrderEchoResponse>(ct)).Order);
        AssertDistinctlySignedAttempts(server, received, clientClock, expectedAttempts: 2);
    }

    /// <summary>
    /// Signing for every client through <c>ConfigureHttpClientDefaults</c>, a client with its own credentials (whose
    /// registration replaces the default signer, before or after the defaults were registered) and the hedging
    /// handler: the replacement keeps the signing state outermost, so the hedged clone is still signed distinctly, and
    /// both attempts carry the client's own identity.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, true)]
    [InlineData(TestHostKind.TestServer, false)]
    [InlineData(TestHostKind.Kestrel, true)]
    [InlineData(TestHostKind.Kestrel, false)]
    public async Task HedgingClientWithOwnCredentials_AndDefaultSigningForAllClients_HedgedCloneIsSignedWithTheClientsOwnIdentity(TestHostKind kind, bool defaultsFirst)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, UnavailableServer(received, failures: 1), ct);
        FakeTimeProvider clientClock = CreateFrozenClock();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clientClock);
        if (defaultsFirst)
        {
            services.ConfigureHttpClientDefaults(http => http.AddHmacSigning(ConfigurePartnerA));
        }

        IHttpClientBuilder client = services.AddHttpClient<SafetalkApiClient>().UseServer(server);
        client.AddStandardHedgingHandler();
        client.AddHmacSigning(options =>
        {
            options.ClientId = TestCredentials.OtherClientId;
            options.Secret = TestCredentials.OtherSecret;
        });
        if (!defaultsFirst)
        {
            services.ConfigureHttpClientDefaults(http => http.AddHmacSigning(ConfigurePartnerA));
        }

        await using ServiceProvider clientServices = services.BuildServiceProvider();

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/resilience/unavailable", Order, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal(TestCredentials.OtherClientId, echo.ClientId);
        AssertDistinctlySignedAttempts(server, received, clientClock, expectedAttempts: 2);
        Assert.All(server.ValidationResults, result => Assert.Equal(TestCredentials.OtherClientId, result.ClientId));
    }

    /// <summary>
    /// The documented limit, and the control for the tests above: a signing handler composed by hand below a hedging
    /// handler, without the signing state attached before the snapshot, signs the clone on its own. Within the same
    /// second it reproduces the primary's signature, which replay protection rejects. The <c>IHttpClientFactory</c>
    /// integration avoids this by attaching the state outermost.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SigningHandlerComposedByHandBelowTheHedgingHandler_HedgedCloneRepeatsThePrimarysSignature_AsDocumented(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, UnavailableServer(received, failures: 1), ct);
        FakeTimeProvider clientClock = CreateFrozenClock();
        var credentials = new Client.HmacClientOptions { ClientId = TestCredentials.ClientId, Secret = TestCredentials.Secret };
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clientClock);
        services.AddHttpClient("manual")
            .ConfigureHttpClient(client => client.BaseAddress = server.BaseAddress)
            .ConfigurePrimaryHttpMessageHandler(() => new Client.HmacSigningHandler(
                credentials,
                HmacSha256SignatureService.Instance,
                clientClock,
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Client.HmacSigningHandler>.Instance)
            {
                InnerHandler = server.CreatePrimaryHandler(),
            })
            .AddStandardHedgingHandler();
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        using HttpClient manual = clientServices.GetRequiredService<IHttpClientFactory>().CreateClient("manual");

        using HttpResponseMessage response = await manual.PostAsJsonAsync(new Uri("/resilience/unavailable", UriKind.Relative), Order, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
        Assert.Equal(1, received.Count); // Only the primary reached the endpoint.
    }

    private static void ConfigurePartnerA(Client.HmacClientOptions options)
    {
        options.ClientId = TestCredentials.ClientId;
        options.Secret = TestCredentials.Secret;
    }

    /// <summary>
    /// A client clock frozen at the start of a second: whatever it is advanced by below one second, every attempt is
    /// signed "within the same second".
    /// </summary>
    private static FakeTimeProvider CreateFrozenClock()
        => new(DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));

    private static void AssertDistinctlySignedAttempts(SafetalkServer server, ReceivedRequests received, FakeTimeProvider clientClock, int expectedAttempts)
    {
        long second = clientClock.GetUtcNow().ToUnixTimeSeconds();
        long[] expectedTimestamps = [.. Enumerable.Range(0, expectedAttempts).Select(offset => second + offset)];

        // Every attempt reached the endpoint (it passed validation and the replay cache) with its own signature.
        Assert.Equal(expectedAttempts, received.Count);
        Assert.Equal(expectedAttempts, received.Signatures.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(expectedTimestamps, received.Timestamps.Select(value => long.Parse(value, CultureInfo.InvariantCulture)).Order());
        Assert.Equal(expectedAttempts, server.ValidationResults.Count);
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded, result.Failure.ToString()));
    }

    private static ServerSetup UnavailableServer(ReceivedRequests received, int failures) => new()
    {
        ConfigureHmac = hmac => hmac.AddReplayProtection(),
        ConfigureEndpoints = endpoints => MapUnavailableEndpoint(endpoints, received, failures),
    };

    private static void MapUnavailableEndpoint(IEndpointRouteBuilder endpoints, ReceivedRequests received, int failures)
        => endpoints.MapPost("/resilience/unavailable", (HttpContext context, OrderRequest order) =>
            received.Add(context) <= failures
                ? Results.StatusCode(StatusCodes.Status503ServiceUnavailable)
                : Results.Ok(new OrderEchoResponse(context.GetHmacClientId(), order)));
}
