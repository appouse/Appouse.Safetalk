using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The signing handler is always the innermost delegating handler, whatever the registration order: retry and hedging
/// handlers re-sign every attempt, and handlers that modify the request run before it is signed.
/// </summary>
public sealed class HandlerOrderingTests
{
    private static readonly OrderRequest Order = new("SKU-42", 3, "retry me");

    private static readonly string[] ExpectedHandlerOrder = ["before:False", "after:False"];

    /// <summary>
    /// The typical composition: <c>AddHmacClient</c> followed by a retry handler. The endpoint fails once with 503; the
    /// retry is re-signed (new timestamp, new signature), so replay protection accepts it and the caller gets 200.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RetryHandlerAddedAfterAddHmacClient_EndpointFailsOnceWith503_WithReplayProtection_FinalAttemptSucceeds(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, FlakyServer(received, failures: 1), ct);
        var attempts = new ConcurrentQueue<SendAttempt>();
        var services = new ServiceCollection();
        services
            .AddHmacClient<SafetalkApiClient>(options =>
            {
                options.ClientId = TestCredentials.ClientId;
                options.Secret = TestCredentials.Secret;
            })
            .AddHttpMessageHandler(() => new RetryOnStatusHandler(attempts)) // Registered AFTER signing.
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/api/flaky", Order, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal(Order, echo.Order);
        SendAttempt[] recorded = [.. attempts];
        Assert.Equal(new[] { HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK }, recorded.Select(attempt => attempt.StatusCode));
        Assert.All(recorded, attempt => Assert.Single(attempt.Signatures));
        Assert.NotEqual(recorded[0].Signatures[0], recorded[1].Signatures[0]);
        Assert.NotEqual(recorded[0].Timestamps[0], recorded[1].Timestamps[0]);
        Assert.Equal(2, received.Count);
        Assert.Equal(2, received.Signatures.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(2, server.ValidationResults.Count(result => result.Succeeded));
        Assert.DoesNotContain(server.ValidationResults, result => result.Failure == HmacValidationFailure.ReplayDetected);
    }

    /// <summary>
    /// A frozen client clock: every attempt of the same message is signed within the same second, so only the
    /// strictly increasing timestamp (previous + 1) keeps the signatures distinct.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RetriesOfTheSameMessageWithinOneSecond_AreSignedWithStrictlyIncreasingTimestamps(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, FlakyServer(received, failures: 3), ct);
        var attempts = new ConcurrentQueue<SendAttempt>();
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow),
                HandlerBeforeSigning = () => new RetryOnStatusHandler(attempts, maxAttempts: 4),
            });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/api/flaky", Order, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        long[] timestamps = [.. attempts.Select(attempt => long.Parse(Assert.Single(attempt.Timestamps), CultureInfo.InvariantCulture))];
        Assert.Equal(4, timestamps.Length);
        Assert.Equal(new[] { timestamps[0], timestamps[0] + 1, timestamps[0] + 2, timestamps[0] + 3 }, timestamps);
        Assert.Equal(4, attempts.Select(attempt => attempt.Signatures[0]).Distinct(StringComparer.Ordinal).Count());
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    /// <summary>
    /// A hedging-like handler re-sends the same message while the first attempt is still in flight. The second
    /// attempt is re-signed; both attempts pass replay protection and complete with 200.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task HedgingLikeParallelResendOfTheSameMessage_IsReSigned_AndBothAttemptsPassReplayProtection(TestHostKind kind)
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
                ConfigureEndpoints = endpoints => endpoints.MapPost("/api/slow", async (HttpContext context, OrderRequest order) =>
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
        var outcomes = new ConcurrentQueue<SendAttempt>();
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow), // Both attempts within "the same second".
                HandlerBeforeSigning = () => new HedgingLikeHandler(firstArrived.Task, releaseFirst, outcomes),
            });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/api/slow", Order, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal(Order, echo.Order);
        Assert.Equal(2, outcomes.Count);
        Assert.All(outcomes, outcome => Assert.Equal(HttpStatusCode.OK, outcome.StatusCode));
        Assert.Equal(2, received.Count);
        string[] signatures = [.. received.Signatures];
        Assert.NotEqual(signatures[0], signatures[1]);
        long[] timestamps = [.. received.Timestamps.Select(value => long.Parse(value, CultureInfo.InvariantCulture))];
        Assert.Equal(timestamps[0] + 1, timestamps[1]);
        Assert.Equal(2, server.ValidationResults.Count(result => result.Succeeded));
    }

    /// <summary>
    /// A handler that enriches the request (adds a query parameter and a header) is registered after
    /// <c>AddHmacClient</c>; it still runs before signing, so the enriched request verifies.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequestModifyingHandlerAddedAfterAddHmacClient_RunsBeforeSigning_SoTheModifiedRequestVerifies(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                HandlerBeforeSigning = () => new RequestMutatingHandler(request =>
                {
                    Assert.False(request.Headers.Contains(SafetalkHeaderNames.Signature), "The handler must run before signing.");
                    request.RequestUri = new Uri(request.RequestUri!.AbsoluteUri + "&tenant=42");
                }),
            });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/inspect/orders?id=5", ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("?id=5&tenant=42", info.QueryString);
        Assert.Equal(TestCredentials.ClientId, info.ClientId);
    }

    /// <summary>
    /// Even a handler appended at the very end of the additional handlers list (which would normally make it the
    /// innermost one) runs before the signing handler.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task HandlerAppendedLastThroughConfigureAdditionalHttpMessageHandlers_StillRunsBeforeSigning(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var seenBySigningPosition = new ConcurrentQueue<bool>();
        var services = new ServiceCollection();
        services
            .AddHmacClient<SafetalkApiClient>(options =>
            {
                options.ClientId = TestCredentials.ClientId;
                options.Secret = TestCredentials.Secret;
            })
            .ConfigureAdditionalHttpMessageHandlers((handlers, _) => handlers.Add(new RequestMutatingHandler(request =>
            {
                seenBySigningPosition.Enqueue(request.Headers.Contains(SafetalkHeaderNames.Signature));
                request.Headers.TryAddWithoutValidation("X-Correlation-Id", "abc");
            })))
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
        Assert.False(Assert.Single(seenBySigningPosition));
    }

    /// <summary>
    /// Handlers registered before and after the signing registration both run outside it, in registration order.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task HandlersRegisteredBeforeAndAfterAddHmacSigning_BothRunBeforeSigning_InRegistrationOrder(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var order = new ConcurrentQueue<string>();
        var services = new ServiceCollection();
        services.AddHttpClient<SafetalkApiClient>()
            .AddHttpMessageHandler(() => new RequestMutatingHandler(request => order.Enqueue("before:" + request.Headers.Contains(SafetalkHeaderNames.Signature))))
            .AddHmacSigning(options =>
            {
                options.ClientId = TestCredentials.ClientId;
                options.Secret = TestCredentials.Secret;
            })
            .AddHttpMessageHandler(() => new RequestMutatingHandler(request => order.Enqueue("after:" + request.Headers.Contains(SafetalkHeaderNames.Signature))))
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
        Assert.Equal(ExpectedHandlerOrder, order);
    }

    /// <summary>
    /// A retry handler placed between signing and the network (by wrapping the primary handler) re-sends the original
    /// signature; replay protection rejects it. This is why the signing handler is kept innermost.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RetryBelowTheSigningHandler_ResendsTheSameSignature_AndReplayProtectionRejectsIt(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, FlakyServer(received, failures: 1), ct);
        var attempts = new ConcurrentQueue<SendAttempt>();
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new RetryOnStatusHandler(attempts) });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/api/flaky", Order, ct);

        response.AssertUnauthorized();
        Assert.Equal(new[] { HttpStatusCode.ServiceUnavailable, HttpStatusCode.Unauthorized }, attempts.Select(attempt => attempt.StatusCode));
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
    }

    /// <summary>
    /// <c>AddStandardHedgingHandler()</c> (Microsoft.Extensions.Http.Resilience) does not re-send the same message: it
    /// snapshots the request before the first attempt and sends clones that share the content and copy headers and
    /// options (<c>RequestMessageSnapshot</c>). A hedged attempt starts immediately when an attempt fails with a transient
    /// status. The library documents that hedging handlers re-sign every attempt; with replay protection the hedged
    /// attempt must therefore be accepted even when it is signed within the same second as the failed one.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task HedgingHandlerCloningTheRequest_PrimaryFailsWith503_HedgedCloneInTheSameSecond_PassesReplayProtection(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, FlakyServer(received, failures: 1), ct);
        var attempts = new ConcurrentQueue<SendAttempt>();
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow), // Deterministically "the same second".
                HandlerBeforeSigning = () => new SnapshotHedgingHandler(attempts),
            });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsJsonAsync("/api/flaky", Order, ct);

        SendAttempt[] recorded = [.. attempts];
        Assert.Equal(2, recorded.Length);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, recorded[0].StatusCode);
        Assert.Equal(
            (HttpStatusCode.OK, HmacValidationFailure.None),
            (response.StatusCode, server.ValidationResults.Last().Failure));
    }

    private static ServerSetup FlakyServer(ReceivedRequests received, int failures) => new()
    {
        ConfigureHmac = hmac => hmac.AddReplayProtection(),
        ConfigureEndpoints = endpoints => MapFlakyEndpoint(endpoints, received, failures),
    };

    private static void MapFlakyEndpoint(IEndpointRouteBuilder endpoints, ReceivedRequests received, int failures)
        => endpoints.MapPost("/api/flaky", (HttpContext context, OrderRequest order) =>
            received.Add(context) <= failures
                ? Results.StatusCode(StatusCodes.Status503ServiceUnavailable)
                : Results.Ok(new OrderEchoResponse(context.GetHmacClientId(), order)));

    /// <summary>
    /// Mirrors the hedging pipeline of Microsoft.Extensions.Http.Resilience: the snapshot (method, URI, version, shared
    /// content, headers, options) is taken before the primary attempt, which uses the original message; the hedged
    /// attempt is a clone created from the snapshot and started as soon as the primary fails with a transient status.
    /// </summary>
    private sealed class SnapshotHedgingHandler(ConcurrentQueue<SendAttempt> attempts) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpMethod method = request.Method;
            Uri? requestUri = request.RequestUri;
            Version version = request.Version;
            HttpContent? content = request.Content;
            KeyValuePair<string, IEnumerable<string>>[] headers = [.. request.Headers];
            KeyValuePair<string, object?>[] options = [.. request.Options];

            HttpResponseMessage primary = await base.SendAsync(request, cancellationToken);
            attempts.Enqueue(SendAttempt.From(request, primary));
            if (primary.StatusCode != HttpStatusCode.ServiceUnavailable)
            {
                return primary;
            }

            primary.Dispose();

            // Not disposed by the hedging pipeline either: the content is shared with the original message.
#pragma warning disable CA2000
            var clone = new HttpRequestMessage(method, requestUri) { Content = content, Version = version };
#pragma warning restore CA2000
            foreach ((string key, object? value) in options)
            {
                _ = ((IDictionary<string, object?>)clone.Options).TryAdd(key, value);
            }

            foreach ((string name, IEnumerable<string> values) in headers)
            {
                _ = clone.Headers.TryAddWithoutValidation(name, values);
            }

            HttpResponseMessage hedged = await base.SendAsync(clone, cancellationToken);
            attempts.Enqueue(SendAttempt.From(clone, hedged));
            return hedged;
        }
    }

    /// <summary>
    /// Sends the request, waits until the server holds the first attempt, sends the same message again, then lets the
    /// first attempt complete. Returns the response of the second attempt.
    /// </summary>
    private sealed class HedgingLikeHandler(Task firstArrived, TaskCompletionSource releaseFirst, ConcurrentQueue<SendAttempt> outcomes) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Task<HttpResponseMessage> primary = base.SendAsync(request, cancellationToken);
            await firstArrived.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);

            HttpResponseMessage hedged = await base.SendAsync(request, cancellationToken);
            outcomes.Enqueue(SendAttempt.From(request, hedged));
            releaseFirst.TrySetResult();

            using (HttpResponseMessage first = await primary)
            {
                outcomes.Enqueue(new SendAttempt(first.StatusCode, [], []));
            }

            return hedged;
        }
    }
}
