using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Where a retrying handler sits relative to the signing handler decides whether a retry is re-signed
/// (fresh timestamp and signature) or re-sends the original signature.
/// </summary>
public sealed class RetrySemanticsTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RetryHandlerAddedBeforeSigning_EveryAttemptIsSignedAndSucceeds(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var attempts = new ConcurrentQueue<SendAttempt>();
        var services = new ServiceCollection();
        services.AddHttpClient<SafetalkApiClient>()
            .AddHttpMessageHandler(() => new SendTwiceHandler(attempts)) // Added first: runs in front of signing.
            .AddHmacSigning(options =>
            {
                options.ClientId = TestCredentials.ClientId;
                options.Secret = TestCredentials.Secret;
            })
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(20_000);
        using var content = new ByteArrayContent(payload);

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
        Assert.Collection(
            attempts,
            first => AssertSignedOnce(first, HttpStatusCode.OK),
            second => AssertSignedOnce(second, HttpStatusCode.OK));
        Assert.Equal(2, server.ValidationResults.Count(result => result.Succeeded));
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RetryHandlerBeforeSigning_ClockAdvancesBetweenAttempts_RetryGetsFreshTimestampAndPassesReplayProtection(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection() }, ct);
        var clientClock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var attempts = new ConcurrentQueue<SendAttempt>();
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                TimeProvider = clientClock,
                HandlerBeforeSigning = () => new SendTwiceHandler(attempts, beforeRetry: () => clientClock.Advance(TimeSpan.FromSeconds(1))),
            });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        SendAttempt[] recorded = [.. attempts];
        Assert.Equal(2, recorded.Length);
        Assert.All(recorded, attempt => AssertSignedOnce(attempt, HttpStatusCode.OK));
        long firstTimestamp = long.Parse(recorded[0].Timestamps[0], CultureInfo.InvariantCulture);
        long secondTimestamp = long.Parse(recorded[1].Timestamps[0], CultureInfo.InvariantCulture);
        Assert.Equal(firstTimestamp + 1, secondTimestamp);
        Assert.NotEqual(recorded[0].Signatures[0], recorded[1].Signatures[0]);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RetryHandlerAfterSigning_ResendsTheOriginalSignature_WhichReplayProtectionRejects(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection() }, ct);
        var attempts = new ConcurrentQueue<SendAttempt>();
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new SendTwiceHandler(attempts) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        SendAttempt[] recorded = [.. attempts];
        Assert.Equal(2, recorded.Length);
        AssertSignedOnce(recorded[0], HttpStatusCode.OK);
        AssertSignedOnce(recorded[1], HttpStatusCode.Unauthorized);
        Assert.Equal(recorded[0].Timestamps, recorded[1].Timestamps);
        Assert.Equal(recorded[0].Signatures, recorded[1].Signatures);
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RetryHandlerBeforeSigning_NonSeekableStreamContent_IsBufferedAndSentIdenticallyTwice(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        var attempts = new ConcurrentQueue<SendAttempt>();
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerBeforeSigning = () => new SendTwiceHandler(attempts) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(180_000, seed: 31);
        using var content = new StreamContent(new NonSeekableReadStream(payload));

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(payload.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
        Assert.All(attempts, attempt => Assert.Equal(HttpStatusCode.OK, attempt.StatusCode));
        Assert.Equal(2, attempts.Count);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task StaleSigningHeadersSetByTheCaller_AreReplacedNotDuplicated(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/whoami", UriKind.Relative));
        request.Headers.TryAddWithoutValidation(SafetalkHeaderNames.ClientId, TestCredentials.OtherClientId);
        request.Headers.TryAddWithoutValidation(SafetalkHeaderNames.Timestamp, "1");
        request.Headers.TryAddWithoutValidation(SafetalkHeaderNames.Signature, new string('0', 64));

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        WhoAmIResponse whoAmI = await response.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
        Assert.Single(request.Headers.GetValues(SafetalkHeaderNames.ClientId));
        Assert.Single(request.Headers.GetValues(SafetalkHeaderNames.Timestamp));
        Assert.Single(request.Headers.GetValues(SafetalkHeaderNames.Signature));
    }

    private static void AssertSignedOnce(SendAttempt attempt, HttpStatusCode expectedStatus)
    {
        Assert.Equal(expectedStatus, attempt.StatusCode);
        Assert.Single(attempt.Timestamps);
        string signature = Assert.Single(attempt.Signatures);
        Assert.Equal(64, signature.Length);
    }
}
