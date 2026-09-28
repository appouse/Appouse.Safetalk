using System.Globalization;
using System.Net;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// A signed request captured on the wire (after the signing handler) and re-sent verbatim by an attacker.
/// </summary>
public sealed class ReplayProtectionTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayOfCapturedRequest_WithReplayProtection_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection() }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new StringContent("""{"amount":1000,"iban":"TR00 0000"}""", Encoding.UTF8, "application/json");

        using HttpResponseMessage original = await client.PostAsync("/api/raw?transfer=1", content, ct);
        using HttpResponseMessage replayed = await ReplayAsync(server, Assert.Single(capture.Requests), ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        replayed.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayOfCapturedRequest_WithoutReplayProtection_IsAcceptedWithinTheWindow(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(10_000);
        using var content = new ByteArrayContent(payload);

        using HttpResponseMessage original = await client.PostAsync("/api/raw", content, ct);
        using HttpResponseMessage replayed = await ReplayAsync(server, Assert.Single(capture.Requests), ct);

        // Control for the test above: the captured copy is a faithful, valid request, and replay protection is opt-in.
        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        RawBodyResponse body = await replayed.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayWithUpperCasedSignature_WithReplayProtection_IsStillDetected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection() }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage original = await client.GetAsync("/api/whoami", ct);
        using HttpRequestMessage replay = Assert.Single(capture.Requests).ToRequestMessage();
        string signature = replay.Headers.GetValues(SafetalkHeaderNames.Signature).Single();
        replay.Headers.Remove(SafetalkHeaderNames.Signature);
        replay.Headers.TryAddWithoutValidation(SafetalkHeaderNames.Signature, signature.ToUpperInvariant());
        using HttpClient attacker = server.CreateUnsignedClient();
        using HttpResponseMessage replayed = await attacker.SendAsync(replay, ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        replayed.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayAfterTheClockSkewWindow_IsRejectedEvenWithoutReplayProtection(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        var serverClock = new FakeTimeProvider(Now);
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { TimeProvider = serverClock }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(Now), HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage original = await client.GetAsync("/api/whoami", ct);
        serverClock.Advance(HmacServerOptions.DefaultAllowedClockSkew + TimeSpan.FromSeconds(1));
        using HttpResponseMessage replayed = await ReplayAsync(server, Assert.Single(capture.Requests), ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        replayed.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ConcurrentReplaysOfAnUnusedSignedRequest_ExactlyOneIsAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection() }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture, forward: false) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new ByteArrayContent(TestData.CreateBytes(5_000));
        using HttpResponseMessage notSent = await client.PostAsync("/api/raw", content, ct);
        CapturedRequest signed = Assert.Single(capture.Requests);
        using HttpClient attacker = server.CreateUnsignedClient();

        HttpStatusCode[] statuses = await Task.WhenAll(Enumerable.Range(0, 16).Select(async _ =>
        {
            using HttpRequestMessage copy = signed.ToRequestMessage();
            using HttpResponseMessage response = await attacker.SendAsync(copy, ct);
            return response.StatusCode;
        }));

        Assert.Equal(HttpStatusCode.Accepted, notSent.StatusCode);
        Assert.Equal(1, statuses.Count(status => status == HttpStatusCode.OK));
        Assert.Equal(15, statuses.Count(status => status == HttpStatusCode.Unauthorized));
        Assert.Equal(15, server.ValidationResults.Count(result => result.Failure == HmacValidationFailure.ReplayDetected));
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task DistinctRequestsSignedWithinTheSameSecond_WithReplayProtection_AreAllAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection() }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow) }); // A frozen clock: every request shares one timestamp.
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        for (int i = 0; i < 5; i++)
        {
            using HttpResponseMessage response = await client.GetAsync($"/inspect/orders?id={i}", ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task IdenticalRequestsSignedWithinTheSameSecond_WithReplayProtection_SecondIsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection() }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage first = await client.GetAsync("/api/whoami", ct);
        using HttpResponseMessage second = await client.GetAsync("/api/whoami", ct);

        // Documented trade-off of second-resolution timestamps (HmacServerOptions.EnableReplayProtection remarks).
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        second.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task CustomReplayCache_ReceivesLowerCaseSignatureAndExpiryPastTheAcceptanceWindow(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { TimeProvider = new FakeTimeProvider(Now), ConfigureHmac = hmac => hmac.AddReplayProtection<RecordingReplayCache>() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(Now), HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage original = await client.GetAsync("/api/whoami", ct);
        using HttpResponseMessage replayed = await ReplayAsync(server, Assert.Single(capture.Requests), ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        replayed.AssertUnauthorized();
        var cache = Assert.IsType<RecordingReplayCache>(server.Services.GetRequiredService<IHmacReplayCache>());
        Assert.Equal(2, cache.Calls.Count);
        CapturedRequest signed = capture.Requests.Single();
        long timestamp = long.Parse(signed.Timestamp, CultureInfo.InvariantCulture);

        // Accepted until ts + skew + 1 s (exclusive), plus the 30 s safety margin.
        DateTimeOffset expectedExpiry = DateTimeOffset.FromUnixTimeSeconds(timestamp + (long)HmacServerOptions.DefaultAllowedClockSkew.TotalSeconds + 1)
            + TimeSpan.FromSeconds(30);
        Assert.All(cache.Calls, call =>
        {
            Assert.Equal(signed.Signature, call.Signature);
            Assert.Equal(signed.Signature.ToLowerInvariant(), call.Signature);
            Assert.Equal(expectedExpiry, call.ExpiresAt);
            Assert.True(call.ExpiresAt > call.Now, "The validator must never hand the cache an already expired entry.");
            Assert.True(call.TokenCanBeCanceled, "The request-aborted token flows to the cache.");
        });
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task FailedVerification_IsNotRecordedInTheReplayCache(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection<RecordingReplayCache>() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { Secret = "not-the-shared-secret" });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        var cache = Assert.IsType<RecordingReplayCache>(server.Services.GetRequiredService<IHmacReplayCache>());
        Assert.Empty(cache.Calls);
    }

    /// <summary>
    /// <c>X-Client-Id</c> is not signed. With a secret store that matches client ids case-insensitively (which the docs
    /// warn against, but e.g. SQL Server collations do), a replay under another spelling of the client id still
    /// verifies; keying the replay cache on the signature alone makes it a detected replay anyway.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, "PARTNER-A")]
    [InlineData(TestHostKind.Kestrel, "PARTNER-A")]
    [InlineData(TestHostKind.TestServer, "Partner-A")]
    [InlineData(TestHostKind.Kestrel, "Partner-A")]
    public async Task ReplayUnderAnotherSpellingOfTheClientId_WithCaseInsensitiveSecretStore_IsDetected(TestHostKind kind, string spelling)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureHmac = hmac => hmac
                    .AddSecretProvider(_ => new CaseInsensitiveSecretProvider(), ServiceLifetime.Singleton)
                    .AddReplayProtection(),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });

        using HttpResponseMessage original = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        using HttpRequestMessage replay = Assert.Single(capture.Requests).ToRequestMessage();
        replay.Headers.Remove(SafetalkHeaderNames.ClientId);
        replay.Headers.TryAddWithoutValidation(SafetalkHeaderNames.ClientId, spelling);
        using HttpClient attacker = server.CreateUnsignedClient();
        using HttpResponseMessage replayed = await attacker.SendAsync(replay, ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        replayed.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
        Assert.Equal(spelling, server.ValidationResults.Last().ClientId);
    }

    /// <summary>
    /// The in-memory cache purges expired entries on a timer driven by the server's <see cref="TimeProvider"/>, and
    /// never before the request timestamp has left the acceptance window: a replay after the purge is rejected as
    /// expired, not accepted.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task InMemoryReplayCache_PurgesEntriesAfterTheWindow_AndReplayAfterThePurgeIsStillRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        var serverClock = new FakeTimeProvider(Now);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { TimeProvider = serverClock, ConfigureHmac = hmac => hmac.AddReplayProtection() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(Now), HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        var cache = Assert.IsType<InMemoryHmacReplayCache>(server.Services.GetRequiredService<IHmacReplayCache>());

        using HttpResponseMessage original = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        int afterRequest = cache.Count;

        // Last accepted second of the timestamp: the entry must still be there after any number of purges.
        serverClock.Advance(HmacServerOptions.DefaultAllowedClockSkew);
        int atWindowEnd = cache.Count;
        using HttpResponseMessage replayInWindow = await ReplayAsync(server, capture.Requests.Single(), ct);
        HmacValidationFailure inWindowFailure = server.LastFailure;

        // Past the window, the 30 s margin and one more purge interval.
        serverClock.Advance(TimeSpan.FromSeconds(1) + TimeSpan.FromSeconds(30) + InMemoryHmacReplayCache.CleanupInterval);
        int afterPurge = cache.Count;
        using HttpResponseMessage replayAfterPurge = await ReplayAsync(server, capture.Requests.Single(), ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        Assert.Equal(1, afterRequest);
        Assert.Equal(1, atWindowEnd);
        replayInWindow.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, inWindowFailure);
        Assert.Equal(0, afterPurge);
        replayAfterPurge.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayCacheRejectingTheEntry_FailsTheRequestClosed(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection<AlwaysFullReplayCache>() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
    }

    private static async Task<HttpResponseMessage> ReplayAsync(SafetalkServer server, CapturedRequest captured, CancellationToken cancellationToken)
    {
        using HttpClient attacker = server.CreateUnsignedClient();
        using HttpRequestMessage replay = captured.ToRequestMessage();
        // The default completion option buffers the response content, so it outlives the attacker's client.
        return await attacker.SendAsync(replay, cancellationToken);
    }

    /// <summary>A secret store with a case-insensitive key lookup (like a SQL Server default collation).</summary>
    private sealed class CaseInsensitiveSecretProvider : IHmacSecretProvider
    {
        private readonly Dictionary<string, string> _secrets = new(TestCredentials.All, StringComparer.OrdinalIgnoreCase);

        public ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(_secrets.GetValueOrDefault(clientId));
    }

    /// <summary>A shared store that is unavailable or refuses writes: the validator must not accept the request.</summary>
    private sealed class AlwaysFullReplayCache : IHmacReplayCache
    {
        public ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(false);
    }
}
