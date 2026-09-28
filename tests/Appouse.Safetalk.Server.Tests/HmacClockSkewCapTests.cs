using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// While replay protection is on, the validator registered by <c>AddHmacServer()</c> enforces
/// <c>min(configured AllowedClockSkew, value captured at first resolution)</c> and keeps replay entries for the
/// captured window: narrowing applies immediately, widening only after a restart (logged once).
/// </summary>
public sealed class HmacClockSkewCapTests : IDisposable
{
    private const int WideningDeferredEventId = 3;
    private static readonly TimeSpan Margin = TimeSpan.FromSeconds(30);

    private readonly LogCollector _logs = new();

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public void Dispose() => _logs.Dispose();

    [Theory]
    [InlineData(60, 60)]
    [InlineData(59, 59)]
    [InlineData(1, 1)]
    [InlineData(61, 60)]
    [InlineData(86_400, 60)]
    public void Tracker_ReturnsTheConfiguredValueUpToTheCap(int configuredSeconds, int expectedSeconds)
    {
        var tracker = new HmacClockSkewTracker(TimeSpan.FromMinutes(1));

        TimeSpan effective = tracker.GetEffectiveClockSkew(TimeSpan.FromSeconds(configuredSeconds), out bool firstWideningAttempt);

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), effective);
        Assert.Equal(configuredSeconds > 60, firstWideningAttempt);
        Assert.Equal(TimeSpan.FromMinutes(1), tracker.MaxClockSkew);
    }

    [Fact]
    public void Tracker_ReportsOnlyTheFirstWideningAttempt()
    {
        var tracker = new HmacClockSkewTracker(TimeSpan.FromMinutes(1));

        tracker.GetEffectiveClockSkew(TimeSpan.FromMinutes(5), out bool first);
        tracker.GetEffectiveClockSkew(TimeSpan.FromMinutes(1), out bool notWidening);
        tracker.GetEffectiveClockSkew(TimeSpan.FromMinutes(10), out bool second);

        Assert.True(first);
        Assert.False(notWidening);
        Assert.False(second);
    }

    [Fact]
    public async Task Tracker_ConcurrentWideningAttempts_ReportExactlyOnce()
    {
        var tracker = new HmacClockSkewTracker(TimeSpan.FromMinutes(1));
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        Task<bool>[] attempts =
        [
            .. Enumerable.Range(0, 64).Select(_ => Task.Run(
                async () =>
                {
                    await start.Task;
                    tracker.GetEffectiveClockSkew(TimeSpan.FromMinutes(5), out bool first);
                    return first;
                },
                CancellationToken)),
        ];
        start.SetResult();
        bool[] results = await Task.WhenAll(attempts);

        Assert.Single(results, first => first);
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtection_NarrowingAppliesImmediatelyWithoutWarning()
    {
        ValidatorHarness harness = CreateHarness(captured: TimeSpan.FromMinutes(5));
        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(5);
        HmacValidationResult beforeNarrowing = await harness.ValidateAsync(RequestAged(harness, seconds: 120).Build());

        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(1);
        HmacValidationResult afterNarrowing = await harness.ValidateAsync(RequestAged(harness, seconds: 120, query: "?n=2").Build());
        HmacValidationResult withinNarrowedWindow = await harness.ValidateAsync(RequestAged(harness, seconds: 60, query: "?n=3").Build());

        Assert.True(beforeNarrowing.Succeeded);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, afterNarrowing.Failure);
        Assert.True(withinNarrowedWindow.Succeeded);
        Assert.Empty(_logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-45)]
    [InlineData(45)]
    public async Task ValidateAsync_ReplayProtectionWithNarrowedWindow_KeepsEntriesForTheCapturedWindow(int offsetSeconds)
    {
        var replayCache = new RecordingReplayCache();
        ValidatorHarness harness = CreateHarness(captured: TimeSpan.FromMinutes(5), replayCache);
        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(1);
        long timestamp = harness.UnixNow + offsetSeconds;
        SignedRequestBuilder request = harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(timestamp);

        HmacValidationResult result = await harness.ValidateAsync(request.Build());

        // A later reload may widen the window back up to the captured 5 minutes: the entry must outlive that window.
        Assert.True(result.Succeeded);
        ReplayCacheCall call = Assert.Single(replayCache.Calls);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(timestamp + 300 + 1) + Margin, call.ExpiresAt);
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtection_NarrowThenWidenBackToCapturedValue_AppliesWithoutWarning()
    {
        ValidatorHarness harness = CreateHarness(captured: TimeSpan.FromMinutes(5));
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;
        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(1);
        Assert.True((await harness.ValidateAsync(request.Build(signature))).Succeeded);

        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(5);
        harness.Time.Advance(TimeSpan.FromMinutes(4));
        HmacValidationResult replay = await harness.ValidateAsync(request.Build(signature));
        HmacValidationResult fresh = await harness.ValidateAsync(RequestAged(harness, seconds: 290, query: "?n=2").Build());

        // The entry recorded under the 1 minute window was kept for the captured 5 minutes.
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
        Assert.True(fresh.Succeeded);
        Assert.Empty(_logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtection_WideningBeyondCapturedValueIsCappedAndLoggedOnce()
    {
        ValidatorHarness harness = CreateHarness(captured: TimeSpan.FromMinutes(1));
        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(5);

        HmacValidationResult[] aged =
        [
            await harness.ValidateAsync(RequestAged(harness, seconds: 120, query: "?n=1").Build()),
            await harness.ValidateAsync(RequestAged(harness, seconds: 61, query: "?n=2").Build()),
            await harness.ValidateAsync(RequestAged(harness, seconds: -61, query: "?n=3").Build()),
        ];
        HmacValidationResult withinCap = await harness.ValidateAsync(RequestAged(harness, seconds: 60, query: "?n=4").Build());

        Assert.All(aged, result => Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure));
        Assert.True(withinCap.Succeeded);
        LogRecord warning = Assert.Single(_logs.Find<HmacRequestValidator>(WideningDeferredEventId));
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Equal(TimeSpan.FromMinutes(5), warning.Properties["Configured"]);
        Assert.Equal(TimeSpan.FromMinutes(1), warning.Properties["Effective"]);
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtection_ReplayAfterWideningIsStillDetected()
    {
        ValidatorHarness harness = CreateHarness(captured: TimeSpan.FromMinutes(1));
        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(1);
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await harness.ValidateAsync(request.Build(signature))).Succeeded);

        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(5);
        harness.Time.Advance(TimeSpan.FromSeconds(59));
        HmacValidationResult replayInsideWindow = await harness.ValidateAsync(request.Build(signature));
        harness.Time.Advance(TimeSpan.FromSeconds(33)); // Past ts + 61 s + 30 s margin: the entry has expired.
        HmacValidationResult replayAfterEntryExpired = await harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.ReplayDetected, replayInsideWindow.Failure);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, replayAfterEntryExpired.Failure);
        Assert.Single(_logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    [Fact]
    public async Task ValidateAsync_WithoutReplayProtection_WideningAppliesImmediatelyWithoutWarning()
    {
        ValidatorHarness harness = CreateHarness(captured: TimeSpan.FromMinutes(1));
        harness.Options.EnableReplayProtection = false;
        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(5);

        HmacValidationResult result = await harness.ValidateAsync(RequestAged(harness, seconds: 240).Build());

        Assert.True(result.Succeeded);
        Assert.Empty(_logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtectionEnabledAtRuntimeAfterWidening_CapsAtTheCapturedValue()
    {
        ValidatorHarness harness = CreateHarness(captured: TimeSpan.FromMinutes(1));
        harness.Options.EnableReplayProtection = false;
        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(5);
        HmacValidationResult unprotected = await harness.ValidateAsync(RequestAged(harness, seconds: 120).Build());

        harness.Options.EnableReplayProtection = true;
        HmacValidationResult protectedResult = await harness.ValidateAsync(RequestAged(harness, seconds: 120, query: "?n=2").Build());

        Assert.True(unprotected.Succeeded);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, protectedResult.Failure);
        Assert.Single(_logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    [Fact]
    public async Task DependencyInjection_ReloadWideningWithReplayProtection_IsCappedAndLoggedOnce()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Safetalk:AllowedClockSkew", "00:01:00"),
            new("Safetalk:EnableReplayProtection", "true"),
            new("Safetalk:Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
        ]);
        var time = new FakeTimeProvider(TestCredentials.Now);
        await using ServiceProvider provider = BuildProvider(root, time);
        long start = time.GetUtcNow().ToUnixTimeSeconds();
        HmacValidationResult first = await ValidateInNewScopeAsync(provider, new SignedRequestBuilder(start).Build());

        source.Update("Safetalk:AllowedClockSkew", "00:05:00");
        time.Advance(TimeSpan.FromMinutes(2));
        var aged = new SignedRequestBuilder(start) { Query = "?n=2" };
        HmacValidationResult afterWidening = await ValidateInNewScopeAsync(provider, aged.Build());
        HmacValidationResult again = await ValidateInNewScopeAsync(provider, new SignedRequestBuilder(start) { Query = "?n=3" }.Build());

        Assert.True(first.Succeeded);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, afterWidening.Failure);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, again.Failure);
        Assert.Single(_logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    [Fact]
    public async Task DependencyInjection_ReloadNarrowingWithReplayProtection_AppliesToTheNextRequest()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Safetalk:EnableReplayProtection", "true"),
            new("Safetalk:Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
        ]);
        var time = new FakeTimeProvider(TestCredentials.Now);
        await using ServiceProvider provider = BuildProvider(root, time);
        long now = time.GetUtcNow().ToUnixTimeSeconds();
        HmacValidationResult before = await ValidateInNewScopeAsync(provider, new SignedRequestBuilder(now - 120).Build());

        source.Update("Safetalk:AllowedClockSkew", "00:01:00");
        HmacValidationResult after = await ValidateInNewScopeAsync(provider, new SignedRequestBuilder(now - 120) { Query = "?n=2" }.Build());

        Assert.True(before.Succeeded);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, after.Failure);
    }

    [Fact]
    public async Task DependencyInjection_ReloadWideningWithoutReplayProtection_AppliesToTheNextRequest()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Safetalk:AllowedClockSkew", "00:01:00"),
            new("Safetalk:Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
        ]);
        var time = new FakeTimeProvider(TestCredentials.Now);
        await using ServiceProvider provider = BuildProvider(root, time);
        long now = time.GetUtcNow().ToUnixTimeSeconds();
        HmacValidationResult before = await ValidateInNewScopeAsync(provider, new SignedRequestBuilder(now - 120).Build());

        source.Update("Safetalk:AllowedClockSkew", "00:05:00");
        HmacValidationResult after = await ValidateInNewScopeAsync(provider, new SignedRequestBuilder(now - 120).Build());

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, before.Failure);
        Assert.True(after.Succeeded);
        Assert.Empty(_logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    [Theory]
    [InlineData(true, HttpStatusCode.Unauthorized)]
    [InlineData(false, HttpStatusCode.OK)]
    public async Task Pipeline_ClockSkewWidenedByReload_AppliesOnlyWithoutReplayProtection(bool replayProtection, HttpStatusCode expected)
    {
        var source = new ReloadableConfigurationSource(
        [
            new("Safetalk:AllowedClockSkew", "00:01:00"),
            new("Safetalk:EnableReplayProtection", replayProtection ? "true" : "false"),
            new("Safetalk:Clients:" + TestCredentials.ClientId, TestCredentials.Secret),
        ]);
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                builder.Logging.AddProvider(_logs);
                ((IConfigurationBuilder)builder.Configuration).Add(source);
                builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));
            },
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.MapGet("/b2b", (HttpContext context) => context.GetHmacClientId() ?? "anonymous");
            });
        using HttpResponseMessage warmUp = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b"));
        HttpRequestMessage aged = app.CreateSignedRequest(HttpMethod.Get, "/b2b?n=2");

        source.Provider.Update("Safetalk:AllowedClockSkew", "00:05:00");
        app.Time.Advance(TimeSpan.FromMinutes(2));
        using HttpResponseMessage response = await app.SendAsync(aged);

        Assert.Equal(HttpStatusCode.OK, warmUp.StatusCode);
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(replayProtection ? 1 : 0, _logs.Find<HmacRequestValidator>(WideningDeferredEventId).Count);
    }

    private static SignedRequestBuilder RequestAged(ValidatorHarness harness, int seconds, string query = "?id=5")
    {
        SignedRequestBuilder request = harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(harness.UnixNow - seconds);
        request.Query = query;
        return request;
    }

    private static async Task<HmacValidationResult> ValidateInNewScopeAsync(IServiceProvider provider, HttpContext context)
    {
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        IHmacRequestValidator validator = scope.ServiceProvider.GetRequiredService<IHmacRequestValidator>();
        return await validator.ValidateAsync(context, CancellationToken);
    }

    private ServiceProvider BuildProvider(IConfigurationRoot root, FakeTimeProvider time)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(_logs));
        services.AddSingleton<TimeProvider>(time);
        services.AddHmacServer(root.GetSection("Safetalk"));
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private ValidatorHarness CreateHarness(TimeSpan captured, IHmacReplayCache? replayCache = null)
    {
        var harness = new ValidatorHarness(
            replayCache: replayCache,
            clockSkewTracker: new HmacClockSkewTracker(captured),
            logger: _logs.CreateLogger<HmacRequestValidator>());
        harness.Options.EnableReplayProtection = true;
        return harness;
    }
}
