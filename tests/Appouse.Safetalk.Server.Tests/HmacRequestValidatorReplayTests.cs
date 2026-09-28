using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRequestValidatorReplayTests
{
    private static readonly TimeSpan Margin = TimeSpan.FromSeconds(30);

    private readonly ValidatorHarness _harness = new();

    public static TheoryData<int> LastSecondOfWindowMilliseconds { get; } = new(300_000, 300_500, 300_999);

    [Fact]
    public async Task ValidateAsync_ReplayProtectionDisabled_AcceptsIdenticalRequestTwice()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;

        HmacValidationResult first = await _harness.ValidateAsync(request.Build(signature));
        HmacValidationResult second = await _harness.ValidateAsync(request.Build(signature));

        Assert.True(first.Succeeded);
        Assert.True(second.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtectionEnabled_RejectsIdenticalRequest()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;

        HmacValidationResult first = await _harness.ValidateAsync(request.Build(signature));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature));

        Assert.True(first.Succeeded);
        Assert.False(replay.Succeeded);
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
        Assert.Equal(TestCredentials.ClientId, replay.ClientId);
    }

    [Fact]
    public async Task ValidateAsync_ReplayWithUpperCaseHexOfSameSignature_ReturnsReplayDetected()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;

        HmacValidationResult first = await _harness.ValidateAsync(request.Build(signature));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature.ToUpperInvariant()));

        Assert.True(first.Succeeded);
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
    }

    [Fact]
    public async Task ValidateAsync_ReplayWithMixedCaseHexOfSameSignature_ReturnsReplayDetected()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        string mixedCase = string.Concat(signature.Select((c, i) => i % 2 == 0 ? char.ToUpperInvariant(c) : c));

        HmacValidationResult first = await _harness.ValidateAsync(request.Build(signature.ToUpperInvariant()));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(mixedCase));

        Assert.True(first.Succeeded);
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
    }

    [Fact]
    public async Task ValidateAsync_SameContentWithDifferentTimestamps_AcceptsBoth()
    {
        _harness.Options.EnableReplayProtection = true;

        HmacValidationResult first = await _harness.ValidateAsync(_harness.NewRequest().Build());
        _harness.Time.Advance(TimeSpan.FromSeconds(1));
        HmacValidationResult second = await _harness.ValidateAsync(_harness.NewRequest().Build());

        Assert.True(first.Succeeded);
        Assert.True(second.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_DifferentRequestsInSameSecond_AcceptsBoth()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder firstRequest = _harness.NewRequest();
        SignedRequestBuilder secondRequest = _harness.NewRequest();
        secondRequest.Query = "?id=6";

        HmacValidationResult first = await _harness.ValidateAsync(firstRequest.Build());
        HmacValidationResult second = await _harness.ValidateAsync(secondRequest.Build());

        Assert.True(first.Succeeded);
        Assert.True(second.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_ReplayShortlyBeforeWindowCloses_ReturnsReplayDetected()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await _harness.ValidateAsync(request.Build(signature))).Succeeded);

        _harness.Time.Advance(TimeSpan.FromSeconds(299));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
    }

    [Theory]
    [MemberData(nameof(LastSecondOfWindowMilliseconds))]
    public async Task ValidateAsync_FreshRequestAtEndOfClockSkewWindow_IsAccepted(int elapsedMilliseconds)
    {
        // Establishes the acceptance window: a timestamp T is accepted until the clock reaches T + skew + 1 s.
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;

        _harness.Time.Advance(TimeSpan.FromMilliseconds(elapsedMilliseconds));
        HmacValidationResult result = await _harness.ValidateAsync(request.Build(signature));

        Assert.True(result.Succeeded);
    }

    [Theory]
    [MemberData(nameof(LastSecondOfWindowMilliseconds))]
    public async Task ValidateAsync_ReplayDuringLastSecondOfWindow_ReturnsReplayDetected(int elapsedMilliseconds)
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await _harness.ValidateAsync(request.Build(signature))).Succeeded);

        _harness.Time.Advance(TimeSpan.FromMilliseconds(elapsedMilliseconds));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature));

        // The timestamp is still inside the accepted window at this instant (see the test above), so the replay
        // cache must still remember the signature: an attacker must not be able to replay the captured request.
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
    }

    [Theory]
    [InlineData(301_000)]
    [InlineData(301_001)]
    [InlineData(330_999)]
    [InlineData(331_000)]
    [InlineData(3_600_000)]
    public async Task ValidateAsync_ReplayOnceWindowClosed_ReturnsTimestampOutOfRange(int elapsedMilliseconds)
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await _harness.ValidateAsync(request.Build(signature))).Succeeded);

        _harness.Time.Advance(TimeSpan.FromMilliseconds(elapsedMilliseconds));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, replay.Failure);
    }

    [Fact]
    public async Task ValidateAsync_FutureTimestampReplayedAtEndOfItsWindow_ReturnsReplayDetected()
    {
        // A timestamp 5 minutes ahead of the server clock stays acceptable for 10 minutes (+1 s).
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow + 300);
        string signature = request.Signature;
        Assert.True((await _harness.ValidateAsync(request.Build(signature))).Succeeded);

        _harness.Time.Advance(TimeSpan.FromMilliseconds(600_999));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature));
        _harness.Time.Advance(TimeSpan.FromMilliseconds(1));
        HmacValidationResult late = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, late.Failure);
    }

    [Fact]
    public async Task ValidateAsync_OldestAcceptableTimestamp_IsStillProtectedDuringItsLastSecond()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow - 300);
        string signature = request.Signature;
        Assert.True((await _harness.ValidateAsync(request.Build(signature))).Succeeded);

        _harness.Time.Advance(TimeSpan.FromMilliseconds(999));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature));
        _harness.Time.Advance(TimeSpan.FromMilliseconds(1));
        HmacValidationResult late = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, late.Failure);
    }

    [Fact]
    public async Task ValidateAsync_ReplayAcrossPurges_IsDetectedUntilWindowCloses()
    {
        // The in-memory cache purges every minute; the entry must survive every purge while the timestamp is fresh.
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await _harness.ValidateAsync(request.Build(signature))).Succeeded);

        for (int minute = 1; minute <= 5; minute++)
        {
            _harness.Time.Advance(TimeSpan.FromMinutes(1));
            HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature));
            Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
        }
    }

    [Fact]
    public async Task ValidateAsync_RejectedRequest_DoesNotConsumeSignature()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        byte[] genuineBody = request.Body;

        // An attacker reuses the captured signature with a tampered body first.
        request.Body = """{"orderId":5,"amount":0}"""u8.ToArray();
        HmacValidationResult tampered = await _harness.ValidateAsync(request.Build(signature));
        request.Body = genuineBody;
        HmacValidationResult genuine = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.InvalidSignature, tampered.Failure);
        Assert.True(genuine.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtectionEnabled_RecordsLowerCaseSignatureWithExactExpiryAndToken()
    {
        var replayCache = new RecordingReplayCache();
        var harness = new ValidatorHarness(replayCache: replayCache);
        harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;
        long timestamp = harness.UnixNow;

        HmacValidationResult result = await harness.ValidateAsync(request.Build(signature.ToUpperInvariant()));

        Assert.True(result.Succeeded);
        ReplayCacheCall call = Assert.Single(replayCache.Calls);
        Assert.Equal(signature, call.Signature);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(timestamp + 300 + 1) + Margin, call.ExpiresAt);
        Assert.Equal(TestContext.Current.CancellationToken, call.CancellationToken);
    }

    [Theory]
    [InlineData(0, 300.0)]
    [InlineData(-300, 300.0)]
    [InlineData(300, 300.0)]
    [InlineData(-17, 300.0)]
    [InlineData(0, 90.9)]
    [InlineData(-90, 90.9)]
    [InlineData(0, 1.0)]
    [InlineData(-1, 1.0)]
    [InlineData(0, 86_400.0)]
    public async Task ValidateAsync_ReplayEntryExpiry_IsEndOfAcceptanceWindowPlusMargin(int timestampOffsetSeconds, double clockSkewSeconds)
    {
        var replayCache = new RecordingReplayCache();
        var harness = new ValidatorHarness(replayCache: replayCache);
        harness.Options.EnableReplayProtection = true;
        harness.Options.AllowedClockSkew = TimeSpan.FromSeconds(clockSkewSeconds);
        long timestamp = harness.UnixNow + timestampOffsetSeconds;
        SignedRequestBuilder request = harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(timestamp);

        HmacValidationResult result = await harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
        ReplayCacheCall call = Assert.Single(replayCache.Calls);
        long tolerance = (long)clockSkewSeconds;
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(timestamp + tolerance + 1) + Margin, call.ExpiresAt);
        Assert.True(call.ExpiresAt > harness.Time.GetUtcNow(), "The validator must always pass an expiry in the future.");
    }

    [Fact]
    public void ReplayEntryExpirationMargin_IsThirtySeconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(30), HmacRequestValidator.ReplayEntryExpirationMargin);
    }

    [Fact]
    public async Task ValidateAsync_ReplayCacheReportsSignatureAsSeen_ReturnsReplayDetected()
    {
        var harness = new ValidatorHarness(replayCache: new RecordingReplayCache(firstSeen: false));
        harness.Options.EnableReplayProtection = true;

        HmacValidationResult result = await harness.ValidateAsync(harness.NewRequest().Build());

        Assert.Equal(HmacValidationFailure.ReplayDetected, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtectionDisabled_DoesNotUseReplayCache()
    {
        var replayCache = new RecordingReplayCache(firstSeen: false);
        var harness = new ValidatorHarness(replayCache: replayCache);

        HmacValidationResult result = await harness.ValidateAsync(harness.NewRequest().Build());

        Assert.True(result.Succeeded);
        Assert.Empty(replayCache.Calls);
    }

    [Fact]
    public async Task ValidateAsync_InvalidSignature_DoesNotUseReplayCache()
    {
        var replayCache = new RecordingReplayCache();
        var harness = new ValidatorHarness(replayCache: replayCache);
        harness.Options.EnableReplayProtection = true;

        HmacValidationResult result = await harness.ValidateAsync(
            harness.NewRequest().Build(new string('a', HmacSha256SignatureService.SignatureHexLength)));

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
        Assert.Empty(replayCache.Calls);
    }

    [Fact]
    public async Task ValidateAsync_BodyStallsPastWindow_WithReplayProtection_ReturnsTimestampOutOfRangeWithoutRecording()
    {
        var replayCache = new RecordingReplayCache();
        var harness = new ValidatorHarness(replayCache: replayCache);
        harness.Options.EnableReplayProtection = true;
        DefaultHttpContext context = BuildStallingRequest(harness, TimeSpan.FromSeconds(301));

        HmacValidationResult result = await harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Empty(replayCache.Calls);
    }

    [Fact]
    public async Task ValidateAsync_BodyStallsPastWindow_WithoutReplayProtection_IsAccepted()
    {
        // Without replay protection freshness is only checked when the request arrives.
        DefaultHttpContext context = BuildStallingRequest(_harness, TimeSpan.FromSeconds(301));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(1_000)]
    [InlineData(300_000)]
    [InlineData(300_999)]
    public async Task ValidateAsync_BodyStallsWithinWindow_IsAcceptedAndRecordedWithFutureExpiry(int stallMilliseconds)
    {
        var replayCache = new RecordingReplayCache();
        var harness = new ValidatorHarness(replayCache: replayCache);
        harness.Options.EnableReplayProtection = true;
        long timestamp = harness.UnixNow;
        DefaultHttpContext context = BuildStallingRequest(harness, TimeSpan.FromMilliseconds(stallMilliseconds));

        HmacValidationResult result = await harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
        ReplayCacheCall call = Assert.Single(replayCache.Calls);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(timestamp + 301) + Margin, call.ExpiresAt);
        Assert.True(call.ExpiresAt - harness.Time.GetUtcNow() > Margin - TimeSpan.FromSeconds(1));
    }

    [Theory]
    [InlineData(301_000)]
    [InlineData(301_001)]
    public async Task ValidateAsync_BodyStallsJustPastWindow_ReturnsTimestampOutOfRange(int stallMilliseconds)
    {
        _harness.Options.EnableReplayProtection = true;
        DefaultHttpContext context = BuildStallingRequest(_harness, TimeSpan.FromMilliseconds(stallMilliseconds));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_ReplayStartedInLastSecondAndStalledUntilEntryPurged_IsRejected()
    {
        // The attack the second freshness check prevents: the replay passes the first freshness check, then trickles
        // its body in until the genuine request's cache entry has expired and been purged.
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await _harness.ValidateAsync(request.Build(signature))).Succeeded);

        _harness.Time.Advance(TimeSpan.FromMilliseconds(300_500));
        DefaultHttpContext replay = request.Build(signature);
        replay.Request.Body = new CallbackReadStream(request.Body, 4, read =>
        {
            if (read == 0)
            {
                _harness.Time.Advance(InMemoryHmacReplayCache.CleanupInterval + Margin);
            }
        });

        HmacValidationResult result = await _harness.ValidateAsync(replay);

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
    }

    [Theory]
    [InlineData("PARTNER-A")]
    [InlineData("Partner-A")]
    [InlineData("partner-A")]
    public async Task ValidateAsync_ReplayUnderClientIdCaseVariantWithCaseInsensitiveProvider_ReturnsReplayDetected(string variant)
    {
        var harness = new ValidatorHarness(new RecordingSecretProvider(CaseInsensitiveLookup));
        harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;

        HmacValidationResult first = await harness.ValidateAsync(request.Build(signature));
        request.ClientId = variant;
        HmacValidationResult replay = await harness.ValidateAsync(request.Build(signature));

        Assert.True(first.Succeeded);
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
        Assert.Equal(variant, replay.ClientId);
    }

    [Fact]
    public async Task ValidateAsync_VariantSpellingAcceptedFirst_OriginalSpellingIsThenAReplay()
    {
        var harness = new ValidatorHarness(new RecordingSecretProvider(CaseInsensitiveLookup));
        harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;

        request.ClientId = "PARTNER-A";
        HmacValidationResult first = await harness.ValidateAsync(request.Build(signature));
        request.ClientId = TestCredentials.ClientId;
        HmacValidationResult replay = await harness.ValidateAsync(request.Build(signature));

        Assert.True(first.Succeeded);
        Assert.Equal("PARTNER-A", first.ClientId);
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
    }

    [Fact]
    public async Task ValidateAsync_SameSignatureUnderAnotherClientSharingTheSecret_ReturnsReplayDetected()
    {
        var harness = new ValidatorHarness(new RecordingSecretProvider(_ => TestCredentials.Secret));
        harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;

        HmacValidationResult first = await harness.ValidateAsync(request.Build(signature));
        request.ClientId = TestCredentials.OtherClientId;
        HmacValidationResult replay = await harness.ValidateAsync(request.Build(signature));

        Assert.True(first.Succeeded);
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
    }

    [Fact]
    public async Task ValidateAsync_ClockSkewIncreasedAfterAcceptance_WindowStaysCappedSoTheCapturedRequestCannotBeReplayed()
    {
        // AllowedClockSkew is reloadable (AddHmacServer(IConfiguration)). An entry recorded under a 1 minute window
        // expires after ts + 91 s; were the window widened to 5 minutes at runtime, the same timestamp would be
        // accepted again until ts + 301 s. The validator registered by AddHmacServer() (internal constructor with the
        // clock skew tracker) therefore keeps the window captured at start-up while replay protection is on.
        var harness = new ValidatorHarness(clockSkewTracker: new HmacClockSkewTracker(TimeSpan.FromMinutes(1)));
        harness.Options.EnableReplayProtection = true;
        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(1);
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await harness.ValidateAsync(request.Build(signature))).Succeeded);

        harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(5);
        harness.Time.Advance(TimeSpan.FromSeconds(30));
        HmacValidationResult replayWhileRemembered = await harness.ValidateAsync(request.Build(signature));
        harness.Time.Advance(TimeSpan.FromSeconds(90));
        HmacValidationResult replayAfterEntryExpired = await harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.ReplayDetected, replayWhileRemembered.Failure);
        Assert.False(replayAfterEntryExpired.Succeeded, "A captured request was replayed after the clock skew window was widened.");
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, replayAfterEntryExpired.Failure);
    }

    [Fact]
    public async Task ValidateAsync_PublicConstructorWithoutTracker_UsesTheConfiguredClockSkewAsIs()
    {
        // The public constructor has no clock skew tracker: a widened window applies to the next request.
        _harness.Options.EnableReplayProtection = true;
        _harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(1);
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow - 120);
        HmacValidationResult beforeWidening = await _harness.ValidateAsync(request.Build());

        _harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(5);
        HmacValidationResult afterWidening = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, beforeWidening.Failure);
        Assert.True(afterWidening.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_ClockSkewReducedAfterAcceptance_ReplayIsRejected()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await _harness.ValidateAsync(request.Build(signature))).Succeeded);

        _harness.Options.AllowedClockSkew = TimeSpan.FromMinutes(1);
        _harness.Time.Advance(TimeSpan.FromSeconds(30));
        HmacValidationResult replayInsideNewWindow = await _harness.ValidateAsync(request.Build(signature));
        _harness.Time.Advance(TimeSpan.FromMinutes(1));
        HmacValidationResult replayOutsideNewWindow = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.ReplayDetected, replayInsideNewWindow.Failure);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, replayOutsideNewWindow.Failure);
    }

    [Fact]
    public async Task ValidateAsync_ReplayProtectionEnabledAtRuntime_OnlyRequestsAcceptedAfterwardsAreRemembered()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;

        HmacValidationResult unprotected = await _harness.ValidateAsync(request.Build(signature));
        _harness.Options.EnableReplayProtection = true;
        HmacValidationResult firstProtected = await _harness.ValidateAsync(request.Build(signature));
        HmacValidationResult replay = await _harness.ValidateAsync(request.Build(signature));

        Assert.True(unprotected.Succeeded);
        Assert.True(firstProtected.Succeeded);
        Assert.Equal(HmacValidationFailure.ReplayDetected, replay.Failure);
    }

    [Fact]
    public async Task ValidateAsync_ConcurrentIdenticalRequests_AcceptsExactlyOne()
    {
        _harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        DefaultHttpContext[] contexts = [.. Enumerable.Range(0, 32).Select(_ => request.Build(signature))];
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        Task<HmacValidationResult>[] validations =
        [
            .. contexts.Select(context => Task.Run(
                async () =>
                {
                    await start.Task;
                    return await _harness.Validator.ValidateAsync(context, cancellationToken);
                },
                cancellationToken)),
        ];
        start.SetResult();
        HmacValidationResult[] results = await Task.WhenAll(validations);

        Assert.Single(results, result => result.Succeeded);
        Assert.All(
            results.Where(result => !result.Succeeded),
            result => Assert.Equal(HmacValidationFailure.ReplayDetected, result.Failure));
    }

    [Fact]
    public async Task ValidateAsync_ConcurrentReplaysUnderDifferentClientIdSpellings_AcceptsExactlyOne()
    {
        var harness = new ValidatorHarness(new RecordingSecretProvider(CaseInsensitiveLookup));
        harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;
        string[] spellings = ["partner-a", "PARTNER-A", "Partner-A", "pArTnEr-A"];
        DefaultHttpContext[] contexts =
        [
            .. Enumerable.Range(0, 32).Select(i =>
            {
                request.ClientId = spellings[i % spellings.Length];
                return request.Build(signature);
            }),
        ];
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        Task<HmacValidationResult>[] validations =
        [
            .. contexts.Select(context => Task.Run(
                async () =>
                {
                    await start.Task;
                    return await harness.Validator.ValidateAsync(context, cancellationToken);
                },
                cancellationToken)),
        ];
        start.SetResult();
        HmacValidationResult[] results = await Task.WhenAll(validations);

        Assert.Single(results, result => result.Succeeded);
    }

    private static string? CaseInsensitiveLookup(string clientId) =>
        string.Equals(clientId, TestCredentials.ClientId, StringComparison.OrdinalIgnoreCase) ? TestCredentials.Secret : null;

    private static DefaultHttpContext BuildStallingRequest(ValidatorHarness harness, TimeSpan stall)
    {
        SignedRequestBuilder request = harness.NewRequest();
        DefaultHttpContext context = request.Build();
        context.Request.Body = new CallbackReadStream(request.Body, 4, read =>
        {
            if (read == 0)
            {
                harness.Time.Advance(stall);
            }
        });
        return context;
    }
}
