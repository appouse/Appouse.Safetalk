using System.Globalization;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Server.Tests;

public sealed class InMemoryHmacReplayCacheTests : IDisposable
{
    private const string Signature = "4f3c2a1b0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b";
    private const string OtherSignature = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private readonly FakeTimeProvider _time = new(TestCredentials.Now);
    private readonly InMemoryHmacReplayCache _cache;

    public InMemoryHmacReplayCacheTests()
    {
        _cache = new InMemoryHmacReplayCache(_time);
    }

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public void Dispose() => _cache.Dispose();

    [Fact]
    public async Task TryAddAsync_FirstTime_ReturnsTrue()
    {
        bool added = await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(5)), CancellationToken);

        Assert.True(added);
        Assert.Equal(1, _cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_SameSignatureAgain_ReturnsFalse()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(5)), CancellationToken);

        bool addedAgain = await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(5)), CancellationToken);

        Assert.False(addedAgain);
        Assert.Equal(1, _cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_SameSignatureWithLaterExpiry_ReturnsFalseAndKeepsOriginalExpiry()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);
        Assert.False(await _cache.TryAddAsync(Signature, In(TimeSpan.FromDays(1)), CancellationToken));

        _time.Advance(TimeSpan.FromSeconds(10));

        // The replayed call must not have extended the entry: it expired at +10 s and can be recorded again.
        Assert.True(await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_DifferentSignatures_AreIndependent()
    {
        bool first = await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(5)), CancellationToken);
        bool second = await _cache.TryAddAsync(OtherSignature, In(TimeSpan.FromMinutes(5)), CancellationToken);

        Assert.True(first);
        Assert.True(second);
        Assert.Equal(2, _cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_SignaturesDifferingOnlyByCase_AreDistinctEntries()
    {
        // The cache compares ordinally; normalizing the hex casing is the validator's job.
        bool lower = await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(5)), CancellationToken);
        bool upper = await _cache.TryAddAsync(Signature.ToUpperInvariant(), In(TimeSpan.FromMinutes(5)), CancellationToken);

        Assert.True(lower);
        Assert.True(upper);
    }

    [Fact]
    public async Task TryAddAsync_BeforeExpiry_StillReturnsFalse()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);
        _time.Advance(TimeSpan.FromSeconds(9));

        bool added = await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);

        Assert.False(added);
    }

    [Fact]
    public async Task TryAddAsync_OneTickBeforeExpiry_StillReturnsFalse()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);
        _time.Advance(TimeSpan.FromSeconds(10) - TimeSpan.FromTicks(1));

        Assert.False(await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_ExactlyAtExpiry_EntryIsExpiredAndCanBeAddedAgain()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);
        _time.Advance(TimeSpan.FromSeconds(10));

        Assert.True(await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_ExpiredEntryNotYetPurged_CanBeAddedAgain()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);
        _time.Advance(TimeSpan.FromSeconds(11)); // Expired, but before the first purge (CleanupInterval).

        bool added = await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);
        bool addedAgain = await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);

        Assert.True(added);
        Assert.False(addedAgain); // The refreshed entry is protected again.
        Assert.Equal(1, _cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_ExpiresAtInThePast_FailsClosedWithoutRecording()
    {
        bool added = await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(-1)), CancellationToken);

        Assert.False(added);
        Assert.Equal(0, _cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_ExpiresAtEqualToNow_FailsClosed()
    {
        bool added = await _cache.TryAddAsync(Signature, _time.GetUtcNow(), CancellationToken);

        Assert.False(added);
        Assert.Equal(0, _cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_ExpiresAtOneTickInTheFuture_IsRecorded()
    {
        bool added = await _cache.TryAddAsync(Signature, In(TimeSpan.FromTicks(1)), CancellationToken);

        Assert.True(added);
        Assert.False(await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(1)), CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_ExpiresAtMinValue_FailsClosed()
    {
        Assert.False(await _cache.TryAddAsync(Signature, DateTimeOffset.MinValue, CancellationToken));
        Assert.Equal(0, _cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_ExpiresAtMaxValue_IsRecordedAndNeverPurged()
    {
        Assert.True(await _cache.TryAddAsync(Signature, DateTimeOffset.MaxValue, CancellationToken));

        _time.Advance(TimeSpan.FromDays(3));

        Assert.Equal(1, _cache.Count);
        Assert.False(await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(1)), CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_PastExpiryForExpiredUnpurgedEntry_FailsClosedAndDoesNotRefreshIt()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);
        _time.Advance(TimeSpan.FromSeconds(20));

        bool stale = await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(-5)), CancellationToken);
        bool fresh = await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(10)), CancellationToken);

        Assert.False(stale);
        Assert.True(fresh);
    }

    [Fact]
    public async Task TryAddAsync_PastExpiryForLiveEntry_ReturnsFalseAndKeepsEntry()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(5)), CancellationToken);

        Assert.False(await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(-1)), CancellationToken));
        Assert.False(await _cache.TryAddAsync(Signature, In(TimeSpan.FromMinutes(5)), CancellationToken));
    }

    [Fact]
    public async Task Timer_BeforeCleanupInterval_DoesNotPurge()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(1)), CancellationToken);

        _time.Advance(InMemoryHmacReplayCache.CleanupInterval - TimeSpan.FromTicks(1));

        Assert.Equal(1, _cache.Count);
    }

    [Fact]
    public async Task Timer_AtCleanupInterval_PurgesExpiredEntriesWithoutAnyFurtherCall()
    {
        await _cache.TryAddAsync("expires-soon", In(TimeSpan.FromSeconds(10)), CancellationToken);
        await _cache.TryAddAsync("expires-late", In(TimeSpan.FromMinutes(10)), CancellationToken);

        _time.Advance(TimeSpan.FromSeconds(30));
        await _cache.TryAddAsync("added-at-30s", In(TimeSpan.FromMinutes(5)), CancellationToken);
        Assert.Equal(3, _cache.Count); // Expired entry still held: no purge before CleanupInterval.

        _time.Advance(InMemoryHmacReplayCache.CleanupInterval - TimeSpan.FromSeconds(30));

        Assert.Equal(2, _cache.Count);
        Assert.True(await _cache.TryAddAsync("expires-soon", In(TimeSpan.FromMinutes(5)), CancellationToken));
        Assert.False(await _cache.TryAddAsync("expires-late", In(TimeSpan.FromMinutes(5)), CancellationToken));
    }

    [Fact]
    public async Task Timer_PurgesEntryExpiringExactlyAtPurgeTimeButKeepsLaterOne()
    {
        TimeSpan interval = InMemoryHmacReplayCache.CleanupInterval;
        await _cache.TryAddAsync("expires-at-purge", In(interval), CancellationToken);
        await _cache.TryAddAsync("expires-one-tick-later", In(interval + TimeSpan.FromTicks(1)), CancellationToken);

        _time.Advance(interval);

        Assert.Equal(1, _cache.Count);
        Assert.True(await _cache.TryAddAsync("expires-at-purge", In(TimeSpan.FromMinutes(1)), CancellationToken));
        Assert.False(await _cache.TryAddAsync("expires-one-tick-later", In(TimeSpan.FromMinutes(1)), CancellationToken));
    }

    [Fact]
    public async Task Timer_RunsOncePerCleanupInterval()
    {
        _time.Advance(InMemoryHmacReplayCache.CleanupInterval); // First purge, nothing to remove.
        await _cache.TryAddAsync("long-lived", In(TimeSpan.FromMinutes(10)), CancellationToken);
        await _cache.TryAddAsync("short-lived", In(TimeSpan.FromSeconds(1)), CancellationToken);

        _time.Advance(TimeSpan.FromSeconds(30)); // "short-lived" expired, next purge not due yet.
        Assert.Equal(2, _cache.Count);

        _time.Advance(TimeSpan.FromSeconds(30)); // Second purge is due.
        Assert.Equal(1, _cache.Count);
    }

    [Fact]
    public async Task Timer_KeepsPurgingPeriodically()
    {
        for (int round = 0; round < 5; round++)
        {
            await _cache.TryAddAsync("round-" + round.ToString(CultureInfo.InvariantCulture), In(TimeSpan.FromSeconds(1)), CancellationToken);
            Assert.Equal(1, _cache.Count);

            _time.Advance(InMemoryHmacReplayCache.CleanupInterval);

            Assert.Equal(0, _cache.Count);
        }
    }

    [Fact]
    public async Task Dispose_StopsThePurgeTimer()
    {
        await _cache.TryAddAsync(Signature, In(TimeSpan.FromSeconds(1)), CancellationToken);

        _cache.Dispose();
        _time.Advance(InMemoryHmacReplayCache.CleanupInterval * 3);

        Assert.Equal(1, _cache.Count);
    }

    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        _cache.Dispose();
        _cache.Dispose();
    }

    [Fact]
    public void Constructor_SchedulesPeriodicTimerWithCleanupInterval_AndDisposeDisposesIt()
    {
        var time = new RecordingTimeProvider(_time);

        var cache = new InMemoryHmacReplayCache(time);
        RecordingTimeProvider.TimerRegistration timer = Assert.Single(time.Timers);
        cache.Dispose();

        Assert.Equal(InMemoryHmacReplayCache.CleanupInterval, timer.DueTime);
        Assert.Equal(InMemoryHmacReplayCache.CleanupInterval, timer.Period);
        Assert.True(timer.Disposed);
    }

    [Fact]
    public async Task ServiceProviderDisposal_DisposesDefaultCacheAndStopsItsTimer()
    {
        var time = new FakeTimeProvider(TestCredentials.Now);
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(time);
        services.AddHmacServer();
        InMemoryHmacReplayCache cache;
        await using (ServiceProvider provider = services.BuildServiceProvider())
        {
            cache = Assert.IsType<InMemoryHmacReplayCache>(provider.GetRequiredService<IHmacReplayCache>());
            await cache.TryAddAsync(Signature, time.GetUtcNow() + TimeSpan.FromSeconds(1), CancellationToken);
        }

        time.Advance(InMemoryHmacReplayCache.CleanupInterval * 2);

        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_ConcurrentCallsForSameKey_ExactlyOneSucceeds()
    {
        for (int round = 0; round < 20; round++)
        {
            string signature = Signature + round.ToString(CultureInfo.InvariantCulture);
            DateTimeOffset expiresAt = In(TimeSpan.FromMinutes(5));

            bool[] results = await RunConcurrentlyAsync(64, () => _cache.TryAddAsync(signature, expiresAt, CancellationToken));

            Assert.Single(results, added => added);
        }
    }

    [Fact]
    public async Task TryAddAsync_ConcurrentCallsReusingExpiredEntry_ExactlyOneSucceeds()
    {
        for (int round = 0; round < 20; round++)
        {
            string signature = Signature + round.ToString(CultureInfo.InvariantCulture);
            await _cache.TryAddAsync(signature, In(TimeSpan.FromMilliseconds(1)), CancellationToken);
        }

        _time.Advance(TimeSpan.FromSeconds(1)); // All entries expired, no purge yet.

        for (int round = 0; round < 20; round++)
        {
            string signature = Signature + round.ToString(CultureInfo.InvariantCulture);
            DateTimeOffset expiresAt = In(TimeSpan.FromMinutes(5));

            bool[] results = await RunConcurrentlyAsync(64, () => _cache.TryAddAsync(signature, expiresAt, CancellationToken));

            Assert.Single(results, added => added);
        }
    }

    [Fact]
    public async Task TryAddAsync_ConcurrentWithPurges_ExactlyOneSucceedsPerSignature()
    {
        // Expired entries are purged by the timer (fired from Advance on another thread) while callers race to
        // re-add the same signatures. A live entry must never be purged, and each signature is accepted once.
        const int Signatures = 50;
        for (int i = 0; i < Signatures; i++)
        {
            await _cache.TryAddAsync("sig-" + i.ToString(CultureInfo.InvariantCulture), In(TimeSpan.FromMilliseconds(1)), CancellationToken);
        }

        _time.Advance(TimeSpan.FromSeconds(1));
        DateTimeOffset expiresAt = In(TimeSpan.FromDays(1));
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        Task purger = Task.Run(
            async () =>
            {
                await start.Task;
                for (int i = 0; i < 20; i++)
                {
                    _time.Advance(InMemoryHmacReplayCache.CleanupInterval);
                }
            },
            CancellationToken);

        Task<bool>[] adders =
        [
            .. Enumerable.Range(0, Signatures * 8).Select(i => Task.Run(
                async () =>
                {
                    await start.Task;
                    return await _cache.TryAddAsync("sig-" + (i % Signatures).ToString(CultureInfo.InvariantCulture), expiresAt, CancellationToken);
                },
                CancellationToken)),
        ];

        start.SetResult();
        bool[] results = await Task.WhenAll(adders);
        await purger;

        Assert.Equal(Signatures, results.Count(added => added));
        Assert.Equal(Signatures, _cache.Count);
    }

    [Fact]
    public async Task TryAddAsync_NullSignature_ThrowsArgumentNullException()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            "signature",
            () => _cache.TryAddAsync(null!, In(TimeSpan.FromMinutes(5)), CancellationToken).AsTask());
    }

    [Fact]
    public async Task TryAddAsync_EmptySignature_ThrowsArgumentException()
    {
        await Assert.ThrowsAsync<ArgumentException>(
            "signature",
            () => _cache.TryAddAsync(string.Empty, In(TimeSpan.FromMinutes(5)), CancellationToken).AsTask());
    }

    [Fact]
    public void Constructor_NullTimeProvider_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("timeProvider", () => new InMemoryHmacReplayCache(null!));
    }

    [Fact]
    public void CleanupInterval_IsOneMinute()
    {
        Assert.Equal(TimeSpan.FromMinutes(1), InMemoryHmacReplayCache.CleanupInterval);
    }

    private static async Task<bool[]> RunConcurrentlyAsync(int parallelism, Func<ValueTask<bool>> operation)
    {
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<bool>[] tasks =
        [
            .. Enumerable.Range(0, parallelism).Select(_ => Task.Run(
                async () =>
                {
                    await start.Task;
                    return await operation();
                },
                CancellationToken)),
        ];

        start.SetResult();
        return await Task.WhenAll(tasks);
    }

    private DateTimeOffset In(TimeSpan delay) => _time.GetUtcNow() + delay;
}
