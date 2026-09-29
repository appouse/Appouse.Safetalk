using Appouse.Safetalk.Redis.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;

namespace Appouse.Safetalk.Redis.Tests;

/// <summary>
/// Behaviour of <see cref="RedisHmacReplayCache"/> that does not need a server.
/// </summary>
public sealed class RedisHmacReplayCacheTests
{
    private const string Signature = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 29, 12, 0, 0, TimeSpan.Zero));
    private readonly FakeRedis _redis = new();

    [Fact]
    public async Task TryAddAsync_WritesThePrefixedKeyOnlyIfAbsentWithTheRemainingLifetime()
    {
        var cache = new RedisHmacReplayCache(_redis.Multiplexer, _time, "tenant-a:", database: 3);

        bool added = await cache.TryAddAsync(Signature, _time.GetUtcNow().AddSeconds(90), TestContext.Current.CancellationToken);

        Assert.True(added);
        FakeRedis.StringSetCall call = Assert.Single(_redis.StringSetCalls);
        Assert.Equal("tenant-a:" + Signature, (string?)call.Key);
        Assert.Equal(When.NotExists, call.When);
        Assert.Equal(TimeSpan.FromSeconds(90), call.Expiry);
        Assert.Equal(3, Assert.Single(_redis.RequestedDatabases));
    }

    [Fact]
    public async Task TryAddAsync_DefaultOptions_UseTheDefaultPrefixAndDatabase()
    {
        var cache = new RedisHmacReplayCache(_redis.Multiplexer, _time);

        await cache.TryAddAsync(Signature, _time.GetUtcNow().AddMinutes(1), TestContext.Current.CancellationToken);

        Assert.Equal(RedisReplayCacheOptions.DefaultKeyPrefix + Signature, (string?)Assert.Single(_redis.StringSetCalls).Key);
        Assert.Equal(-1, Assert.Single(_redis.RequestedDatabases));
    }

    [Theory]
    [InlineData(1234.2, 1235)]
    [InlineData(0.1, 1)]
    [InlineData(999.999, 1000)]
    [InlineData(1000, 1000)]
    public async Task TryAddAsync_RoundsTheLifetimeUpToTheNextMillisecond(double remainingMilliseconds, int expectedMilliseconds)
    {
        var cache = new RedisHmacReplayCache(_redis.Multiplexer, _time);

        await cache.TryAddAsync(Signature, _time.GetUtcNow().AddMilliseconds(remainingMilliseconds), TestContext.Current.CancellationToken);

        Assert.Equal(TimeSpan.FromMilliseconds(expectedMilliseconds), Assert.Single(_redis.StringSetCalls).Expiry);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TryAddAsync_ReturnsWhetherTheServerWroteTheKey(bool written)
    {
        _redis.StringSetResult = written;
        var cache = new RedisHmacReplayCache(_redis.Multiplexer, _time);

        bool added = await cache.TryAddAsync(Signature, _time.GetUtcNow().AddMinutes(1), TestContext.Current.CancellationToken);

        Assert.Equal(written, added);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData(-600_000_000L)]
    public async Task TryAddAsync_ExpiresAtNowOrInThePast_FailsClosedWithoutContactingTheServer(long offsetTicks)
    {
        var cache = new RedisHmacReplayCache(_redis.Multiplexer, _time);

        bool added = await cache.TryAddAsync(Signature, _time.GetUtcNow().AddTicks(offsetTicks), TestContext.Current.CancellationToken);

        Assert.False(added);
        Assert.Empty(_redis.StringSetCalls);
        Assert.Empty(_redis.RequestedDatabases);
    }

    [Fact]
    public async Task TryAddAsync_CancelledToken_ThrowsWithoutContactingTheServer()
    {
        var cache = new RedisHmacReplayCache(_redis.Multiplexer, _time);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => cache.TryAddAsync(Signature, _time.GetUtcNow().AddMinutes(1), new CancellationToken(canceled: true)).AsTask());

        Assert.Empty(_redis.StringSetCalls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task TryAddAsync_MissingSignature_Throws(string? signature)
    {
        var cache = new RedisHmacReplayCache(_redis.Multiplexer, _time);

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => cache.TryAddAsync(signature!, _time.GetUtcNow().AddMinutes(1), TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void Constructor_InvalidArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => new RedisHmacReplayCache(null!, _time));
        Assert.Throws<ArgumentNullException>(() => new RedisHmacReplayCache(_redis.Multiplexer, null!));
        Assert.Throws<ArgumentNullException>(() => new RedisHmacReplayCache(_redis.Multiplexer, _time, keyPrefix: null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RedisHmacReplayCache(_redis.Multiplexer, _time, database: -2));
    }

    [Fact]
    public async Task TryAddAsync_ServerUnreachable_ThrowsInsteadOfAccepting()
    {
        await using ConnectionMultiplexer unreachable = await ConnectionMultiplexer.ConnectAsync(
            "127.0.0.1:1,abortConnect=false,connectTimeout=200,asyncTimeout=500,connectRetry=0");
        var cache = new RedisHmacReplayCache(unreachable, TimeProvider.System);

        await Assert.ThrowsAnyAsync<RedisException>(
            () => cache.TryAddAsync(Signature, DateTimeOffset.UtcNow.AddMinutes(1), TestContext.Current.CancellationToken).AsTask());
    }
}
