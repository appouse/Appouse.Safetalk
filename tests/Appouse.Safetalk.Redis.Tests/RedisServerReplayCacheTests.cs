using Appouse.Safetalk.Redis.Tests.Infrastructure;
using StackExchange.Redis;

namespace Appouse.Safetalk.Redis.Tests;

/// <summary>
/// <see cref="RedisHmacReplayCache"/> against real Redis and KeyDB servers.
/// </summary>
public sealed class RedisServerReplayCacheTests(RedisServers servers)
{
    private readonly string _keyPrefix = $"test:{Guid.NewGuid():N}:";

    [Theory]
    [InlineData(RedisServerKind.Redis, "redis-server")]
    [InlineData(RedisServerKind.KeyDb, "keydb-server")]
    public async Task Server_IsTheExpectedImplementation(RedisServerKind kind, string executable)
    {
        await using ConnectionMultiplexer connection = await servers.ConnectAsync(kind, allowAdmin: true);

        string info = (await connection.GetDatabase().ExecuteAsync("INFO", "server")).ToString();

        Assert.Contains(executable, info, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(RedisServerKind.Redis)]
    [InlineData(RedisServerKind.KeyDb)]
    public async Task TryAddAsync_FirstSeen_ThenReplay(RedisServerKind kind)
    {
        await using ConnectionMultiplexer connection = await servers.ConnectAsync(kind);
        var cache = new RedisHmacReplayCache(connection, TimeProvider.System, _keyPrefix);
        string signature = NewSignature();

        bool first = await cache.TryAddAsync(signature, DateTimeOffset.UtcNow.AddMinutes(5), TestContext.Current.CancellationToken);
        bool replay = await cache.TryAddAsync(signature, DateTimeOffset.UtcNow.AddMinutes(5), TestContext.Current.CancellationToken);

        Assert.True(first);
        Assert.False(replay);
    }

    [Theory]
    [InlineData(RedisServerKind.Redis)]
    [InlineData(RedisServerKind.KeyDb)]
    public async Task TryAddAsync_DifferentSignatures_AreIndependent(RedisServerKind kind)
    {
        await using ConnectionMultiplexer connection = await servers.ConnectAsync(kind);
        var cache = new RedisHmacReplayCache(connection, TimeProvider.System, _keyPrefix);

        bool[] results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ =>
            cache.TryAddAsync(NewSignature(), DateTimeOffset.UtcNow.AddMinutes(1), TestContext.Current.CancellationToken).AsTask()));

        Assert.All(results, Assert.True);
    }

    [Theory]
    [InlineData(RedisServerKind.Redis)]
    [InlineData(RedisServerKind.KeyDb)]
    public async Task TryAddAsync_KeyLivesUntilExpiresAt(RedisServerKind kind)
    {
        await using ConnectionMultiplexer connection = await servers.ConnectAsync(kind);
        var cache = new RedisHmacReplayCache(connection, TimeProvider.System, _keyPrefix);
        string signature = NewSignature();

        await cache.TryAddAsync(signature, DateTimeOffset.UtcNow.AddSeconds(330), TestContext.Current.CancellationToken);
        TimeSpan? timeToLive = await connection.GetDatabase().KeyTimeToLiveAsync(_keyPrefix + signature);

        Assert.NotNull(timeToLive);
        Assert.InRange(timeToLive.Value, TimeSpan.FromSeconds(320), TimeSpan.FromSeconds(330));
    }

    [Theory]
    [InlineData(RedisServerKind.Redis)]
    [InlineData(RedisServerKind.KeyDb)]
    public async Task TryAddAsync_HonoursKeyPrefixAndDatabase(RedisServerKind kind)
    {
        await using ConnectionMultiplexer connection = await servers.ConnectAsync(kind);
        var cache = new RedisHmacReplayCache(connection, TimeProvider.System, _keyPrefix, database: 3);
        string signature = NewSignature();

        await cache.TryAddAsync(signature, DateTimeOffset.UtcNow.AddMinutes(1), TestContext.Current.CancellationToken);

        Assert.True(await connection.GetDatabase(3).KeyExistsAsync(_keyPrefix + signature));
        Assert.False(await connection.GetDatabase(0).KeyExistsAsync(_keyPrefix + signature));
    }

    [Theory]
    [InlineData(RedisServerKind.Redis)]
    [InlineData(RedisServerKind.KeyDb)]
    public async Task TryAddAsync_ConcurrentCopiesFromSeveralInstances_ExactlyOneIsAccepted(RedisServerKind kind)
    {
        // Four connections stand in for four API instances receiving copies of the same captured request at once.
        ConnectionMultiplexer[] instances = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => servers.ConnectAsync(kind)));
        try
        {
            string signature = NewSignature();
            DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
            using var start = new ManualResetEventSlim();

            Task<bool>[] attempts = [.. Enumerable.Range(0, 64).Select(i => Task.Run(async () =>
            {
                var cache = new RedisHmacReplayCache(instances[i % instances.Length], TimeProvider.System, _keyPrefix);
                start.Wait(TestContext.Current.CancellationToken);
                return await cache.TryAddAsync(signature, expiresAt, TestContext.Current.CancellationToken);
            }, TestContext.Current.CancellationToken))];
            start.Set();
            bool[] results = await Task.WhenAll(attempts);

            Assert.Equal(1, results.Count(accepted => accepted));
        }
        finally
        {
            foreach (ConnectionMultiplexer instance in instances)
            {
                await instance.DisposeAsync();
            }
        }
    }

    [Theory]
    [InlineData(RedisServerKind.Redis)]
    [InlineData(RedisServerKind.KeyDb)]
    public async Task TryAddAsync_AfterTheKeyExpired_AcceptsTheSignatureAgain(RedisServerKind kind)
    {
        await using ConnectionMultiplexer connection = await servers.ConnectAsync(kind);
        var cache = new RedisHmacReplayCache(connection, TimeProvider.System, _keyPrefix);
        string signature = NewSignature();

        Assert.True(await cache.TryAddAsync(signature, DateTimeOffset.UtcNow.AddMilliseconds(300), TestContext.Current.CancellationToken));
        Assert.False(await cache.TryAddAsync(signature, DateTimeOffset.UtcNow.AddSeconds(5), TestContext.Current.CancellationToken));

        DateTime deadline = DateTime.UtcNow.AddSeconds(10);
        while (await connection.GetDatabase().KeyExistsAsync(_keyPrefix + signature) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50, TestContext.Current.CancellationToken);
        }

        Assert.True(await cache.TryAddAsync(signature, DateTimeOffset.UtcNow.AddSeconds(5), TestContext.Current.CancellationToken));
    }

    // 64 lower-case hexadecimal characters, like a real signature.
    private static string NewSignature() => string.Concat(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
}
