using Appouse.Safetalk.Redis.Tests.Infrastructure;
using StackExchange.Redis;

namespace Appouse.Safetalk.Redis.Tests;

public sealed class RedisConnectionTests
{
    [Fact]
    public async Task Create_ConcurrentCallers_ConnectOnce()
    {
        var redis = new FakeRedis();
        int connects = 0;
        var gate = new TaskCompletionSource();
        await using RedisConnection connection = RedisConnection.Create(async () =>
        {
            Interlocked.Increment(ref connects);
            await gate.Task;
            return redis.Multiplexer;
        });

        Task<IConnectionMultiplexer>[] callers = [.. Enumerable.Range(0, 32).Select(_ => connection.GetAsync(TestContext.Current.CancellationToken).AsTask())];
        gate.SetResult();
        IConnectionMultiplexer[] results = await Task.WhenAll(callers);

        Assert.Equal(1, connects);
        Assert.All(results, result => Assert.Same(redis.Multiplexer, result));
    }

    [Fact]
    public async Task Create_FailedConnection_IsNotCached()
    {
        var redis = new FakeRedis();
        int attempts = 0;
        await using RedisConnection connection = RedisConnection.Create(() => ++attempts == 1
            ? Task.FromException<IConnectionMultiplexer>(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"))
            : Task.FromResult(redis.Multiplexer));

        await Assert.ThrowsAsync<RedisConnectionException>(() => connection.GetAsync(TestContext.Current.CancellationToken).AsTask());
        IConnectionMultiplexer second = await connection.GetAsync(TestContext.Current.CancellationToken);

        Assert.Same(redis.Multiplexer, second);
        Assert.Equal(2, attempts);
    }

    [Fact]
    public async Task Create_Dispose_DisposesTheOwnedMultiplexer()
    {
        var redis = new FakeRedis();
        RedisConnection connection = RedisConnection.Create(() => Task.FromResult(redis.Multiplexer));
        await connection.GetAsync(TestContext.Current.CancellationToken);

        await connection.DisposeAsync();
        connection.Dispose();

        Assert.Equal(1, redis.DisposeCalls);
    }

    [Fact]
    public async Task Create_DisposedBeforeFirstUse_NeverConnects()
    {
        int connects = 0;
        RedisConnection connection = RedisConnection.Create(() =>
        {
            connects++;
            return Task.FromResult(new FakeRedis().Multiplexer);
        });

        connection.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => connection.GetAsync(TestContext.Current.CancellationToken).AsTask());
        Assert.Equal(0, connects);
    }

    [Fact]
    public async Task Borrow_Dispose_LeavesTheApplicationsMultiplexerAlone()
    {
        var redis = new FakeRedis();
        RedisConnection connection = RedisConnection.Borrow(redis.Multiplexer);

        Assert.Same(redis.Multiplexer, await connection.GetAsync(TestContext.Current.CancellationToken));
        connection.Dispose();
        await connection.DisposeAsync();

        Assert.Equal(0, redis.DisposeCalls);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => connection.GetAsync(TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task Create_FromConfigurationWithoutAbortConnect_ReturnsAReconnectingMultiplexerWhenTheServerIsDown()
    {
        await using RedisConnection connection = RedisConnection.Create("127.0.0.1:1,connectTimeout=200,connectRetry=0");

        IConnectionMultiplexer multiplexer = await connection.GetAsync(TestContext.Current.CancellationToken);

        Assert.False(multiplexer.IsConnected);
    }

    [Fact]
    public async Task Create_FromConfigurationWithAbortConnect_FailsWhenTheServerIsDown()
    {
        await using RedisConnection connection = RedisConnection.Create("127.0.0.1:1,connectTimeout=200,connectRetry=0,abortConnect=true");

        await Assert.ThrowsAsync<RedisConnectionException>(() => connection.GetAsync(TestContext.Current.CancellationToken).AsTask());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Create_MissingConfiguration_Throws(string? configuration)
        => Assert.ThrowsAny<ArgumentException>(() => RedisConnection.Create(configuration!));
}
