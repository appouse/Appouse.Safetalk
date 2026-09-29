using StackExchange.Redis;

namespace Appouse.Safetalk.Redis;

/// <summary>
/// An <see cref="IHmacReplayCache"/> shared by every instance of a scaled-out API, stored in a Redis-compatible
/// server (Redis, KeyDB).
/// </summary>
/// <remarks>
/// <para>
/// Each accepted signature is written with <c>SET key 1 NX PX ttl</c>: the check and the write are one atomic command,
/// so of any number of concurrent copies of a request — on any instance — exactly one is accepted. The key expires on
/// its own when the request timestamp could no longer be accepted anyway.
/// </para>
/// <para>
/// The cache fails closed: when the server cannot be reached, the command throws and the request is not accepted.
/// Replay protection is only as strong as the server's consistency: asynchronous replication (a failover in Redis
/// Sentinel, or KeyDB multi-master / active replication with instances writing to different masters) can lose or race
/// recently written keys, so point every instance at the same primary.
/// </para>
/// </remarks>
public sealed class RedisHmacReplayCache : IHmacReplayCache
{
    private static readonly RedisValue Marker = 1;

    private readonly RedisConnection _connection;
    private readonly string _keyPrefix;
    private readonly int _database;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new cache over a connection owned by the application.
    /// </summary>
    /// <param name="connection">The connection to the Redis or KeyDB server. It is not disposed by the cache.</param>
    /// <param name="timeProvider">The clock used to compute key lifetimes.</param>
    /// <param name="keyPrefix">The prefix of the replay keys.</param>
    /// <param name="database">The database number, or <c>-1</c> for the connection's default database.</param>
    public RedisHmacReplayCache(
        IConnectionMultiplexer connection,
        TimeProvider timeProvider,
        string keyPrefix = RedisReplayCacheOptions.DefaultKeyPrefix,
        int database = -1)
        : this(RedisConnection.Borrow(connection), timeProvider, keyPrefix, database)
    {
    }

    internal RedisHmacReplayCache(RedisConnection connection, TimeProvider timeProvider, string keyPrefix, int database)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(keyPrefix);
        ArgumentOutOfRangeException.ThrowIfLessThan(database, -1);

        _connection = connection;
        _timeProvider = timeProvider;
        _keyPrefix = keyPrefix;
        _database = database;
    }

    /// <inheritdoc />
    /// <exception cref="RedisException">The server could not be reached or rejected the command (fail closed).</exception>
    public async ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(signature);
        cancellationToken.ThrowIfCancellationRequested();

        TimeSpan timeToLive = expiresAt - _timeProvider.GetUtcNow();
        if (timeToLive <= TimeSpan.Zero)
        {
            return false; // Fail closed: an entry that is already expired protects nothing.
        }

        // PX has millisecond resolution: round up so the key never expires before expiresAt.
        timeToLive = TimeSpan.FromMilliseconds(Math.Ceiling(timeToLive.TotalMilliseconds));

        IConnectionMultiplexer multiplexer = await _connection.GetAsync(cancellationToken).ConfigureAwait(false);
        IDatabase database = multiplexer.GetDatabase(_database);

        // StackExchange.Redis has no cancellation support; stop waiting (the command itself may still complete).
        return await database
            .StringSetAsync(string.Concat(_keyPrefix, signature), Marker, timeToLive, When.NotExists)
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
    }
}
