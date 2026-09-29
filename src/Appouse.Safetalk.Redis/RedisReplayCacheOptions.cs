namespace Appouse.Safetalk.Redis;

/// <summary>
/// Options of <see cref="RedisHmacReplayCache"/>.
/// </summary>
public sealed class RedisReplayCacheOptions
{
    /// <summary>
    /// The default <see cref="KeyPrefix"/>.
    /// </summary>
    public const string DefaultKeyPrefix = "safetalk:replay:";

    /// <summary>
    /// Gets or sets the StackExchange.Redis configuration string of the Redis or KeyDB server, for example
    /// <c>localhost:6379,password=...,ssl=true</c>.
    /// </summary>
    /// <remarks>
    /// When it is not set, the <c>IConnectionMultiplexer</c> already registered in the service collection is used (and
    /// never disposed by this library). When it is set, a dedicated connection is created on first use and disposed
    /// with the service provider; unless the string sets <c>abortConnect</c>, it keeps retrying in the background
    /// instead of failing when the server is temporarily unavailable.
    /// </remarks>
    public string? Configuration { get; set; }

    /// <summary>
    /// Gets or sets the prefix of the replay keys, which lets several applications share one server.
    /// Defaults to <see cref="DefaultKeyPrefix"/>.
    /// </summary>
    public string KeyPrefix { get; set; } = DefaultKeyPrefix;

    /// <summary>
    /// Gets or sets the database number, or <c>-1</c> (the default) for the connection's default database.
    /// </summary>
    public int Database { get; set; } = -1;
}
