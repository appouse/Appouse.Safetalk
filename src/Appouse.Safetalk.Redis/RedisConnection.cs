using StackExchange.Redis;

namespace Appouse.Safetalk.Redis;

/// <summary>
/// Provides the <see cref="IConnectionMultiplexer"/> used by <see cref="RedisHmacReplayCache"/>: either one borrowed
/// from the application (never disposed here) or a dedicated one created on first use and owned by this instance.
/// </summary>
internal sealed class RedisConnection : IDisposable, IAsyncDisposable
{
    private readonly Func<Task<IConnectionMultiplexer>>? _connect;
    private readonly SemaphoreSlim _connectGate = new(1, 1);
    private readonly bool _owned;
    private IConnectionMultiplexer? _multiplexer;
    private volatile bool _disposed;

    private RedisConnection(IConnectionMultiplexer? multiplexer, Func<Task<IConnectionMultiplexer>>? connect, bool owned)
    {
        _multiplexer = multiplexer;
        _connect = connect;
        _owned = owned;
    }

    /// <summary>
    /// Uses a multiplexer owned by the application.
    /// </summary>
    public static RedisConnection Borrow(IConnectionMultiplexer multiplexer)
    {
        ArgumentNullException.ThrowIfNull(multiplexer);
        return new RedisConnection(multiplexer, connect: null, owned: false);
    }

    /// <summary>
    /// Connects on first use with <paramref name="configuration"/> and owns the resulting multiplexer.
    /// </summary>
    public static RedisConnection Create(string configuration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration);

        ConfigurationOptions options = ConfigurationOptions.Parse(configuration);
        if (!configuration.Contains("abortConnect", StringComparison.OrdinalIgnoreCase))
        {
            // Keep reconnecting in the background instead of failing for good when the server is briefly unavailable.
            options.AbortOnConnectFail = false;
        }

        return Create(async () => await ConnectionMultiplexer.ConnectAsync(options).ConfigureAwait(false));
    }

    /// <summary>
    /// Connects on first use with <paramref name="connect"/> and owns the resulting multiplexer.
    /// </summary>
    internal static RedisConnection Create(Func<Task<IConnectionMultiplexer>> connect)
    {
        ArgumentNullException.ThrowIfNull(connect);
        return new RedisConnection(multiplexer: null, connect, owned: true);
    }

    /// <summary>
    /// Returns the multiplexer, connecting once. A failed attempt is not cached: the next call tries again.
    /// </summary>
    public async ValueTask<IConnectionMultiplexer> GetAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        IConnectionMultiplexer? multiplexer = Volatile.Read(ref _multiplexer);
        if (multiplexer is not null)
        {
            return multiplexer;
        }

        await _connectGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            multiplexer = _multiplexer;
            if (multiplexer is null)
            {
                multiplexer = await _connect!().ConfigureAwait(false);
                Volatile.Write(ref _multiplexer, multiplexer);
            }

            return multiplexer;
        }
        finally
        {
            _connectGate.Release();
        }
    }

    public void Dispose()
    {
        _disposed = true;
        if (_owned)
        {
            Interlocked.Exchange(ref _multiplexer, null)?.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        if (_owned && Interlocked.Exchange(ref _multiplexer, null) is { } multiplexer)
        {
            await multiplexer.DisposeAsync().ConfigureAwait(false);
        }
    }
}
