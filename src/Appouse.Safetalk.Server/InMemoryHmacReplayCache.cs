using System.Collections.Concurrent;

namespace Appouse.Safetalk.Server;

/// <summary>
/// A lock-free, process-local <see cref="IHmacReplayCache"/>.
/// </summary>
/// <remarks>
/// Expired entries are purged by a timer every <see cref="CleanupInterval"/>, off the request path. Memory is bounded
/// by the number of distinct accepted requests within the clock skew window. For multiple instances, implement
/// <see cref="IHmacReplayCache"/> over a shared store instead.
/// </remarks>
public sealed class InMemoryHmacReplayCache : IHmacReplayCache, IDisposable
{
    /// <summary>
    /// The interval between two purges of expired entries.
    /// </summary>
    public static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private readonly ITimer _cleanupTimer;

    /// <summary>
    /// Initializes a new cache.
    /// </summary>
    /// <param name="timeProvider">The clock used to expire entries and to schedule purges.</param>
    public InMemoryHmacReplayCache(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        _timeProvider = timeProvider;
        _cleanupTimer = timeProvider.CreateTimer(
            static state => ((InMemoryHmacReplayCache)state!).PurgeExpiredEntries(),
            this,
            CleanupInterval,
            CleanupInterval);
    }

    /// <summary>
    /// Gets the number of entries currently held, including expired entries that have not been purged yet.
    /// </summary>
    public int Count => _entries.Count;

    /// <inheritdoc />
    public ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(signature);

        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (expiresAt <= now)
        {
            return ValueTask.FromResult(false); // Fail closed: an entry that is already expired protects nothing.
        }

        while (true)
        {
            if (_entries.TryAdd(signature, expiresAt))
            {
                return ValueTask.FromResult(true);
            }

            if (!_entries.TryGetValue(signature, out DateTimeOffset existingExpiry))
            {
                continue; // Removed concurrently by a purge: try to add again.
            }

            if (existingExpiry > now)
            {
                return ValueTask.FromResult(false); // Replay.
            }

            if (_entries.TryUpdate(signature, expiresAt, existingExpiry))
            {
                return ValueTask.FromResult(true); // Reused an expired entry that was not purged yet.
            }
        }
    }

    /// <summary>
    /// Stops the purge timer.
    /// </summary>
    public void Dispose() => _cleanupTimer.Dispose();

    private void PurgeExpiredEntries()
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        foreach (KeyValuePair<string, DateTimeOffset> entry in _entries)
        {
            if (entry.Value <= now)
            {
                // Removes the entry only if it was not refreshed concurrently.
                _entries.TryRemove(entry);
            }
        }
    }
}
