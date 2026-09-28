using System.Collections.Concurrent;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// A custom <see cref="IHmacReplayCache"/> (stand-in for a distributed cache) that records what the server stores.
/// Like a real implementation it keys entries on the signature alone and fails closed for already expired entries.
/// </summary>
public sealed class RecordingReplayCache(TimeProvider timeProvider) : IHmacReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<ReplayCacheCall> _calls = new();

    public IReadOnlyCollection<ReplayCacheCall> Calls => _calls;

    public ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        DateTimeOffset now = timeProvider.GetUtcNow();
        _calls.Enqueue(new ReplayCacheCall(signature, expiresAt, now, cancellationToken.CanBeCanceled));

        return ValueTask.FromResult(expiresAt > now && _entries.TryAdd(signature, expiresAt));
    }
}

/// <summary>One call made by the server to <see cref="RecordingReplayCache"/>.</summary>
public sealed record ReplayCacheCall(string Signature, DateTimeOffset ExpiresAt, DateTimeOffset Now, bool TokenCanBeCanceled);
