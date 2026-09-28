namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// An <see cref="IHmacReplayCache"/> that records its calls and returns a fixed answer. Thread-safe, so it can be
/// shared by concurrent requests.
/// </summary>
internal sealed class RecordingReplayCache(bool firstSeen = true) : IHmacReplayCache
{
    private readonly List<ReplayCacheCall> _calls = [];
    private readonly object _gate = new();

    public IReadOnlyList<ReplayCacheCall> Calls
    {
        get
        {
            lock (_gate)
            {
                return [.. _calls];
            }
        }
    }

    public ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _calls.Add(new ReplayCacheCall(signature, expiresAt, cancellationToken));
        }

        return ValueTask.FromResult(firstSeen);
    }
}

internal readonly record struct ReplayCacheCall(string Signature, DateTimeOffset ExpiresAt, CancellationToken CancellationToken);
