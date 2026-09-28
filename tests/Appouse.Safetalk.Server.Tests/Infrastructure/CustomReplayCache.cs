namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A custom replay cache registered through <c>AddReplayProtection&lt;TCache&gt;()</c>. It remembers every
/// signature forever, like a trivial distributed cache, and is distinguishable from the default cache by type.
/// </summary>
public sealed class CustomReplayCache : IHmacReplayCache
{
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return ValueTask.FromResult(_seen.Add(signature));
        }
    }
}
