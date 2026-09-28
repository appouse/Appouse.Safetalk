namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// Counts the requests that made it past the HMAC middleware.
/// </summary>
public sealed class RequestCounter
{
    private int _count;

    public int Count => Volatile.Read(ref _count);

    public void Increment() => Interlocked.Increment(ref _count);
}
