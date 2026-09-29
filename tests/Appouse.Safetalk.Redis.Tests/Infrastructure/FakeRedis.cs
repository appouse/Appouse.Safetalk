using System.Collections.Concurrent;
using System.Reflection;
using StackExchange.Redis;

namespace Appouse.Safetalk.Redis.Tests.Infrastructure;

/// <summary>
/// A recording stand-in for <see cref="IConnectionMultiplexer"/> and <see cref="IDatabase"/>, for tests that must not
/// need a server. Only the members used by the library are implemented.
/// </summary>
public sealed class FakeRedis
{
    public FakeRedis()
    {
        Multiplexer = RecordingProxy.Create<IConnectionMultiplexer>(InvokeMultiplexer);
        Database = RecordingProxy.Create<IDatabase>(InvokeDatabase);
    }

    public IConnectionMultiplexer Multiplexer { get; }

    public IDatabase Database { get; }

    public bool StringSetResult { get; set; } = true;

    public ConcurrentQueue<StringSetCall> StringSetCalls { get; } = new();

    public ConcurrentQueue<int> RequestedDatabases { get; } = new();

    public int DisposeCalls => _disposeCalls;

    private int _disposeCalls;

    private object? InvokeMultiplexer(MethodInfo method, object?[] args)
    {
        switch (method.Name)
        {
            case nameof(IConnectionMultiplexer.GetDatabase):
                RequestedDatabases.Enqueue((int)args[0]!);
                return Database;
            case nameof(IDisposable.Dispose):
                Interlocked.Increment(ref _disposeCalls);
                return null;
            case nameof(IAsyncDisposable.DisposeAsync):
                Interlocked.Increment(ref _disposeCalls);
                return ValueTask.CompletedTask;
            default:
                throw new NotSupportedException($"FakeRedis does not implement {method.Name}.");
        }
    }

    private object? InvokeDatabase(MethodInfo method, object?[] args)
    {
        if (method.Name != nameof(IDatabase.StringSetAsync))
        {
            throw new NotSupportedException($"FakeRedis does not implement {method.Name}.");
        }

        StringSetCalls.Enqueue(new StringSetCall(
            (RedisKey)args[0]!,
            (RedisValue)args[1]!,
            args.OfType<TimeSpan>().Cast<TimeSpan?>().FirstOrDefault(),
            args.OfType<When>().DefaultIfEmpty(When.Always).First()));
        return Task.FromResult(StringSetResult);
    }

    public sealed record StringSetCall(RedisKey Key, RedisValue Value, TimeSpan? Expiry, When When);
}

/// <summary>
/// Creates proxies that forward every interface call to a handler.
/// </summary>
public static class RecordingProxy
{
    public static T Create<T>(Func<MethodInfo, object?[], object?> handler)
        where T : class
    {
        T proxy = DispatchProxy.Create<T, ForwardingProxy>();
        ((ForwardingProxy)(object)proxy).Handler = handler;
        return proxy;
    }
}

/// <summary>
/// The <see cref="DispatchProxy"/> behind <see cref="RecordingProxy"/>.
/// </summary>
public class ForwardingProxy : DispatchProxy
{
    internal Func<MethodInfo, object?[], object?> Handler { get; set; } = null!;

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        => Handler(targetMethod!, args ?? []);
}
