using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// An <see cref="ILogger{TCategoryName}"/> that records every entry (all levels enabled).
/// </summary>
internal sealed class ListLogger<T> : ILogger<T>
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    public IReadOnlyList<LogEntry> Entries => [.. _entries];

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);
        _entries.Enqueue(new LogEntry(logLevel, eventId, formatter(state, exception)));
    }
}
