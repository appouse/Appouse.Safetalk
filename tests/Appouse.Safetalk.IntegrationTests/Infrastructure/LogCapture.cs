using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// An <see cref="ILoggerProvider"/> that records the log entries of the library (categories starting with
/// <c>Appouse.Safetalk</c>), including their structured state, so tests can assert warnings, errors and how often an
/// operation actually ran.
/// </summary>
internal sealed class LogCapture : ILoggerProvider
{
    private const string LibraryCategoryPrefix = "Appouse.Safetalk";

    private readonly ConcurrentQueue<CapturedLog> _entries = new();

    public IReadOnlyCollection<CapturedLog> Entries => _entries;

    /// <summary>Returns the entries written by <typeparamref name="TCategory"/> with <paramref name="eventId"/>.</summary>
    public CapturedLog[] Find<TCategory>(int eventId)
        => [.. _entries.Where(entry => entry.EventId.Id == eventId && entry.Category == typeof(TCategory).FullName)];

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, this);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(string category, LogCapture owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull
            => null;

        public bool IsEnabled(LogLevel logLevel) => category.StartsWith(LibraryCategoryPrefix, StringComparison.Ordinal);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            KeyValuePair<string, object?>[] values = state is IEnumerable<KeyValuePair<string, object?>> structured ? [.. structured] : [];
            owner._entries.Enqueue(new CapturedLog(category, logLevel, eventId, formatter(state, exception), values));
        }
    }
}

/// <summary>One entry recorded by <see cref="LogCapture"/>.</summary>
internal sealed record CapturedLog(
    string Category,
    LogLevel Level,
    EventId EventId,
    string Message,
    IReadOnlyList<KeyValuePair<string, object?>> Values)
{
    /// <summary>Returns the value of a structured logging placeholder, for example <c>ClientId</c>.</summary>
    public object? GetValue(string name) => Values.Single(value => value.Key == name).Value;
}
