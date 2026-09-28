using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A log entry captured by <see cref="LogCollector"/>, with the structured properties of the message.
/// </summary>
internal sealed record LogRecord(
    string Category,
    LogLevel Level,
    EventId EventId,
    string Message,
    IReadOnlyDictionary<string, object?> Properties);

/// <summary>
/// An <see cref="ILoggerProvider"/> that keeps every entry in memory, so tests can assert what was logged, how often
/// and with which structured values. Thread-safe.
/// </summary>
internal sealed class LogCollector : ILoggerProvider
{
    private readonly List<LogRecord> _records = [];
    private readonly object _gate = new();

    public IReadOnlyList<LogRecord> Records
    {
        get
        {
            lock (_gate)
            {
                return [.. _records];
            }
        }
    }

    /// <summary>
    /// Returns the entries of <typeparamref name="TCategory"/>'s category with the given event id.
    /// </summary>
    public IReadOnlyList<LogRecord> Find<TCategory>(int eventId) =>
        [.. Records.Where(record => record.Category == typeof(TCategory).FullName && record.EventId.Id == eventId)];

    public ILogger CreateLogger(string categoryName) => new CollectingLogger(this, categoryName);

    public ILogger<T> CreateLogger<T>() => new CollectingLogger<T>(this);

    public void Dispose()
    {
    }

    private void Add(LogRecord record)
    {
        lock (_gate)
        {
            _records.Add(record);
        }
    }

    private class CollectingLogger(LogCollector collector, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);

            Dictionary<string, object?> properties = new(StringComparer.Ordinal);
            if (state is IEnumerable<KeyValuePair<string, object?>> values)
            {
                foreach (KeyValuePair<string, object?> value in values)
                {
                    properties[value.Key] = value.Value;
                }
            }

            collector.Add(new LogRecord(category, logLevel, eventId, formatter(state, exception), properties));
        }
    }

    private sealed class CollectingLogger<T>(LogCollector collector)
        : CollectingLogger(collector, typeof(T).FullName!), ILogger<T>;
}
