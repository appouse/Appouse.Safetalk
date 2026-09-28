namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A <see cref="TimeProvider"/> that delegates to another one and records the timers created through it, including
/// whether they were disposed.
/// </summary>
internal sealed class RecordingTimeProvider(TimeProvider inner) : TimeProvider
{
    private readonly List<TimerRegistration> _timers = [];
    private readonly object _gate = new();

    public IReadOnlyList<TimerRegistration> Timers
    {
        get
        {
            lock (_gate)
            {
                return [.. _timers];
            }
        }
    }

    public override TimeZoneInfo LocalTimeZone => inner.LocalTimeZone;

    public override long TimestampFrequency => inner.TimestampFrequency;

    public override DateTimeOffset GetUtcNow() => inner.GetUtcNow();

    public override long GetTimestamp() => inner.GetTimestamp();

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var registration = new TimerRegistration(inner.CreateTimer(callback, state, dueTime, period), dueTime, period);
        lock (_gate)
        {
            _timers.Add(registration);
        }

        return registration;
    }

    internal sealed class TimerRegistration(ITimer timer, TimeSpan dueTime, TimeSpan period) : ITimer
    {
        public TimeSpan DueTime { get; } = dueTime;

        public TimeSpan Period { get; } = period;

        public bool Disposed { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period) => timer.Change(dueTime, period);

        public void Dispose()
        {
            Disposed = true;
            timer.Dispose();
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return timer.DisposeAsync();
        }
    }
}
