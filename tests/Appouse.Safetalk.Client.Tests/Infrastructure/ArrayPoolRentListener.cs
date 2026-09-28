using System.Collections.Concurrent;
using System.Diagnostics.Tracing;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Records the size of every buffer rented from (or allocated by) <see cref="System.Buffers.ArrayPool{T}.Shared"/>
/// while it is alive, through the runtime's <c>System.Buffers.ArrayPoolEventSource</c>. Events are raised
/// synchronously on the renting thread, so what the code under test rents is observed whether or not the pool
/// already held a suitable array.
/// </summary>
internal sealed class ArrayPoolRentListener : EventListener
{
    private const string EventSourceName = "System.Buffers.ArrayPoolEventSource";

    // Field initializers run before the EventListener constructor, which may already raise events.
    private readonly ConcurrentQueue<int> _rentedSizes = new();

    public IReadOnlyCollection<int> RentedSizes => [.. _rentedSizes];

    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        if (eventSource.Name == EventSourceName)
        {
            EnableEvents(eventSource, EventLevel.Verbose);
        }
    }

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        if (eventData.EventName is "BufferRented" or "BufferAllocated" && eventData.Payload is { Count: > 1 } payload && payload[1] is int size)
        {
            _rentedSizes?.Enqueue(size);
        }
    }
}
