using System.Net;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// A custom <see cref="HttpContent"/> (synchronous and asynchronous serialization) that records how often it is
/// serialized and whether it was disposed, and that can announce a deliberately wrong length.
/// </summary>
internal sealed class TrackingContent(byte[] payload, long? announcedLength = null) : HttpContent
{
    private int _serializationCount;
    private int _disposeCount;

    public int SerializationCount => Volatile.Read(ref _serializationCount);

    public bool IsDisposed => Volatile.Read(ref _disposeCount) > 0;

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _serializationCount);
        await stream.WriteAsync(payload.AsMemory(), cancellationToken);
    }

    protected override void SerializeToStream(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _serializationCount);
        stream.Write(payload);
    }

    protected override bool TryComputeLength(out long length)
    {
        length = announcedLength ?? 0;
        return announcedLength is not null;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Interlocked.Increment(ref _disposeCount);
        }

        base.Dispose(disposing);
    }
}
