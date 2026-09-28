namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A forward-only request body that invokes a callback before every read, for example to advance a fake clock and
/// simulate a client that trickles its body in slowly.
/// </summary>
internal sealed class CallbackReadStream : Stream
{
    private readonly MemoryStream _inner;
    private readonly int _maxBytesPerRead;
    private readonly Action<int> _beforeRead;
    private int _reads;

    /// <param name="content">The body.</param>
    /// <param name="maxBytesPerRead">The maximum number of bytes returned by one read.</param>
    /// <param name="beforeRead">Called with the zero-based index of the read about to happen.</param>
    public CallbackReadStream(byte[] content, int maxBytesPerRead, Action<int> beforeRead)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytesPerRead);
        ArgumentNullException.ThrowIfNull(beforeRead);

        _inner = new MemoryStream(content, writable: false);
        _maxBytesPerRead = maxBytesPerRead;
        _beforeRead = beforeRead;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        _beforeRead(_reads++);
        return _inner.Read(buffer[..Math.Min(buffer.Length, _maxBytesPerRead)]);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Read(buffer.Span));

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
