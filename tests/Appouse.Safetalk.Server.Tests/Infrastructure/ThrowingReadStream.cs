namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A request body that fails the test if anything tries to read it, proving that no body I/O happens.
/// </summary>
internal sealed class ThrowingReadStream : Stream
{
    private const string Message = "The request body must not be read.";

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException(Message);

    public override int Read(Span<byte> buffer) => throw new InvalidOperationException(Message);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(Message);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException(Message);

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
