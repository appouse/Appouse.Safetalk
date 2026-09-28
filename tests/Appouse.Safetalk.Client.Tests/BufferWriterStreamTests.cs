using System.Buffers;
using System.Text;

namespace Appouse.Safetalk.Client.Tests;

public sealed class BufferWriterStreamTests
{
    private readonly ArrayBufferWriter<byte> _writer = new();

    [Fact]
    public void Capabilities_AreWriteOnlyAndNonSeekable()
    {
        using var stream = new BufferWriterStream(_writer);

        Assert.False(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.True(stream.CanWrite);
        Assert.False(stream.CanTimeout);
    }

    [Fact]
    public void UnsupportedMembers_ThrowNotSupportedException()
    {
        using var stream = new BufferWriterStream(_writer);

        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Read(new byte[4], 0, 4));
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(0));
    }

    [Fact]
    public void Write_ByteArrayWithOffsetAndCount_AppendsOnlyTheSlice()
    {
        using var stream = new BufferWriterStream(_writer);
        byte[] buffer = [1, 2, 3, 4, 5, 6];

        stream.Write(buffer, 2, 3);

        Assert.Equal([3, 4, 5], _writer.WrittenSpan.ToArray());
    }

    [Fact]
    public void Write_ZeroCount_WritesNothing()
    {
        using var stream = new BufferWriterStream(_writer);

        stream.Write([1, 2, 3], 3, 0);
        stream.Write(ReadOnlySpan<byte>.Empty);

        Assert.Equal(0, _writer.WrittenCount);
    }

    [Fact]
    public void Write_Span_AppendsBytes()
    {
        using var stream = new BufferWriterStream(_writer);

        stream.Write("hello"u8);

        Assert.Equal("hello"u8.ToArray(), _writer.WrittenSpan.ToArray());
    }

    [Fact]
    public void WriteByte_AppendsSingleByte()
    {
        using var stream = new BufferWriterStream(_writer);

        stream.WriteByte(0xAB);
        stream.WriteByte(0x00);

        Assert.Equal([0xAB, 0x00], _writer.WrittenSpan.ToArray());
    }

    [Fact]
    public void Write_SequentialCalls_AppendInOrder()
    {
        using var stream = new BufferWriterStream(_writer);

        stream.Write("GET\n"u8);
        stream.Write(Encoding.ASCII.GetBytes("/api?x=1\n"), 0, 9);
        stream.WriteByte((byte)'1');
        stream.Write("\n"u8);

        Assert.Equal("GET\n/api?x=1\n1\n", Encoding.ASCII.GetString(_writer.WrittenSpan));
    }

    [Fact]
    public void Write_InvalidArguments_Throw()
    {
        using var stream = new BufferWriterStream(_writer);
        byte[] buffer = new byte[4];

        Assert.Throws<ArgumentNullException>(() => stream.Write(null!, 0, 1));
        Assert.ThrowsAny<ArgumentException>(() => stream.Write(buffer, -1, 1));
        Assert.ThrowsAny<ArgumentException>(() => stream.Write(buffer, 0, -1));
        Assert.ThrowsAny<ArgumentException>(() => stream.Write(buffer, 2, 3));
        Assert.Equal(0, _writer.WrittenCount);
    }

    [Fact]
    public async Task WriteAsync_ByteArray_AppendsSliceAndCompletesSynchronously()
    {
        using var stream = new BufferWriterStream(_writer);
        byte[] buffer = [9, 8, 7, 6];

        Task task = stream.WriteAsync(buffer, 1, 2, TestContext.Current.CancellationToken);

        Assert.True(task.IsCompletedSuccessfully);
        await task;
        Assert.Equal([8, 7], _writer.WrittenSpan.ToArray());
    }

    [Fact]
    public async Task WriteAsync_Memory_AppendsAndCompletesSynchronously()
    {
        using var stream = new BufferWriterStream(_writer);

        ValueTask task = stream.WriteAsync("payload"u8.ToArray().AsMemory(), TestContext.Current.CancellationToken);

        Assert.True(task.IsCompletedSuccessfully);
        await task;
        Assert.Equal("payload"u8.ToArray(), _writer.WrittenSpan.ToArray());
    }

    [Fact]
    public async Task WriteAsync_ByteArrayWithCancelledToken_ReturnsCanceledTaskAndWritesNothing()
    {
        using var stream = new BufferWriterStream(_writer);
        var cancelled = new CancellationToken(canceled: true);

        Task task = stream.WriteAsync(new byte[] { 1, 2, 3 }, 0, 3, cancelled);

        Assert.True(task.IsCanceled);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.Equal(0, _writer.WrittenCount);
    }

    [Fact]
    public async Task WriteAsync_MemoryWithCancelledToken_ReturnsCanceledTaskAndWritesNothing()
    {
        using var stream = new BufferWriterStream(_writer);
        var cancelled = new CancellationToken(canceled: true);

        ValueTask task = stream.WriteAsync(new byte[] { 1, 2, 3 }.AsMemory(), cancelled);

        Assert.True(task.IsCanceled);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await task);
        Assert.Equal(0, _writer.WrittenCount);
    }

    [Fact]
    public async Task WriteAsync_ByteArrayWithInvalidArguments_Throws()
    {
        using var stream = new BufferWriterStream(_writer);

        await Assert.ThrowsAsync<ArgumentNullException>(() => stream.WriteAsync(null!, 0, 1, TestContext.Current.CancellationToken));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => stream.WriteAsync(new byte[2], 1, 5, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Flush_And_FlushAsync_AreNoOps()
    {
        using var stream = new BufferWriterStream(_writer);
        stream.Write("x"u8);

        stream.Flush();
        await stream.FlushAsync(TestContext.Current.CancellationToken);

        Assert.Equal("x"u8.ToArray(), _writer.WrittenSpan.ToArray());
    }

    [Fact]
    public void CopyTo_FromLargeSourceStream_WritesAllBytes()
    {
        byte[] payload = CreatePayload(300_000);
        using var stream = new BufferWriterStream(_writer);
        using var source = new MemoryStream(payload);

        source.CopyTo(stream, bufferSize: 8_192);

        Assert.Equal(payload, _writer.WrittenSpan.ToArray());
    }

    [Fact]
    public async Task CopyToAsync_FromLargeSourceStream_WritesAllBytes()
    {
        byte[] payload = CreatePayload(300_000);
        using var stream = new BufferWriterStream(_writer);
        using var source = new BufferedStream(new MemoryStream(payload), 4_096);

        await source.CopyToAsync(stream, TestContext.Current.CancellationToken);

        Assert.Equal(payload, _writer.WrittenSpan.ToArray());
    }

    [Fact]
    public async Task HttpContentCopyToAsync_IntoCanonicalRequestBuffer_AppendsBodyAfterHeader()
    {
        using CanonicalRequestBuffer canonicalRequest = CanonicalRequestBuffer.Create("post", "/api/orders", "1790000000");
        using var content = new StringContent("{\"id\":5}");
        using var stream = new BufferWriterStream(canonicalRequest);

        await content.CopyToAsync(stream, TestContext.Current.CancellationToken);

        Assert.Equal("POST\n/api/orders\n1790000000\n{\"id\":5}", Encoding.UTF8.GetString(canonicalRequest.WrittenSpan));
    }

    [Fact]
    public void Dispose_DoesNotAffectWrittenData()
    {
        var stream = new BufferWriterStream(_writer);
        stream.Write("abc"u8);

        stream.Dispose();

        Assert.Equal("abc"u8.ToArray(), _writer.WrittenSpan.ToArray());
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i ^ (i >> 8));
        }

        return payload;
    }
}
