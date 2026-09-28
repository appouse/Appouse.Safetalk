using System.Buffers;
using System.Text;
using System.Text.Json;
using Appouse.Safetalk.Core.Tests.Infrastructure;

namespace Appouse.Safetalk.Core.Tests;

/// <summary>
/// Verifies that the whole rented array is wiped before it goes back to the shared pool, including bytes that were
/// written through <see cref="CanonicalRequestBuffer.GetSpan"/> or <see cref="CanonicalRequestBuffer.GetMemory"/> but
/// never committed with <see cref="CanonicalRequestBuffer.Advance"/> (partial writes, failed reads, failed serializers).
/// </summary>
[Collection(ArrayPoolInspectionDefinition.Name)]
public sealed class CanonicalRequestBufferUncommittedBytesTests
{
    private const string Method = "POST";
    private const string PathAndQuery = "/api/secret-orders";
    private const string Timestamp = "1700000000";
    private const byte Marker = 0xA5;
    private const byte Stale = 0x5C;
    private const int ReadChunkSize = 8 * 1024;

    private static readonly byte[] Header = Encoding.UTF8.GetBytes($"{Method}\n{PathAndQuery}\n{Timestamp}\n");

    public static TheoryData<bool> WriteThroughMemory => new() { false, true };

    [Theory]
    [MemberData(nameof(WriteThroughMemory))]
    public void Dispose_BytesWrittenWithoutAdvance_ZeroesWholeRentedArray(bool throughMemory)
    {
        const int bodyLength = 10_000;
        var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, bodyLength);
        try
        {
            byte[] rented = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
            Span<byte> destination = throughMemory ? buffer.GetMemory(bodyLength).Span : buffer.GetSpan(bodyLength);
            destination[..bodyLength].Fill(Marker);

            // Precondition: the body is physically in the array but not committed.
            Assert.Equal(Header.Length, buffer.WrittenCount);
            Assert.Equal(-1, rented.AsSpan(Header.Length, bodyLength).IndexOfAnyExcept(Marker));

            buffer.Dispose();

            ByteAssert.AllZero(rented);
        }
        finally
        {
            buffer.Dispose();
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4_999)]
    [InlineData(9_999)]
    public void Dispose_PartialAdvance_ZeroesCommittedAndUncommittedBytes(int committed)
    {
        const int bodyLength = 10_000;
        var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, bodyLength);
        try
        {
            byte[] rented = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
            buffer.GetSpan(bodyLength)[..bodyLength].Fill(Marker);
            buffer.Advance(committed);
            Assert.Equal(Header.Length + committed, buffer.WrittenCount);

            buffer.Dispose();

            ByteAssert.AllZero(rented);
        }
        finally
        {
            buffer.Dispose();
        }
    }

    [Fact]
    public void Dispose_WholeFreeSpaceFilledBeyondSizeHint_ZeroesUpToLastByteOfRentedArray()
    {
        var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        try
        {
            byte[] rented = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
            Span<byte> span = buffer.GetSpan(1);

            // The span reaches the end of the array, so a writer may legitimately touch every byte of it.
            Assert.Equal(rented.Length - Header.Length, span.Length);
            Assert.True(span.Length > 1);
            span.Fill(Marker);
            Assert.Equal(Marker, rented[^1]);

            buffer.Dispose();

            ByteAssert.AllZero(rented);
        }
        finally
        {
            buffer.Dispose();
        }
    }

    [Fact]
    public void Dispose_ExceptionAfterWritingIntoSpan_ZeroesUncommittedBytesWhenUsingScopeUnwinds()
    {
        byte[] secret = Encoding.UTF8.GetBytes("{\"card\":\"4111111111111111\",\"cvv\":\"123\"}");
        byte[]? rented = null;

        Action produceBody = () =>
        {
            using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, secret.Length);
            rented = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
            secret.CopyTo(buffer.GetSpan(secret.Length));
            throw new InvalidOperationException("The body producer failed before calling Advance.");
        };

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(produceBody);

        Assert.Equal("The body producer failed before calling Advance.", exception.Message);
        Assert.NotNull(rented);
        ByteAssert.AllZero(rented);
    }

    [Fact]
    public void Dispose_Utf8JsonWriterFailsBeforeFlush_ZeroesPendingJson()
    {
        byte[]? rented = null;
        int pendingBytes = 0;

        Action serialize = () =>
        {
            using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, bodyLengthHint: 4_096);
            rented = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);

            // The writer is deliberately not disposed: disposing it would flush (commit) the pending JSON.
            var writer = new Utf8JsonWriter(buffer);
            writer.WriteStartObject();
            writer.WriteString("password", "correct horse battery staple");
            pendingBytes = writer.BytesPending;

            // Precondition: the JSON sits in the pooled array but has not been committed yet.
            Assert.Equal(Header.Length, buffer.WrittenCount);
            Assert.Equal("{\"password\":\"correct horse battery staple\"", Encoding.UTF8.GetString(rented, Header.Length, pendingBytes));
            throw new InvalidOperationException("Serialization failed.");
        };

        Assert.Throws<InvalidOperationException>(serialize);

        Assert.True(pendingBytes > 0);
        Assert.NotNull(rented);
        ByteAssert.AllZero(rented);
    }

    [Fact]
    public void Dispose_StreamFaultsAfterPartiallyFillingSpan_ZeroesEveryArrayTheReadTouched()
    {
        var touched = new List<byte[]>();
        using var body = new FaultingStream(TestBytes.Pattern(50_000, seed: 3), bytesWrittenByFaultingRead: 1_000, fill: Marker);

        Assert.Throws<IOException>(() =>
        {
            using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
            touched.Add(PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount));
            ReadToEnd(body, buffer, touched);
        });

        Assert.True(body.FaultRaised);
        Assert.True(touched.Distinct().Count() > 1, "Expected the reads to grow the buffer at least once.");
        Assert.All(touched, array => ByteAssert.AllZero(array));
    }

    [Fact]
    public async Task Dispose_StreamFaultsAsynchronouslyAfterPartiallyFillingMemory_ZeroesEveryArrayTheReadTouched()
    {
        var touched = new List<byte[]>();
        await using var body = new FaultingStream(TestBytes.Pattern(50_000, seed: 5), bytesWrittenByFaultingRead: ReadChunkSize, fill: Marker);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await Assert.ThrowsAsync<IOException>(async () =>
        {
            using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
            touched.Add(PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount));
            await ReadToEndAsync(body, buffer, touched, cancellationToken);
        });

        Assert.True(body.FaultRaised);
        Assert.True(touched.Distinct().Count() > 1, "Expected the reads to grow the buffer at least once.");
        Assert.All(touched, array => ByteAssert.AllZero(array));
    }

    [Theory]
    [MemberData(nameof(WriteThroughMemory))]
    public void Growth_AfterUncommittedWrite_ZeroesWholeReplacedArrayAndKeepsOnlyCommittedBytes(bool throughMemory)
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        byte[] original = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
        Span<byte> free = buffer.GetSpan();
        free.Fill(Marker);
        int committed = free.Length / 2;
        buffer.Advance(committed);
        Assert.Equal(Marker, original[^1]);

        // Asking for more than the whole original array forces a move to a larger one.
        int required = original.Length;
        int available = throughMemory ? buffer.GetMemory(required).Length : buffer.GetSpan(required).Length;

        byte[] replacement = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
        Assert.NotSame(original, replacement);
        Assert.True(available >= required);
        ByteAssert.AllZero(original);
        ByteAssert.Equal([.. Header, .. Enumerable.Repeat(Marker, committed)], buffer.WrittenSpan);
    }

    [Theory]
    [MemberData(nameof(WriteThroughMemory))]
    public void Growth_SizeHintEqualToFreeSpace_KeepsArrayAndItsUncommittedBytes(bool throughMemory)
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        byte[] original = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
        Span<byte> free = buffer.GetSpan();
        free.Fill(Marker);

        int length = throughMemory ? buffer.GetMemory(free.Length).Length : buffer.GetSpan(free.Length).Length;

        Assert.Equal(free.Length, length);
        Assert.Same(original, PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount));
        Assert.Equal(-1, original.AsSpan(Header.Length).IndexOfAnyExcept(Marker));
    }

    [Theory]
    [MemberData(nameof(WriteThroughMemory))]
    public void Growth_SizeHintOneByteLargerThanFreeSpace_ReplacesAndZeroesArray(bool throughMemory)
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        byte[] original = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
        Span<byte> free = buffer.GetSpan();
        free.Fill(Marker);
        int sizeHint = free.Length + 1;

        int length = throughMemory ? buffer.GetMemory(sizeHint).Length : buffer.GetSpan(sizeHint).Length;

        Assert.True(length >= sizeHint);
        Assert.NotSame(original, PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount));
        ByteAssert.AllZero(original);
        ByteAssert.Equal(Header, buffer.WrittenSpan);
    }

    [Fact]
    public void Growth_RepeatedWithUncommittedTails_ZeroesEveryReplacedArrayAndFinalArrayOnDispose()
    {
        var arrays = new List<byte[]>();
        var expectedBody = new List<byte>();
        var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        try
        {
            for (int round = 0; round < 6; round++)
            {
                byte[] current = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
                arrays.Add(current);
                Span<byte> free = buffer.GetSpan();
                byte fill = (byte)(0x10 + round);
                free.Fill(fill);
                int committed = free.Length / 3;
                buffer.Advance(committed);
                expectedBody.AddRange(Enumerable.Repeat(fill, committed));

                buffer.GetSpan(current.Length);

                // Every replaced array is wiped immediately, not only when the buffer is disposed.
                ByteAssert.AllZero(current);
            }

            byte[] last = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
            Assert.DoesNotContain(arrays, array => ReferenceEquals(array, last));
            buffer.GetSpan().Fill(0xEE);
            ByteAssert.Equal([.. Header, .. expectedBody], buffer.WrittenSpan);

            buffer.Dispose();

            Assert.All(arrays, array => ByteAssert.AllZero(array));
            ByteAssert.AllZero(last);
        }
        finally
        {
            buffer.Dispose();
        }
    }

    [Fact]
    public void Growth_BeyondMaximumSize_ThrowsAndKeepsArrayUntilDisposeZeroesIt()
    {
        var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        try
        {
            byte[] rented = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
            buffer.GetSpan().Fill(Marker);

            Assert.Throws<InsufficientMemoryException>(() => { buffer.GetSpan(int.MaxValue); });
            Assert.Throws<InsufficientMemoryException>(() => buffer.GetMemory(Array.MaxLength - Header.Length + 1));

            // The failed growth neither released nor wiped the live array.
            Assert.Same(rented, PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount));
            Assert.Equal(-1, rented.AsSpan(Header.Length).IndexOfAnyExcept(Marker));
            ByteAssert.Equal(Header, buffer.WrittenSpan);

            buffer.Dispose();

            ByteAssert.AllZero(rented);
        }
        finally
        {
            buffer.Dispose();
        }
    }

    [Fact]
    public void Create_NonAsciiMethod_ReturnsWipedArrayToPool()
    {
        // 3 000 bytes of body hint puts the initial rent in the same 4 KiB bucket as the planted array.
        byte[] planted = PooledArrays.PlantDirtyArray(4_096, Stale);

        Assert.Throws<ArgumentException>(() => CanonicalRequestBuffer.Create("GÉT", PathAndQuery, Timestamp, bodyLengthHint: 3_000));

        // The failed Create rented the planted array, wiped all of it (including stale bytes it never wrote) and returned it.
        ByteAssert.AllZero(planted);
        byte[] next = ArrayPool<byte>.Shared.Rent(4_096);
        try
        {
            Assert.Same(planted, next);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(next);
        }
    }

    [Fact]
    public void Dispose_ArrayRentedWithStaleData_WipesStaleBytesTheBufferNeverWrote()
    {
        byte[] planted = PooledArrays.PlantDirtyArray(4_096, Stale);
        var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, bodyLengthHint: 3_000);
        try
        {
            Assert.Same(planted, PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount));
            Assert.Equal(Stale, planted[^1]);

            buffer.Dispose();

            ByteAssert.AllZero(planted);
        }
        finally
        {
            buffer.Dispose();
        }
    }

    [Fact]
    public void Dispose_CalledTwice_ReturnsArrayToPoolOnlyOnce()
    {
        var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, bodyLengthHint: 3_000);
        byte[] rented = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
        Assert.Equal(4_096, rented.Length);

        buffer.Dispose();
        buffer.Dispose();

        // A second return would make the pool hand the same array to two renters.
        byte[] first = ArrayPool<byte>.Shared.Rent(4_096);
        byte[] second = ArrayPool<byte>.Shared.Rent(4_096);
        try
        {
            Assert.Same(rented, first);
            Assert.NotSame(first, second);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(second);
            ArrayPool<byte>.Shared.Return(first);
        }
    }

    private static void ReadToEnd(Stream source, CanonicalRequestBuffer destination, List<byte[]> touched)
    {
        while (true)
        {
            Memory<byte> memory = destination.GetMemory(ReadChunkSize);
            touched.Add(PooledArrays.GetBackingArray(memory, destination.WrittenCount));
            int read = source.Read(memory.Span);
            if (read == 0)
            {
                return;
            }

            destination.Advance(read);
        }
    }

    private static async Task ReadToEndAsync(Stream source, CanonicalRequestBuffer destination, List<byte[]> touched, CancellationToken cancellationToken)
    {
        while (true)
        {
            Memory<byte> memory = destination.GetMemory(ReadChunkSize);
            touched.Add(PooledArrays.GetBackingArray(memory, destination.WrittenCount));
            int read = await source.ReadAsync(memory, cancellationToken);
            if (read == 0)
            {
                return;
            }

            destination.Advance(read);
        }
    }

    /// <summary>
    /// A request body that delivers its payload in small chunks, then fills part of the next destination and faults,
    /// like a connection that is reset in the middle of a read.
    /// </summary>
    private sealed class FaultingStream(byte[] payload, int bytesWrittenByFaultingRead, byte fill) : Stream
    {
        private const int MaxChunk = 3_000;

        private int _position;

        public bool FaultRaised { get; private set; }

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
            if (_position < payload.Length)
            {
                int length = Math.Min(Math.Min(MaxChunk, buffer.Length), payload.Length - _position);
                payload.AsSpan(_position, length).CopyTo(buffer);
                _position += length;
                return length;
            }

            buffer[..Math.Min(bytesWrittenByFaultingRead, buffer.Length)].Fill(fill);
            FaultRaised = true;
            throw new IOException("The connection was reset while the body was being read.");
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            return Read(buffer.Span);
        }

        public override void Flush() => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
