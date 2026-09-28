using System.Buffers;
using System.Text;
using System.Text.Json;
using Appouse.Safetalk.Core.Tests.Infrastructure;

namespace Appouse.Safetalk.Core.Tests;

public sealed class CanonicalRequestBufferWriterTests
{
    private const string Method = "POST";
    private const string PathAndQuery = "/api/orders?id=5";
    private const string Timestamp = "1700000000";
    private const int LargeBodyLength = (1 << 20) + 12_345;

    private static readonly byte[] Header = Encoding.UTF8.GetBytes($"{Method}\n{PathAndQuery}\n{Timestamp}\n");

    public static TheoryData<string> TextBodies => new()
    {
        string.Empty,
        "{\"a\":1}",
        "line1\nline2\r\nline3\n",
        "\u015Fifre \u011F\u00FC\u00E7\u00F6\u0131 \u0130 \u20AC \uD83D\uDE00",
        "\0\0\0",
        new string('z', 300),
    };

    public static TheoryData<int> LargeBodyLengthHints => new()
    {
        0,
        1,
        4_096,
        LargeBodyLength / 2,
        LargeBodyLength - 1,
        LargeBodyLength,
        LargeBodyLength + 1,
        LargeBodyLength * 2,
    };

    [Theory]
    [MemberData(nameof(TextBodies))]
    public void GetSpanAndAdvance_TextBody_ProducesUtf8OfFormat(string body)
    {
        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        Span<byte> span = buffer.GetSpan(bodyBytes.Length);
        bodyBytes.CopyTo(span);
        buffer.Advance(bodyBytes.Length);

        ByteAssert.Equal(Encoding.UTF8.GetBytes(CanonicalRequest.Format(Method, PathAndQuery, Timestamp, body)), buffer.WrittenSpan);
    }

    [Theory]
    [MemberData(nameof(TextBodies))]
    public void GetMemoryAndAdvance_TextBody_ProducesUtf8OfFormat(string body)
    {
        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        Memory<byte> memory = buffer.GetMemory(bodyBytes.Length);
        bodyBytes.CopyTo(memory);
        buffer.Advance(bodyBytes.Length);

        ByteAssert.Equal(Encoding.UTF8.GetBytes(CanonicalRequest.Format(Method, PathAndQuery, Timestamp, body)), buffer.WrittenSpan);
    }

    [Theory]
    [MemberData(nameof(TextBodies))]
    public void BuffersExtensionsWrite_TextBody_ProducesUtf8OfFormat(string body)
    {
        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        BuffersExtensions.Write(buffer, bodyBytes.AsSpan());

        ByteAssert.Equal(Encoding.UTF8.GetBytes(CanonicalRequest.Format(Method, PathAndQuery, Timestamp, body)), buffer.WrittenSpan);
    }

    [Fact]
    public void GetMemory_ExactContentLength_AllowsSingleShotFill()
    {
        // Mirrors the server path: GetMemory(length)[..length] is filled in one read, then Advance(length).
        byte[] body = TestBytes.Pattern(70_000);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, body.Length);

        Memory<byte> memory = buffer.GetMemory(body.Length)[..body.Length];
        body.CopyTo(memory);
        buffer.Advance(body.Length);

        ByteAssert.Equal([.. Header, .. body], buffer.WrittenSpan);
    }

    [Fact]
    public void Write_BinaryBodyWithAllByteValues_IsAppendedVerbatim()
    {
        byte[] body = TestBytes.AllByteValues(repetitions: 4);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        BuffersExtensions.Write(buffer, body.AsSpan());

        ByteAssert.Equal([.. Header, .. body], buffer.WrittenSpan);
        Assert.Equal(Header.Length + body.Length, buffer.WrittenCount);
    }

    [Fact]
    public void Write_OneByteAtATime_GrowsAndPreservesContent()
    {
        byte[] body = TestBytes.Pattern(20_000);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        foreach (byte value in body)
        {
            buffer.GetSpan(1)[0] = value;
            buffer.Advance(1);
        }

        ByteAssert.Equal([.. Header, .. body], buffer.WrittenSpan);
    }

    [Fact]
    public void Write_ChunksOfVaryingSize_GrowsAndPreservesContent()
    {
        byte[] body = TestBytes.Pattern(3 * 1024 * 1024);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        int offset = 0;
        foreach (int chunkLength in TestBytes.ChunkLengths(body.Length, maxChunk: 70_000))
        {
            Span<byte> span = buffer.GetSpan(chunkLength);
            Assert.True(span.Length >= chunkLength);
            body.AsSpan(offset, chunkLength).CopyTo(span);
            buffer.Advance(chunkLength);
            offset += chunkLength;
        }

        Assert.Equal(body.Length, offset);
        ByteAssert.Equal([.. Header, .. body], buffer.WrittenSpan);
    }

    [Theory]
    [MemberData(nameof(LargeBodyLengthHints))]
    public void Write_BodyLargerThanOneMebibyteInFixedChunks_PreservesContentForAnyHint(int bodyLengthHint)
    {
        byte[] body = TestBytes.Pattern(LargeBodyLength, seed: 7);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, bodyLengthHint);

        const int chunkSize = 8 * 1024;
        for (int offset = 0; offset < body.Length; offset += chunkSize)
        {
            int length = Math.Min(chunkSize, body.Length - offset);
            Memory<byte> memory = buffer.GetMemory(chunkSize);
            body.AsMemory(offset, length).CopyTo(memory);
            buffer.Advance(length);
        }

        ByteAssert.Equal([.. Header, .. body], buffer.WrittenSpan);
    }

    [Theory]
    [MemberData(nameof(LargeBodyLengthHints))]
    public void Write_BodyLargerThanOneMebibyteInOneCall_PreservesContentForAnyHint(int bodyLengthHint)
    {
        byte[] body = TestBytes.Pattern(LargeBodyLength, seed: 11);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp, bodyLengthHint);

        BuffersExtensions.Write(buffer, body.AsSpan());

        ByteAssert.Equal([.. Header, .. body], buffer.WrittenSpan);
    }

    [Fact]
    public void EncodingGetBytes_LargeUnicodeBodyEncodedIntoBuffer_ProducesUtf8OfFormat()
    {
        var builder = new StringBuilder();
        for (int i = 0; i < 40_000; i++)
        {
            builder.Append("\u015Fifre-\u011F\u00FC\u00E7\u00F6\u0131-\u20AC-\uD83D\uDE00-");
        }

        string body = builder.ToString();
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        Encoding.UTF8.GetBytes(body.AsSpan(), buffer);

        ByteAssert.Equal(Encoding.UTF8.GetBytes(CanonicalRequest.Format(Method, PathAndQuery, Timestamp, body)), buffer.WrittenSpan);
    }

    [Fact]
    public void Utf8JsonWriter_SerializesDirectlyIntoBuffer_ProducesHeaderFollowedByJson()
    {
        var reference = new ArrayBufferWriter<byte>();
        WriteOrderJson(reference);
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        WriteOrderJson(buffer);

        ByteAssert.Equal([.. Header, .. reference.WrittenSpan], buffer.WrittenSpan);
    }

    [Fact]
    public void GetSpan_ZeroSizeHintWhenBufferIsFull_ReturnsNonEmptySpan()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        FillRemainingCapacity(buffer);

        Span<byte> span = buffer.GetSpan(0);

        Assert.True(span.Length >= 1);
    }

    [Fact]
    public void GetMemory_ZeroSizeHintWhenBufferIsFull_ReturnsNonEmptyMemory()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        FillRemainingCapacity(buffer);

        Memory<byte> memory = buffer.GetMemory(0);

        Assert.True(memory.Length >= 1);
    }

    [Fact]
    public void GetSpan_AfterBufferIsFull_KeepsPreviouslyWrittenBytes()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        int filled = FillRemainingCapacity(buffer, fill: 0x5A);

        buffer.GetSpan(0)[0] = 0x42;
        buffer.Advance(1);

        byte[] expectedBody = [.. Enumerable.Repeat((byte)0x5A, filled), 0x42];
        ByteAssert.Equal([.. Header, .. expectedBody], buffer.WrittenSpan);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(4_096)]
    [InlineData(65_537)]
    [InlineData(1_048_577)]
    public void GetSpan_SizeHint_ReturnsAtLeastRequestedLength(int sizeHint)
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        Assert.True(buffer.GetSpan(sizeHint).Length >= sizeHint);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(4_096)]
    [InlineData(65_537)]
    [InlineData(1_048_577)]
    public void GetMemory_SizeHint_ReturnsAtLeastRequestedLength(int sizeHint)
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        Assert.True(buffer.GetMemory(sizeHint).Length >= sizeHint);
    }

    [Fact]
    public void GetSpan_LargeSizeHintAfterWriting_GrowsAndKeepsWrittenBytes()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"a\":1}");
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        BuffersExtensions.Write(buffer, body.AsSpan());

        Span<byte> span = buffer.GetSpan(10 * 1024 * 1024);

        Assert.True(span.Length >= 10 * 1024 * 1024);
        ByteAssert.Equal([.. Header, .. body], buffer.WrittenSpan);
    }

    [Fact]
    public void GetSpan_WithoutAdvance_DoesNotCommitBytes()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        buffer.GetSpan(16).Fill(0xFF);
        buffer.GetMemory(16).Span.Fill(0xFF);

        Assert.Equal(Header.Length, buffer.WrittenCount);
        ByteAssert.Equal(Header, buffer.WrittenSpan);
    }

    [Fact]
    public void GetSpan_AfterPartialAdvance_ContinuesDirectlyAfterCommittedBytes()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        Span<byte> first = buffer.GetSpan(10);
        "0123456789"u8.CopyTo(first);
        buffer.Advance(4);

        Span<byte> second = buffer.GetSpan(3);
        "abc"u8.CopyTo(second);
        buffer.Advance(3);

        ByteAssert.Equal([.. Header, .. "0123abc"u8], buffer.WrittenSpan);
    }

    [Fact]
    public void GetSpan_NegativeSizeHint_ThrowsArgumentOutOfRangeException()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() => { buffer.GetSpan(-1); });

        Assert.Equal("sizeHint", exception.ParamName);
    }

    [Fact]
    public void GetMemory_NegativeSizeHint_ThrowsArgumentOutOfRangeException()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() => { buffer.GetMemory(-1); });

        Assert.Equal("sizeHint", exception.ParamName);
    }

    [Fact]
    public void Advance_Zero_DoesNotChangeWrittenData()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        buffer.Advance(0);

        ByteAssert.Equal(Header, buffer.WrittenSpan);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Advance_NegativeCount_ThrowsAndLeavesBufferUnchanged(int count)
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() => buffer.Advance(count));

        Assert.Equal("count", exception.ParamName);
        ByteAssert.Equal(Header, buffer.WrittenSpan);
    }

    [Fact]
    public void Advance_PastEndOfBuffer_ThrowsAndLeavesBufferUsable()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);
        int available = buffer.GetSpan().Length;

        Assert.Throws<InvalidOperationException>(() => buffer.Advance(available + 1));
        Assert.Equal(Header.Length, buffer.WrittenCount);

        buffer.GetSpan()[..available].Fill(0x33);
        buffer.Advance(available);
        Assert.Equal(Header.Length + available, buffer.WrittenCount);
    }

    [Fact]
    public void Advance_IntMaxValue_ThrowsInvalidOperationException()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        Assert.Throws<InvalidOperationException>(() => buffer.Advance(int.MaxValue));
        Assert.Equal(Header.Length, buffer.WrittenCount);
    }

    [Fact]
    public void Advance_PartOfReturnedSpan_CommitsOnlyAdvancedBytes()
    {
        using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, Timestamp);

        "0123456789"u8.CopyTo(buffer.GetSpan(10));
        buffer.Advance(4);

        ByteAssert.Equal([.. Header, .. "0123"u8], buffer.WrittenSpan);
        Assert.Equal(Header.Length + 4, buffer.WrittenCount);
    }

    [Fact]
    public void Create_ManyBuffersInSequence_EachContainsOnlyItsOwnContent()
    {
        for (int i = 0; i < 200; i++)
        {
            string body = new string((char)('a' + (i % 26)), i * 37);
            string timestamp = (1_700_000_000 + i).ToString(System.Globalization.CultureInfo.InvariantCulture);
            using var buffer = CanonicalRequestBuffer.Create(Method, PathAndQuery, timestamp);

            Encoding.UTF8.GetBytes(body.AsSpan(), buffer);

            ByteAssert.Equal(Encoding.UTF8.GetBytes(CanonicalRequest.Format(Method, PathAndQuery, timestamp, body)), buffer.WrittenSpan);
        }
    }

    private static int FillRemainingCapacity(CanonicalRequestBuffer buffer, byte fill = 0x61)
    {
        Span<byte> remaining = buffer.GetSpan();
        remaining.Fill(fill);
        buffer.Advance(remaining.Length);
        return remaining.Length;
    }

    private static void WriteOrderJson(IBufferWriter<byte> destination)
    {
        using var writer = new Utf8JsonWriter(destination);
        writer.WriteStartObject();
        writer.WriteString("customer", "\u015E\u00FCkr\u00FC \u00D6z\u00E7elik");
        writer.WriteStartArray("lines");
        for (int i = 0; i < 20_000; i++)
        {
            writer.WriteStartObject();
            writer.WriteNumber("id", i);
            writer.WriteString("sku", $"SKU-{i:D6}");
            writer.WriteNumber("price", i * 1.25m);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();
    }
}
