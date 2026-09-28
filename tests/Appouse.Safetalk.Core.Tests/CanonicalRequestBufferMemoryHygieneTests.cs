using System.Runtime.InteropServices;
using System.Text;
using Appouse.Safetalk.Core.Tests.Infrastructure;

namespace Appouse.Safetalk.Core.Tests;

/// <summary>
/// Verifies that request payloads are wiped from pooled arrays before they are handed back to the shared pool.
/// </summary>
[Collection(ArrayPoolInspectionDefinition.Name)]
public sealed class CanonicalRequestBufferMemoryHygieneTests
{
    private const string Timestamp = "1700000000";
    private const byte Marker = 0xA5;

    [Fact]
    public void Dispose_WrittenBytes_AreZeroedInRentedArray()
    {
        const int bodyLength = 150_000;
        var buffer = CanonicalRequestBuffer.Create("POST", "/api/secret-orders", Timestamp, bodyLength);
        try
        {
            byte[] rented = PooledArrays.GetBackingArray(buffer.GetMemory(bodyLength), buffer.WrittenCount);
            buffer.GetSpan(bodyLength)[..bodyLength].Fill(Marker);
            buffer.Advance(bodyLength);
            int written = buffer.WrittenCount;

            // Precondition: the header and body are really stored in the inspected array.
            Assert.Equal(Encoding.UTF8.GetBytes("POST\n/api/secret-orders\n1700000000\n"), rented.AsSpan(0, written - bodyLength).ToArray());
            Assert.Equal(-1, rented.AsSpan(written - bodyLength, bodyLength).IndexOfAnyExcept(Marker));

            buffer.Dispose();

            ByteAssert.AllZero(rented.AsSpan(0, written));
        }
        finally
        {
            buffer.Dispose();
        }
    }

    [Fact]
    public void GetSpan_WhenGrowing_ZeroesWrittenBytesOfReplacedArray()
    {
        const int initialBodyLength = 100_000;
        using var buffer = CanonicalRequestBuffer.Create("POST", "/api/secret-orders", Timestamp, initialBodyLength);
        byte[] original = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
        buffer.GetSpan(initialBodyLength)[..initialBodyLength].Fill(Marker);
        buffer.Advance(initialBodyLength);
        int written = buffer.WrittenCount;

        // Requesting more than the whole original array forces a move to a larger array.
        buffer.GetSpan(original.Length);

        byte[] replacement = PooledArrays.GetBackingArray(buffer.GetMemory(), buffer.WrittenCount);
        Assert.NotSame(original, replacement);
        ByteAssert.AllZero(original.AsSpan(0, written));

        byte[] expectedBody = Enumerable.Repeat(Marker, initialBodyLength).ToArray();
        ByteAssert.Equal([.. "POST\n/api/secret-orders\n1700000000\n"u8, .. expectedBody], buffer.WrittenSpan);
    }

    [Fact]
    public void GetMemory_AfterCreate_ReturnsMemoryDirectlyAfterHeaderInBackingArray()
    {
        using var buffer = CanonicalRequestBuffer.Create("GET", "/", Timestamp);

        Assert.True(MemoryMarshal.TryGetArray<byte>(buffer.GetMemory(), out ArraySegment<byte> segment));

        Assert.Equal(buffer.WrittenCount, segment.Offset);
    }
}
