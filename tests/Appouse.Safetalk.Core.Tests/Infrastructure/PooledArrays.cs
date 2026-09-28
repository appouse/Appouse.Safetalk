using System.Buffers;
using System.Runtime.InteropServices;

namespace Appouse.Safetalk.Core.Tests.Infrastructure;

/// <summary>
/// Helpers for inspecting the arrays that <see cref="CanonicalRequestBuffer"/> rents from <see cref="ArrayPool{T}.Shared"/>.
/// Tests using them must belong to the <see cref="ArrayPoolInspectionDefinition"/> collection.
/// </summary>
internal static class PooledArrays
{
    /// <summary>
    /// Returns the pooled array behind memory handed out by <see cref="CanonicalRequestBuffer.GetMemory"/>.
    /// </summary>
    public static byte[] GetBackingArray(Memory<byte> memory, int expectedOffset)
    {
        Assert.True(MemoryMarshal.TryGetArray<byte>(memory, out ArraySegment<byte> segment), "Expected array-backed memory.");
        Assert.Equal(expectedOffset, segment.Offset);
        Assert.Equal(segment.Array!.Length, segment.Offset + segment.Count);
        return segment.Array;
    }

    /// <summary>
    /// Plants an array full of <paramref name="fill"/> in the calling thread's cache of <see cref="ArrayPool{T}.Shared"/>,
    /// so that the next rent of the same size bucket on this thread receives exactly that (dirty) array.
    /// </summary>
    /// <remarks>
    /// The shared pool serves a rent from the per-thread slot that the latest return on the same thread filled. The method
    /// verifies that behaviour first, so a test fails loudly instead of inspecting the wrong array if it ever changes.
    /// </remarks>
    public static byte[] PlantDirtyArray(int length, byte fill)
    {
        byte[] probe = ArrayPool<byte>.Shared.Rent(length);
        ArrayPool<byte>.Shared.Return(probe);
        byte[] planted = ArrayPool<byte>.Shared.Rent(length);
        Assert.Same(probe, planted);

        planted.AsSpan().Fill(fill);
        ArrayPool<byte>.Shared.Return(planted, clearArray: false);
        return planted;
    }
}
