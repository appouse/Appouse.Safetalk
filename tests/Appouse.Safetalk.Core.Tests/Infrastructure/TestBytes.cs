namespace Appouse.Safetalk.Core.Tests.Infrastructure;

/// <summary>
/// Deterministic test payloads (no <see cref="Random"/>, so every run uses identical data).
/// </summary>
internal static class TestBytes
{
    /// <summary>
    /// Returns a pseudo-random byte pattern produced by a fixed-seed xorshift generator.
    /// </summary>
    public static byte[] Pattern(int length, uint seed = 0x9E3779B9)
    {
        var bytes = new byte[length];
        uint state = seed == 0 ? 1u : seed;
        for (int i = 0; i < bytes.Length; i++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[i] = (byte)state;
        }

        return bytes;
    }

    /// <summary>
    /// Returns every byte value 0x00..0xFF, repeated <paramref name="repetitions"/> times.
    /// </summary>
    public static byte[] AllByteValues(int repetitions = 1)
    {
        var bytes = new byte[256 * repetitions];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)i;
        }

        return bytes;
    }

    /// <summary>
    /// Returns a deterministic sequence of chunk lengths in [1, <paramref name="maxChunk"/>] that sum to <paramref name="total"/>.
    /// </summary>
    public static IEnumerable<int> ChunkLengths(int total, int maxChunk, uint seed = 12345)
    {
        uint state = seed;
        int remaining = total;
        while (remaining > 0)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            int chunk = Math.Min(remaining, (int)(state % (uint)maxChunk) + 1);
            remaining -= chunk;
            yield return chunk;
        }
    }
}
