using System.Security.Cryptography;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Deterministic payload helpers.
/// </summary>
internal static class TestData
{
    /// <summary>
    /// Creates a deterministic, non-repeating pseudo-random payload (xorshift32), so that misplaced or duplicated
    /// chunks change the hash.
    /// </summary>
    public static byte[] CreateBytes(int length, uint seed = 0x9E3779B9)
    {
        var bytes = new byte[length];
        uint state = seed == 0 ? 1 : seed;
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
    /// Returns the upper-case hexadecimal SHA-256 hash of the bytes.
    /// </summary>
    public static string Sha256Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));
}
