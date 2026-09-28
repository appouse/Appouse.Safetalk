namespace Appouse.Safetalk.Core.Tests.Infrastructure;

/// <summary>
/// Fast byte sequence assertions with a useful failure message for large payloads.
/// </summary>
internal static class ByteAssert
{
    public static void Equal(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        if (expected.SequenceEqual(actual))
        {
            return;
        }

        int firstDifference = expected.CommonPrefixLength(actual);
        Assert.Fail(
            $"Byte sequences differ. Expected length: {expected.Length}, actual length: {actual.Length}, first difference at index {firstDifference}.");
    }

    public static void AllZero(ReadOnlySpan<byte> actual)
    {
        int index = actual.IndexOfAnyExcept((byte)0);
        if (index >= 0)
        {
            Assert.Fail($"Expected all {actual.Length} bytes to be zero, but byte {index} is 0x{actual[index]:X2}.");
        }
    }
}
