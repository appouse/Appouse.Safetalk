using Appouse.Safetalk.Core.Tests.Infrastructure;

namespace Appouse.Safetalk.Core.Tests;

public sealed class HexEncodingTests
{
    [Fact]
    public void ToLowerHex_Empty_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, HexEncoding.ToLowerHex(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void ToLowerHex_AllByteValues_MatchesReferenceEncoding()
    {
        byte[] bytes = TestBytes.AllByteValues();

        string hex = HexEncoding.ToLowerHex(bytes);

        Assert.Equal(ReferenceHmac.ToLowerHex(bytes), hex);
        Assert.StartsWith("000102030405060708090a0b0c0d0e0f10", hex, StringComparison.Ordinal);
        Assert.EndsWith("f9fafbfcfdfeff", hex, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(1_000)]
    [InlineData(100_000)]
    public void ToLowerHex_InputOfAnyLength_MatchesReferenceEncoding(int length)
    {
        byte[] bytes = TestBytes.Pattern(length);

        string hex = HexEncoding.ToLowerHex(bytes);

        Assert.Equal(length * 2, hex.Length);
        Assert.Equal(ReferenceHmac.ToLowerHex(bytes), hex);
    }

    [Fact]
    public void ToLowerHex_Output_ContainsOnlyLowerCaseHexDigits()
    {
        string hex = HexEncoding.ToLowerHex(TestBytes.AllByteValues(repetitions: 2));

        Assert.All(hex, c => Assert.True(c is (>= '0' and <= '9') or (>= 'a' and <= 'f'), $"Unexpected character '{c}'."));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(129)]
    [InlineData(4_096)]
    public void TryDecode_LowerCaseHex_RoundTrips(int length)
    {
        byte[] original = TestBytes.Pattern(length, seed: 99);
        string hex = HexEncoding.ToLowerHex(original);
        var decoded = new byte[length];

        Assert.True(HexEncoding.TryDecode(hex, decoded));

        Assert.Equal(original, decoded);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(129)]
    [InlineData(4_096)]
    public void TryDecode_UpperCaseHex_RoundTrips(int length)
    {
        byte[] original = TestBytes.Pattern(length, seed: 101);
        string hex = HexEncoding.ToLowerHex(original).ToUpperInvariant();
        var decoded = new byte[length];

        Assert.True(HexEncoding.TryDecode(hex, decoded));

        Assert.Equal(original, decoded);
    }

    [Fact]
    public void TryDecode_AllByteValuesInEitherCase_MatchConvertFromHexString()
    {
        byte[] original = TestBytes.AllByteValues();
        string upper = Convert.ToHexString(original);
        string lower = HexEncoding.ToLowerHex(original);
        var fromUpper = new byte[original.Length];
        var fromLower = new byte[original.Length];

        Assert.True(HexEncoding.TryDecode(upper, fromUpper));
        Assert.True(HexEncoding.TryDecode(lower, fromLower));

        Assert.Equal(Convert.FromHexString(upper), fromUpper);
        Assert.Equal(original, fromUpper);
        Assert.Equal(original, fromLower);
    }

    [Theory]
    [InlineData("0", 0x0)]
    [InlineData("1", 0x1)]
    [InlineData("9", 0x9)]
    [InlineData("a", 0xA)]
    [InlineData("A", 0xA)]
    [InlineData("c", 0xC)]
    [InlineData("C", 0xC)]
    [InlineData("f", 0xF)]
    [InlineData("F", 0xF)]
    public void TryDecode_EachHexDigit_DecodesToItsNibbleInBothPositions(string digit, int nibble)
    {
        Span<byte> destination = stackalloc byte[2];

        Assert.True(HexEncoding.TryDecode(digit + "0" + "0" + digit, destination));

        Assert.Equal((byte)(nibble << 4), destination[0]);
        Assert.Equal((byte)nibble, destination[1]);
    }

    [Fact]
    public void TryDecode_EmptyHexAndEmptyDestination_ReturnsTrue()
    {
        Assert.True(HexEncoding.TryDecode(ReadOnlySpan<char>.Empty, Span<byte>.Empty));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(3, 2)]
    [InlineData(2, 0)]
    [InlineData(0, 1)]
    [InlineData(62, 32)]
    [InlineData(63, 32)]
    [InlineData(65, 32)]
    [InlineData(66, 32)]
    [InlineData(32, 32)]
    [InlineData(128, 32)]
    public void TryDecode_LengthMismatch_ReturnsFalse(int hexLength, int destinationLength)
    {
        string hex = new('a', hexLength);
        var destination = new byte[destinationLength];

        Assert.False(HexEncoding.TryDecode(hex, destination));
    }

    [Theory]
    [InlineData('/')] // just below '0'
    [InlineData(':')] // just above '9'
    [InlineData('@')] // just below 'A'
    [InlineData('G')] // just above 'F'
    [InlineData('`')] // just below 'a'
    [InlineData('g')] // just above 'f'
    [InlineData('x')]
    [InlineData(' ')]
    [InlineData('\0')]
    [InlineData('\u00FF')]
    [InlineData('\u0130')]
    [InlineData('\uFF10')] // FULLWIDTH DIGIT ZERO
    [InlineData('\uFF21')] // FULLWIDTH LATIN CAPITAL LETTER A
    [InlineData('\u0663')] // ARABIC-INDIC DIGIT THREE
    [InlineData('\u00B2')] // SUPERSCRIPT TWO
    public void TryDecode_CharacterOutsideHexAlphabetAtAnyPosition_ReturnsFalse(char invalid)
    {
        const string valid = "00112233445566778899aabbccddeeffAABBCCDDEEFF0123";
        var destination = new byte[valid.Length / 2];
        Assert.True(HexEncoding.TryDecode(valid, destination));

        for (int position = 0; position < valid.Length; position++)
        {
            char[] hex = valid.ToCharArray();
            hex[position] = invalid;

            Assert.False(HexEncoding.TryDecode(hex, destination), $"Invalid character at position {position} was accepted.");
        }
    }
}
