using System.Text;
using Appouse.Safetalk.Core.Tests.Infrastructure;

namespace Appouse.Safetalk.Core.Tests;

public sealed class HmacSha256SignatureServiceVerifyTests
{
    private const string Secret = "verify-secret";
    private const string HexDigits = "0123456789abcdef";

    private static readonly byte[] Message = Encoding.UTF8.GetBytes("POST\n/api/orders?id=5\n1700000000\n{\"a\":1}");

    private readonly HmacSha256SignatureService _service = HmacSha256SignatureService.Instance;
    private readonly byte[] _mac = ReferenceHmac.ComputeBytes(Secret, Message);
    private readonly string _signature = ReferenceHmac.Compute(Secret, Message);

    [Fact]
    public void VerifySignature_CorrectLowerCaseSignature_ReturnsTrue()
    {
        Assert.True(_service.VerifySignature(Secret, Message, _signature));
    }

    [Fact]
    public void VerifySignature_SignatureProducedByComputeSignature_ReturnsTrue()
    {
        string signature = _service.ComputeSignature(Secret, Message);

        Assert.True(_service.VerifySignature(Secret, Message, signature));
    }

    [Fact]
    public void VerifySignature_UpperCaseSignature_ReturnsTrue()
    {
        Assert.True(_service.VerifySignature(Secret, Message, _signature.ToUpperInvariant()));
    }

    [Fact]
    public void VerifySignature_MixedCaseSignature_ReturnsTrue()
    {
        char[] mixed = _signature.ToCharArray();
        for (int i = 0; i < mixed.Length; i += 2)
        {
            mixed[i] = char.ToUpperInvariant(mixed[i]);
        }

        Assert.True(_service.VerifySignature(Secret, Message, mixed));
    }

    [Fact]
    public void VerifySignature_Rfc4231VectorInUpperCase_ReturnsTrue()
    {
        Assert.True(_service.VerifySignature(
            "Jefe",
            "what do ya want for nothing?"u8,
            "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"));
    }

    [Fact]
    public void VerifySignature_AnySingleBitFlipInMac_ReturnsFalse()
    {
        for (int bit = 0; bit < _mac.Length * 8; bit++)
        {
            byte[] flipped = _mac.ToArray();
            flipped[bit / 8] ^= (byte)(1 << (bit % 8));

            Assert.False(_service.VerifySignature(Secret, Message, ReferenceHmac.ToLowerHex(flipped)), $"Bit {bit} flip was accepted.");
        }
    }

    [Fact]
    public void VerifySignature_AnySingleHexDigitReplaced_ReturnsFalse()
    {
        for (int position = 0; position < _signature.Length; position++)
        {
            foreach (char replacement in HexDigits)
            {
                if (replacement == _signature[position])
                {
                    continue;
                }

                char[] tampered = _signature.ToCharArray();
                tampered[position] = replacement;

                Assert.False(_service.VerifySignature(Secret, Message, tampered), $"Replacing position {position} with '{replacement}' was accepted.");
            }
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(62)]
    [InlineData(63)]
    public void VerifySignature_TruncatedSignature_ReturnsFalse(int length)
    {
        Assert.False(_service.VerifySignature(Secret, Message, _signature.AsSpan(0, length)));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("00")]
    [InlineData("a")]
    [InlineData(" ")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void VerifySignature_SignatureWithAppendedCharacters_ReturnsFalse(string suffix)
    {
        Assert.False(_service.VerifySignature(Secret, Message, _signature + suffix));
    }

    [Fact]
    public void VerifySignature_SignatureRepeatedTwice_ReturnsFalse()
    {
        Assert.False(_service.VerifySignature(Secret, Message, _signature + _signature));
    }

    [Fact]
    public void VerifySignature_EmptySignature_ReturnsFalse()
    {
        Assert.False(_service.VerifySignature(Secret, Message, ReadOnlySpan<char>.Empty));
        Assert.False(_service.VerifySignature(Secret, Message, string.Empty));
    }

    [Theory]
    [InlineData('g')]
    [InlineData('G')]
    [InlineData('x')]
    [InlineData(' ')]
    [InlineData('-')]
    [InlineData('\0')]
    [InlineData('/')]
    [InlineData(':')]
    [InlineData('@')]
    [InlineData('`')]
    [InlineData('\u00E9')]
    [InlineData('\uFF10')] // FULLWIDTH DIGIT ZERO
    [InlineData('\u0663')] // ARABIC-INDIC DIGIT THREE
    public void VerifySignature_NonHexCharacterAtAnyPosition_ReturnsFalse(char invalid)
    {
        for (int position = 0; position < _signature.Length; position++)
        {
            char[] tampered = _signature.ToCharArray();
            tampered[position] = invalid;

            Assert.False(_service.VerifySignature(Secret, Message, tampered), $"Invalid character at position {position} was accepted.");
        }
    }

    [Fact]
    public void VerifySignature_HexPrefixedOrPaddedSignature_ReturnsFalse()
    {
        Assert.False(_service.VerifySignature(Secret, Message, "0x" + _signature));
        Assert.False(_service.VerifySignature(Secret, Message, "0x" + _signature[2..]));
        Assert.False(_service.VerifySignature(Secret, Message, " " + _signature[1..]));
        Assert.False(_service.VerifySignature(Secret, Message, _signature[..^1] + " "));
        Assert.False(_service.VerifySignature(Secret, Message, " " + _signature + " "));
    }

    [Fact]
    public void VerifySignature_Base64EncodedMac_ReturnsFalse()
    {
        Assert.False(_service.VerifySignature(Secret, Message, Convert.ToBase64String(_mac)));
    }

    [Fact]
    public void VerifySignature_WrongSecret_ReturnsFalse()
    {
        Assert.False(_service.VerifySignature("verify-secreT", Message, _signature));
        Assert.False(_service.VerifySignature(Secret + " ", Message, _signature));
        Assert.False(_service.VerifySignature(Secret[..^1], Message, _signature));
    }

    [Fact]
    public void VerifySignature_TamperedMessage_ReturnsFalse()
    {
        int[] positions = [0, Message.Length / 2, Message.Length - 1];
        foreach (int position in positions)
        {
            byte[] tampered = Message.ToArray();
            tampered[position] ^= 0x20;

            Assert.False(_service.VerifySignature(Secret, tampered, _signature), $"Tampering byte {position} was accepted.");
        }

        Assert.False(_service.VerifySignature(Secret, Message.AsSpan(0, Message.Length - 1), _signature));
        Assert.False(_service.VerifySignature(Secret, [.. Message, (byte)'\n'], _signature));
        Assert.False(_service.VerifySignature(Secret, ReadOnlySpan<byte>.Empty, _signature));
    }

    [Fact]
    public void VerifySignature_AllZeroSignature_ReturnsFalse()
    {
        Assert.False(_service.VerifySignature(Secret, Message, new string('0', HmacSha256SignatureService.SignatureHexLength)));
    }

    [Fact]
    public void VerifySignature_LongSecretOnPooledKeyPath_AcceptsOnlyExactSecret()
    {
        string secret = new string('p', 999) + "X";
        string signature = ReferenceHmac.Compute(secret, Message);

        Assert.True(_service.VerifySignature(secret, Message, signature));
        Assert.False(_service.VerifySignature(new string('p', 999) + "Y", Message, signature));
    }

    [Fact]
    public void VerifySignature_NonAsciiSecret_AcceptsOnlyExactSecret()
    {
        const string secret = "\u015Fifre-\u011F\u00FC\u00E7\u00F6\u0131";
        string signature = ReferenceHmac.Compute(secret, Message);

        Assert.True(_service.VerifySignature(secret, Message, signature));
        Assert.False(_service.VerifySignature("sifre-gucoi", Message, signature));
        Assert.False(_service.VerifySignature("\u015Eifre-\u011F\u00FC\u00E7\u00F6\u0131", Message, signature));
    }

    [Fact]
    public void VerifySignature_ManyServiceGeneratedSignatures_RoundTrip()
    {
        for (int i = 0; i < 100; i++)
        {
            string secret = $"client-secret-{i}-" + new string('\u00E7', i * 3);
            byte[] message = TestBytes.Pattern(i * 131, seed: (uint)i + 3);
            string signature = _service.ComputeSignature(secret, message);

            Assert.True(_service.VerifySignature(secret, message, signature));
            Assert.True(_service.VerifySignature(secret, message, signature.ToUpperInvariant()));
            Assert.Equal(ReferenceHmac.Compute(secret, message), signature);
        }
    }

    [Fact]
    public void VerifySignature_NullSecretWithWellFormedSignature_ThrowsArgumentNullException()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => _service.VerifySignature(null!, Message, _signature));

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public void VerifySignature_EmptySecretWithWellFormedSignature_ThrowsArgumentException()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => _service.VerifySignature(string.Empty, Message, _signature));

        Assert.Equal("secret", exception.ParamName);
    }
}
