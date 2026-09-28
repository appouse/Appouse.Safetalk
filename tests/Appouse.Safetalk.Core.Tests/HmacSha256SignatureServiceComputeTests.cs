using System.Collections.Concurrent;
using System.Text;
using Appouse.Safetalk.Core.Tests.Infrastructure;

namespace Appouse.Safetalk.Core.Tests;

public sealed class HmacSha256SignatureServiceComputeTests
{
    /// <summary>The canonical request from the requirements, as it would be signed on the wire.</summary>
    private static readonly byte[] RequirementCanonical = Encoding.UTF8.GetBytes("POST\n/api/orders?id=5\n1700000000\n{\"a\":1}");

    private readonly HmacSha256SignatureService _service = HmacSha256SignatureService.Instance;

    [Fact]
    public void Constants_DescribeHmacSha256Output()
    {
        Assert.Equal(32, HmacSha256SignatureService.SignatureSizeInBytes);
        Assert.Equal(64, HmacSha256SignatureService.SignatureHexLength);
    }

    [Fact]
    public void Instance_IsSharedAndImplementsContract()
    {
        Assert.Same(HmacSha256SignatureService.Instance, HmacSha256SignatureService.Instance);
        Assert.IsAssignableFrom<IHmacSignatureService>(HmacSha256SignatureService.Instance);
    }

    [Fact]
    public void ComputeSignature_Rfc4231TestCase1_ReturnsPublishedMac()
    {
        // RFC 4231 4.2: Key = 0x0b repeated 20 times (UTF-8 of twenty U+000B), Data = "Hi There".
        string secret = new('\u000B', 20);

        string signature = _service.ComputeSignature(secret, "Hi There"u8);

        Assert.Equal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", signature);
    }

    [Fact]
    public void ComputeSignature_Rfc4231TestCase2_ReturnsPublishedMac()
    {
        // RFC 4231 4.3: Key = "Jefe", Data = "what do ya want for nothing?".
        string signature = _service.ComputeSignature("Jefe", "what do ya want for nothing?"u8);

        Assert.Equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", signature);
    }

    [Fact]
    public void ComputeSignature_Rfc4231TestCase4_ReturnsPublishedMac()
    {
        // RFC 4231 4.5: Key = 0x01..0x19 (UTF-8 of U+0001..U+0019), Data = 0xcd repeated 50 times.
        string secret = new(Enumerable.Range(1, 25).Select(i => (char)i).ToArray());
        byte[] data = Enumerable.Repeat((byte)0xCD, 50).ToArray();

        string signature = _service.ComputeSignature(secret, data);

        Assert.Equal("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", signature);
    }

    [Fact]
    public void ComputeSignature_RequirementCanonicalExample_MatchesIndependentImplementations()
    {
        string signature = _service.ComputeSignature("secret", RequirementCanonical);

        // Produced independently with: printf 'POST\n/api/orders?id=5\n1700000000\n{"a":1}' | openssl dgst -sha256 -mac HMAC -macopt key:secret
        Assert.Equal("29f18f7daec8ae6d82bec2780a7696929c8183b0aaf0bcf3bd62416e60523050", signature);
        Assert.Equal(ReferenceHmac.Compute("secret", RequirementCanonical), signature);
    }

    [Fact]
    public void ComputeSignature_BodylessGetCanonical_MatchesOpenSslVector()
    {
        string signature = _service.ComputeSignature("secret", "GET\n/api/orders?id=5\n1700000000\n"u8);

        Assert.Equal("84384ad32bddb2853ac78700fcdd66044213e2d43b3ab69c6da6062ff1503778", signature);
    }

    [Fact]
    public void ComputeSignature_NonAsciiSecret_UsesUtf8EncodedKey()
    {
        const string secret = "\u015Fifre-\u011F\u00FC\u00E7\u00F6\u0131";

        string signature = _service.ComputeSignature(secret, RequirementCanonical);

        // OpenSSL with hexkey:c59f696672652dc49fc3bcc3a7c3b6c4b1 (the UTF-8 bytes of the secret).
        Assert.Equal("f52d6642d761531fe8b9e8ee8770514d259efd77244e98e4397b22063d8d40f4", signature);
        Assert.Equal(ReferenceHmac.Compute(Encoding.UTF8.GetBytes(secret), RequirementCanonical), signature);
    }

    [Fact]
    public void ComputeSignature_SecretLongerThan256Bytes_MatchesOpenSslVector()
    {
        string secret = new('k', 300);

        string signature = _service.ComputeSignature(secret, RequirementCanonical);

        Assert.Equal("53305e4c0ecdcfc8031952faeaaeb46a5ec8ab5b328aed16dc05f210230de403", signature);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(512)]
    [InlineData(4_096)]
    [InlineData(100_000)]
    public void ComputeSignature_AsciiSecretOfAnyLength_MatchesReference(int secretLength)
    {
        string secret = new(Enumerable.Range(0, secretLength).Select(i => (char)('!' + (i % 94))).ToArray());

        string signature = _service.ComputeSignature(secret, RequirementCanonical);

        Assert.Equal(ReferenceHmac.Compute(secret, RequirementCanonical), signature);
    }

    [Theory]
    [InlineData("\u015F", 128)] // 256 UTF-8 bytes: largest stack-allocated key.
    [InlineData("\u015F", 129)] // 258 UTF-8 bytes: pooled key.
    [InlineData("\u20AC", 85)] // 255 UTF-8 bytes.
    [InlineData("\u20AC", 86)] // 258 UTF-8 bytes from only 86 characters.
    [InlineData("\u20AC", 100)] // 300 UTF-8 bytes from 100 characters.
    [InlineData("\uD83D\uDE00", 64)] // 256 UTF-8 bytes from surrogate pairs.
    [InlineData("\uD83D\uDE00", 65)] // 260 UTF-8 bytes from surrogate pairs.
    [InlineData("a\u00E7\u20AC\uD83D\uDE00", 500)] // Mixed 1-4 byte sequences, 5000 UTF-8 bytes.
    public void ComputeSignature_MultiByteSecretAroundStackThreshold_MatchesReference(string unit, int repetitions)
    {
        string secret = string.Concat(Enumerable.Repeat(unit, repetitions));

        string signature = _service.ComputeSignature(secret, RequirementCanonical);

        Assert.Equal(ReferenceHmac.Compute(Encoding.UTF8.GetBytes(secret), RequirementCanonical), signature);
    }

    [Theory]
    [InlineData(257)]
    [InlineData(1_000)]
    [InlineData(70_000)]
    public void ComputeSignature_SecretsDifferingOnlyInLastCharacter_ProduceDifferentSignatures(int secretLength)
    {
        // Guards against key truncation on the pooled (long secret) path.
        string first = new string('s', secretLength - 1) + "A";
        string second = new string('s', secretLength - 1) + "B";

        Assert.NotEqual(_service.ComputeSignature(first, RequirementCanonical), _service.ComputeSignature(second, RequirementCanonical));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(1_000)]
    [InlineData(1_048_576)]
    public void ComputeSignature_MessageOfAnyLength_MatchesReference(int messageLength)
    {
        byte[] message = TestBytes.Pattern(messageLength);

        string signature = _service.ComputeSignature("secret", message);

        Assert.Equal(ReferenceHmac.Compute("secret", message), signature);
    }

    [Fact]
    public void ComputeSignature_AnyInput_Returns64LowerCaseHexCharacters()
    {
        for (int length = 0; length < 300; length += 7)
        {
            string signature = _service.ComputeSignature($"secret-{length}", TestBytes.Pattern(length, seed: (uint)length + 1));

            Assert.Equal(HmacSha256SignatureService.SignatureHexLength, signature.Length);
            Assert.All(signature, c => Assert.True(c is (>= '0' and <= '9') or (>= 'a' and <= 'f'), $"Unexpected character '{c}' in {signature}."));
        }
    }

    [Fact]
    public void ComputeSignature_SameInput_IsDeterministicAcrossInstances()
    {
        var other = new HmacSha256SignatureService();

        string first = _service.ComputeSignature("secret", RequirementCanonical);
        string second = _service.ComputeSignature("secret", RequirementCanonical);
        string third = other.ComputeSignature("secret", RequirementCanonical);

        Assert.Equal(first, second);
        Assert.Equal(first, third);
    }

    [Fact]
    public void ComputeSignature_SecretsDifferingOnlyByCase_ProduceDifferentSignatures()
    {
        Assert.NotEqual(_service.ComputeSignature("secret", RequirementCanonical), _service.ComputeSignature("Secret", RequirementCanonical));
    }

    [Fact]
    public void ComputeSignature_MessagesDifferingByOneBit_ProduceDifferentSignatures()
    {
        byte[] tampered = RequirementCanonical.ToArray();
        tampered[^1] ^= 0x01;

        Assert.NotEqual(_service.ComputeSignature("secret", RequirementCanonical), _service.ComputeSignature("secret", tampered));
    }

    [Fact]
    public void ComputeSignature_NullSecret_ThrowsArgumentNullException()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => _service.ComputeSignature(null!, RequirementCanonical));

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public void ComputeSignature_EmptySecret_ThrowsArgumentException()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => _service.ComputeSignature(string.Empty, RequirementCanonical));

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public void ComputeSignature_ConcurrentCalls_ProduceSameResultsAsSequentialReference()
    {
        const int count = 256;
        string[] secrets = Enumerable.Range(0, count).Select(i => new string('k', 1 + (i * 3)) + i).ToArray();
        byte[][] messages = Enumerable.Range(0, count).Select(i => TestBytes.Pattern(i * 97, seed: (uint)i + 1)).ToArray();
        string[] expected = Enumerable.Range(0, count).Select(i => ReferenceHmac.Compute(secrets[i], messages[i])).ToArray();
        var failures = new ConcurrentBag<int>();
        var options = new ParallelOptions
        {
            CancellationToken = TestContext.Current.CancellationToken,
            MaxDegreeOfParallelism = Math.Max(4, Environment.ProcessorCount),
        };

        Parallel.For(0, count * 8, options, iteration =>
        {
            int i = iteration % count;
            if (HmacSha256SignatureService.Instance.ComputeSignature(secrets[i], messages[i]) != expected[i])
            {
                failures.Add(i);
            }
        });

        Assert.Empty(failures);
    }
}
