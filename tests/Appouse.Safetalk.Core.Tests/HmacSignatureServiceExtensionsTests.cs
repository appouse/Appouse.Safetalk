using System.Text;
using Appouse.Safetalk.Core.Tests.Infrastructure;

namespace Appouse.Safetalk.Core.Tests;

public sealed class HmacSignatureServiceExtensionsTests
{
    private const string Secret = "secret";
    private const string Timestamp = "1700000000";

    private readonly HmacSha256SignatureService _service = HmacSha256SignatureService.Instance;

    public static TheoryData<string, string, string?> TextRequests => new()
    {
        { "POST", "/api/orders?id=5", "{\"a\":1}" },
        { "GET", "/api/orders?id=5", null },
        { "get", "/api/orders", string.Empty },
        { "put", "/api/%C3%BCr%C3%BCn/5?force=true", "{\"ad\":\"\u015E\u00FCkr\u00FC\"}" },
        { "DELETE", "/api/\u00FCr\u00FCn/\u0130?\u0131=1", null },
        { "PATCH", "/api/orders/5", "line1\nline2\r\n\uD83D\uDE00" },
    };

    public static TheoryData<string> TamperedComponents => new()
    {
        "secret",
        "method",
        "path",
        "query",
        "timestamp",
        "body",
    };

    [Theory]
    [MemberData(nameof(TextRequests))]
    public void ComputeSignature_TextBody_EqualsServiceOverFormattedCanonicalRequest(string method, string pathAndQuery, string? body)
    {
        byte[] canonical = Encoding.UTF8.GetBytes(CanonicalRequest.Format(method, pathAndQuery, Timestamp, body));

        string signature = _service.ComputeSignature(Secret, method, pathAndQuery, Timestamp, Encoding.UTF8.GetBytes(body ?? string.Empty));

        Assert.Equal(_service.ComputeSignature(Secret, canonical), signature);
        Assert.Equal(ReferenceHmac.Compute(Secret, canonical), signature);
    }

    [Theory]
    [MemberData(nameof(TextRequests))]
    public void VerifySignature_TextBody_EqualsServiceOverFormattedCanonicalRequest(string method, string pathAndQuery, string? body)
    {
        byte[] canonical = Encoding.UTF8.GetBytes(CanonicalRequest.Format(method, pathAndQuery, Timestamp, body));
        string signature = ReferenceHmac.Compute(Secret, canonical);

        bool valid = _service.VerifySignature(Secret, method, pathAndQuery, Timestamp, Encoding.UTF8.GetBytes(body ?? string.Empty), signature);

        Assert.True(valid);
    }

    [Fact]
    public void ComputeSignature_RequirementExample_MatchesOpenSslVector()
    {
        string signature = _service.ComputeSignature(Secret, "POST", "/api/orders?id=5", Timestamp, "{\"a\":1}"u8);

        Assert.Equal("29f18f7daec8ae6d82bec2780a7696929c8183b0aaf0bcf3bd62416e60523050", signature);
    }

    [Fact]
    public void ComputeSignature_EmptyBody_MatchesOpenSslVectorForHeaderOnly()
    {
        string signature = _service.ComputeSignature(Secret, "GET", "/api/orders?id=5", Timestamp, ReadOnlySpan<byte>.Empty);

        Assert.Equal("84384ad32bddb2853ac78700fcdd66044213e2d43b3ab69c6da6062ff1503778", signature);
    }

    [Fact]
    public void ComputeSignature_BinaryBodyWithAllByteValues_EqualsReferenceOverHeaderAndRawBody()
    {
        // Includes 0x00, a bare '\n' and byte sequences that are not valid UTF-8: the body must be signed as raw bytes.
        byte[] body = TestBytes.AllByteValues(repetitions: 3);
        byte[] canonical = [.. "POST\n/upload?name=blob.bin\n1700000000\n"u8, .. body];

        string signature = _service.ComputeSignature(Secret, "POST", "/upload?name=blob.bin", Timestamp, body);

        Assert.Equal(ReferenceHmac.Compute(Secret, canonical), signature);
        Assert.True(_service.VerifySignature(Secret, "POST", "/upload?name=blob.bin", Timestamp, body, signature));
    }

    [Fact]
    public void ComputeSignature_LargeBinaryBody_EqualsReference()
    {
        byte[] body = TestBytes.Pattern(3 * 1024 * 1024);
        byte[] canonical = [.. "PUT\n/api/files/1\n1700000000\n"u8, .. body];

        string signature = _service.ComputeSignature(Secret, "PUT", "/api/files/1", Timestamp, body);

        Assert.Equal(ReferenceHmac.Compute(Secret, canonical), signature);
    }

    [Fact]
    public void ComputeSignature_LowerCaseMethod_EqualsUpperCaseMethodSignature()
    {
        string lower = _service.ComputeSignature(Secret, "post", "/api/orders?id=5", Timestamp, "{\"a\":1}"u8);
        string upper = _service.ComputeSignature(Secret, "POST", "/api/orders?id=5", Timestamp, "{\"a\":1}"u8);

        Assert.Equal(upper, lower);
    }

    [Theory]
    [MemberData(nameof(TamperedComponents))]
    public void VerifySignature_AnyComponentTampered_ReturnsFalse(string component)
    {
        string signature = _service.ComputeSignature(Secret, "POST", "/api/orders?id=5", Timestamp, "{\"a\":1}"u8);

        bool valid = _service.VerifySignature(
            component == "secret" ? "Secret" : Secret,
            component == "method" ? "PUT" : "POST",
            component switch
            {
                "path" => "/api/order?id=5",
                "query" => "/api/orders?id=6",
                _ => "/api/orders?id=5",
            },
            component == "timestamp" ? "1700000001" : Timestamp,
            component == "body" ? "{\"a\":2}"u8 : "{\"a\":1}"u8,
            signature);

        Assert.False(valid);
    }

    [Theory]
    [InlineData("/api/orders?id=05")]
    [InlineData("/api/Orders?id=5")]
    [InlineData("/api/orders/?id=5")]
    [InlineData("/api/orders?id=5&")]
    [InlineData("/api/%6Frders?id=5")]
    [InlineData("/api//orders?id=5")]
    [InlineData("/api/orders?%69d=5")]
    public void VerifySignature_RequestTargetNotByteIdentical_ReturnsFalse(string pathAndQuery)
    {
        // The request target is signed exactly as sent: no case folding, decoding or path normalization.
        string signature = _service.ComputeSignature(Secret, "GET", "/api/orders?id=5", Timestamp, ReadOnlySpan<byte>.Empty);

        Assert.False(_service.VerifySignature(Secret, "GET", pathAndQuery, Timestamp, ReadOnlySpan<byte>.Empty, signature));
    }

    [Fact]
    public void VerifySignature_QueryParametersReordered_ReturnsFalse()
    {
        string signature = _service.ComputeSignature(Secret, "GET", "/api/orders?a=1&b=2", Timestamp, ReadOnlySpan<byte>.Empty);

        Assert.False(_service.VerifySignature(Secret, "GET", "/api/orders?b=2&a=1", Timestamp, ReadOnlySpan<byte>.Empty, signature));
    }

    [Fact]
    public void VerifySignature_UpperCaseSignature_ReturnsTrue()
    {
        string signature = _service.ComputeSignature(Secret, "POST", "/api/orders?id=5", Timestamp, "{\"a\":1}"u8);

        Assert.True(_service.VerifySignature(Secret, "POST", "/api/orders?id=5", Timestamp, "{\"a\":1}"u8, signature.ToUpperInvariant()));
    }

    [Fact]
    public void VerifySignature_MalformedSignature_ReturnsFalse()
    {
        Assert.False(_service.VerifySignature(Secret, "POST", "/api/orders?id=5", Timestamp, "{\"a\":1}"u8, "not-a-signature"));
        Assert.False(_service.VerifySignature(Secret, "POST", "/api/orders?id=5", Timestamp, "{\"a\":1}"u8, ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public void ComputeSignature_AnyService_ReceivesExactCanonicalBytesAndSecret()
    {
        var recorder = new RecordingSignatureService { SignatureToReturn = "from-recorder" };
        byte[] body = TestBytes.AllByteValues();

        string signature = recorder.ComputeSignature("client-secret", "patch", "/api/items/7?x=%20", Timestamp, body);

        Assert.Equal("from-recorder", signature);
        Assert.Equal(1, recorder.CallCount);
        Assert.Equal("client-secret", recorder.LastSecret);
        ByteAssert.Equal([.. "PATCH\n/api/items/7?x=%20\n1700000000\n"u8, .. body], recorder.LastCanonicalRequest);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void VerifySignature_AnyService_ForwardsInputsAndReturnsServiceResult(bool serviceResult)
    {
        var recorder = new RecordingSignatureService { VerificationResult = serviceResult };

        bool valid = recorder.VerifySignature("client-secret", "get", "/api/items", Timestamp, ReadOnlySpan<byte>.Empty, "ABCDEF");

        Assert.Equal(serviceResult, valid);
        Assert.Equal(1, recorder.CallCount);
        Assert.Equal("client-secret", recorder.LastSecret);
        Assert.Equal("ABCDEF", recorder.LastSignature);
        ByteAssert.Equal("GET\n/api/items\n1700000000\n"u8, recorder.LastCanonicalRequest);
    }

    [Fact]
    public void ComputeSignature_NullService_ThrowsArgumentNullException()
    {
        IHmacSignatureService service = null!;

        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => service.ComputeSignature(Secret, "GET", "/", Timestamp, ReadOnlySpan<byte>.Empty));

        Assert.Equal("service", exception.ParamName);
    }

    [Fact]
    public void VerifySignature_NullService_ThrowsArgumentNullException()
    {
        IHmacSignatureService service = null!;

        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => service.VerifySignature(Secret, "GET", "/", Timestamp, ReadOnlySpan<byte>.Empty, "00"));

        Assert.Equal("service", exception.ParamName);
    }

    [Fact]
    public void ComputeSignature_InvalidCanonicalComponents_ThrowArgumentExceptions()
    {
        Assert.Equal("method", Assert.Throws<ArgumentNullException>(() => _service.ComputeSignature(Secret, null!, "/", Timestamp, ReadOnlySpan<byte>.Empty)).ParamName);
        Assert.Equal("method", Assert.Throws<ArgumentException>(() => _service.ComputeSignature(Secret, string.Empty, "/", Timestamp, ReadOnlySpan<byte>.Empty)).ParamName);
        Assert.Equal("method", Assert.Throws<ArgumentException>(() => _service.ComputeSignature(Secret, "G\u00C9T", "/", Timestamp, ReadOnlySpan<byte>.Empty)).ParamName);
        Assert.Equal("pathAndQuery", Assert.Throws<ArgumentException>(() => _service.ComputeSignature(Secret, "GET", string.Empty, Timestamp, ReadOnlySpan<byte>.Empty)).ParamName);
        Assert.Equal("timestamp", Assert.Throws<ArgumentException>(() => _service.ComputeSignature(Secret, "GET", "/", string.Empty, ReadOnlySpan<byte>.Empty)).ParamName);
    }

    [Fact]
    public void ComputeSignature_EmptySecret_ThrowsArgumentException()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => _service.ComputeSignature(string.Empty, "GET", "/", Timestamp, ReadOnlySpan<byte>.Empty));

        Assert.Equal("secret", exception.ParamName);
    }
}
