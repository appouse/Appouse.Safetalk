using System.Globalization;
using System.Text;
using Appouse.Safetalk.Core.Tests.Infrastructure;

namespace Appouse.Safetalk.Core.Tests;

public sealed class CanonicalRequestBufferCreateTests
{
    private const string Timestamp = "1700000000";

    public static TheoryData<string, string, string> HeaderCases => new()
    {
        { "GET", "/", "0" },
        { "get", "/api/orders", Timestamp },
        { "pOsT", "/api/orders?id=5", Timestamp },
        { "Delete", "/api/orders/42?force=true&reason=duplicate", Timestamp },
        { "patch", "/api/%C3%BCr%C3%BCnler?q=%E2%82%AC&path=a%2Fb", Timestamp },
        { "PUT", "/api/\u00FCr\u00FCnler/\u00E7\u011F\u0131\u015F?ad=\u015E\u00FCkr\u00FC", Timestamp },
        { "GET", "/\u0130stanbul?\u0131=I", Timestamp },
        { "m-search", "/emoji/\uD83D\uDE00?e=\uD83C\uDF89", Timestamp },
        { "options", "*", Timestamp },
        { "CONNECT", "example.com:443", Timestamp },
        { "GET", "https://example.com/absolute?x=1", Timestamp },
        { "GET", "/path with spaces/a+b?a=b c&d=", Timestamp },
        { "GET", "/a?b=c&b=d&=e&f", "-1" },
        { "propfind", "/dav/collection/", "99999999999" },
        { "GET", "/" + new string('a', 10_000) + "?q=" + new string('\u00E7', 5_000), Timestamp },
        { new string('x', 1_000), "/", Timestamp },
    };

    [Theory]
    [MemberData(nameof(HeaderCases))]
    public void Create_ValidComponents_HeaderBytesEqualUtf8OfFormat(string method, string pathAndQuery, string timestamp)
    {
        byte[] expected = Encoding.UTF8.GetBytes(CanonicalRequest.Format(method, pathAndQuery, timestamp, body: null));

        using var buffer = CanonicalRequestBuffer.Create(method, pathAndQuery, timestamp);

        ByteAssert.Equal(expected, buffer.WrittenSpan);
        Assert.Equal(expected.Length, buffer.WrittenCount);
    }

    [Theory]
    [MemberData(nameof(HeaderCases))]
    public void Create_WithBodyLengthHint_HeaderIsIndependentOfHint(string method, string pathAndQuery, string timestamp)
    {
        byte[] expected = Encoding.UTF8.GetBytes(CanonicalRequest.Format(method, pathAndQuery, timestamp, body: null));

        using var buffer = CanonicalRequestBuffer.Create(method, pathAndQuery, timestamp, bodyLengthHint: 100_000);

        ByteAssert.Equal(expected, buffer.WrittenSpan);
    }

    [Fact]
    public void Create_RequirementExample_WritesExpectedHeader()
    {
        using var buffer = CanonicalRequestBuffer.Create("POST", "/api/orders?id=5", Timestamp);

        Assert.Equal("POST\n/api/orders?id=5\n1700000000\n", Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    [Fact]
    public void Create_PathWithLoneSurrogate_MatchesUtf8EncodingOfFormat()
    {
        // Encoding.UTF8 replaces an unpaired surrogate with U+FFFD; the buffer must agree byte-for-byte with it.
        const string pathAndQuery = "/lone\uD800surrogate?x=\uDC00";
        byte[] expected = Encoding.UTF8.GetBytes(CanonicalRequest.Format("GET", pathAndQuery, Timestamp, body: null));

        using var buffer = CanonicalRequestBuffer.Create("GET", pathAndQuery, Timestamp);

        ByteAssert.Equal(expected, buffer.WrittenSpan);
    }

    [Theory]
    [InlineData("get")]
    [InlineData("Get")]
    [InlineData("gEt")]
    [InlineData("GET")]
    public void Create_MethodInAnyCase_ProducesSameBytesAsUpperCaseMethod(string method)
    {
        using var expected = CanonicalRequestBuffer.Create("GET", "/api/orders", Timestamp);
        using var actual = CanonicalRequestBuffer.Create(method, "/api/orders", Timestamp);

        ByteAssert.Equal(expected.WrittenSpan, actual.WrittenSpan);
    }

    [Fact]
    public void Create_TurkishCurrentCulture_UpperCasesMethodInvariantly()
    {
        CultureInfo originalCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");

            using var buffer = CanonicalRequestBuffer.Create("options", "/items", Timestamp);

            Assert.Equal("OPTIONS\n/items\n1700000000\n", Encoding.UTF8.GetString(buffer.WrittenSpan));
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    [Fact]
    public void Create_PathAndQuery_IsNotCaseFoldedOrNormalized()
    {
        const string pathAndQuery = "/Api/%2f%2F/\u0130?Q=\u0131";

        using var buffer = CanonicalRequestBuffer.Create("get", pathAndQuery, Timestamp);

        Assert.Equal($"GET\n{pathAndQuery}\n{Timestamp}\n", Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(255)]
    [InlineData(4_096)]
    [InlineData(1_048_576)]
    [InlineData(8_388_608)]
    public void Create_BodyLengthHint_PreSizesBufferForTheWholeBody(int bodyLengthHint)
    {
        using var buffer = CanonicalRequestBuffer.Create("POST", "/upload", Timestamp, bodyLengthHint);

        Assert.True(
            buffer.GetSpan().Length >= bodyLengthHint,
            $"Expected at least {bodyLengthHint} bytes of free space without growing, got {buffer.GetSpan().Length}.");
    }

    [Fact]
    public void Create_ZeroBodyLengthHint_StillProvidesFreeSpace()
    {
        using var buffer = CanonicalRequestBuffer.Create("GET", "/", Timestamp, bodyLengthHint: 0);

        Assert.True(buffer.GetSpan().Length >= 1);
    }

    [Theory]
    [InlineData("G\u00C9T")]
    [InlineData("\u041F\u041E\u0421\u0422")]
    [InlineData("POST\u00A0")]
    [InlineData("\u0130NFO")]
    [InlineData("\uD83D\uDE00")]
    public void Create_NonAsciiMethod_ThrowsArgumentException(string method)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CanonicalRequestBuffer.Create(method, "/api/orders", Timestamp));

        Assert.Equal("method", exception.ParamName);
    }

    [Theory]
    [InlineData("method")]
    [InlineData("pathAndQuery")]
    [InlineData("timestamp")]
    public void Create_NullArgument_ThrowsArgumentNullException(string parameterName)
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() => CreateWith(parameterName, null));

        Assert.Equal(parameterName, exception.ParamName);
    }

    [Theory]
    [InlineData("method")]
    [InlineData("pathAndQuery")]
    [InlineData("timestamp")]
    public void Create_EmptyArgument_ThrowsArgumentException(string parameterName)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() => CreateWith(parameterName, string.Empty));

        Assert.Equal(parameterName, exception.ParamName);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Create_NegativeBodyLengthHint_ThrowsArgumentOutOfRangeException(int bodyLengthHint)
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => CanonicalRequestBuffer.Create("GET", "/", Timestamp, bodyLengthHint));

        Assert.Equal("bodyLengthHint", exception.ParamName);
    }

    private static void CreateWith(string parameterName, string? value)
    {
        using var buffer = CanonicalRequestBuffer.Create(
            parameterName == "method" ? value! : "GET",
            parameterName == "pathAndQuery" ? value! : "/",
            parameterName == "timestamp" ? value! : Timestamp);
    }
}
