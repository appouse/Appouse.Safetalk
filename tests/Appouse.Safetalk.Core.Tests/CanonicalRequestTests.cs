using System.Globalization;

namespace Appouse.Safetalk.Core.Tests;

public sealed class CanonicalRequestTests
{
    private const string Timestamp = "1700000000";

    [Fact]
    public void Separator_IsLineFeed()
    {
        Assert.Equal('\n', CanonicalRequest.Separator);
    }

    [Fact]
    public void Format_RequirementExample_JoinsComponentsWithLineFeeds()
    {
        string canonical = CanonicalRequest.Format("POST", "/api/orders?id=5", Timestamp, "{\"a\":1}");

        Assert.Equal("POST\n/api/orders?id=5\n1700000000\n{\"a\":1}", canonical);
    }

    [Fact]
    public void Format_NullBody_EndsWithTrailingSeparator()
    {
        string canonical = CanonicalRequest.Format("GET", "/api/orders", Timestamp, body: null);

        Assert.Equal("GET\n/api/orders\n1700000000\n", canonical);
    }

    [Fact]
    public void Format_EmptyBody_EqualsNullBody()
    {
        string withEmptyBody = CanonicalRequest.Format("GET", "/api/orders", Timestamp, string.Empty);
        string withNullBody = CanonicalRequest.Format("GET", "/api/orders", Timestamp, body: null);

        Assert.Equal(withNullBody, withEmptyBody);
    }

    [Theory]
    [InlineData("get", "GET")]
    [InlineData("post", "POST")]
    [InlineData("Put", "PUT")]
    [InlineData("pAtCh", "PATCH")]
    [InlineData("delete", "DELETE")]
    [InlineData("head", "HEAD")]
    [InlineData("options", "OPTIONS")]
    [InlineData("m-search", "M-SEARCH")]
    [InlineData("POST", "POST")]
    public void Format_MethodInAnyCase_IsUpperCased(string method, string expectedMethod)
    {
        string canonical = CanonicalRequest.Format(method, "/", Timestamp, body: null);

        Assert.Equal($"{expectedMethod}\n/\n{Timestamp}\n", canonical);
    }

    [Fact]
    public void Format_TurkishCurrentCulture_UpperCasesMethodInvariantly()
    {
        CultureInfo originalCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");

            // Precondition: the culture-sensitive upper-casing of "i" is the dotted capital I (U+0130) in Turkish.
            Assert.Equal("OPT\u0130ONS", "options".ToUpper(CultureInfo.CurrentCulture));

            string canonical = CanonicalRequest.Format("options", "/items", Timestamp, body: null);

            Assert.Equal("OPTIONS\n/items\n1700000000\n", canonical);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    [Theory]
    [InlineData("/api/orders?id=5")]
    [InlineData("/api/Orders/%2f?B=2&a=1")]
    [InlineData("/api/%C3%BCr%C3%BCn?q=%E2%82%AC")]
    [InlineData("/api/\u00FCr\u00FCn?ad=\u015E\u00FCkr\u00FC&\u0131=\u0130")]
    [InlineData("/a//b/../c/./d")]
    [InlineData("/api/orders/?")]
    [InlineData("/search?q=a+b%20c&q=d")]
    [InlineData("*")]
    [InlineData("https://example.com/absolute?x=1")]
    public void Format_PathAndQuery_IsPreservedVerbatim(string pathAndQuery)
    {
        string canonical = CanonicalRequest.Format("GET", pathAndQuery, Timestamp, body: null);

        Assert.Equal($"GET\n{pathAndQuery}\n{Timestamp}\n", canonical);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("001700000000")]
    [InlineData("99999999999")]
    public void Format_Timestamp_IsPreservedVerbatim(string timestamp)
    {
        string canonical = CanonicalRequest.Format("GET", "/", timestamp, body: null);

        Assert.Equal($"GET\n/\n{timestamp}\n", canonical);
    }

    [Fact]
    public void Format_BodyWithSeparatorsControlCharactersAndUnicode_IsAppendedVerbatim()
    {
        const string body = "line1\nline2\r\n\0\t\u015Fifre \u011F\u00FC\u00E7\u00F6\u0131 \uD83D\uDE00\n";

        string canonical = CanonicalRequest.Format("PUT", "/upload", Timestamp, body);

        Assert.Equal("PUT\n/upload\n1700000000\n" + body, canonical);
    }

    [Fact]
    public void Format_DifferentComponents_ProduceDifferentCanonicalStrings()
    {
        string baseline = CanonicalRequest.Format("POST", "/api/orders?id=5", Timestamp, "{}");

        Assert.NotEqual(baseline, CanonicalRequest.Format("PUT", "/api/orders?id=5", Timestamp, "{}"));
        Assert.NotEqual(baseline, CanonicalRequest.Format("POST", "/api/orders?id=6", Timestamp, "{}"));
        Assert.NotEqual(baseline, CanonicalRequest.Format("POST", "/api/orders?id=5", "1700000001", "{}"));
        Assert.NotEqual(baseline, CanonicalRequest.Format("POST", "/api/orders?id=5", Timestamp, "{ }"));
    }

    [Theory]
    [InlineData("method")]
    [InlineData("pathAndQuery")]
    [InlineData("timestamp")]
    public void Format_NullArgument_ThrowsArgumentNullException(string parameterName)
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() => FormatWith(parameterName, null));

        Assert.Equal(parameterName, exception.ParamName);
    }

    [Theory]
    [InlineData("method")]
    [InlineData("pathAndQuery")]
    [InlineData("timestamp")]
    public void Format_EmptyArgument_ThrowsArgumentException(string parameterName)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() => FormatWith(parameterName, string.Empty));

        Assert.Equal(parameterName, exception.ParamName);
    }

    private static string FormatWith(string parameterName, string? value) => CanonicalRequest.Format(
        parameterName == "method" ? value! : "GET",
        parameterName == "pathAndQuery" ? value! : "/",
        parameterName == "timestamp" ? value! : Timestamp,
        body: null);
}
