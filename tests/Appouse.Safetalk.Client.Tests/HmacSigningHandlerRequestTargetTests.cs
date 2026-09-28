using Appouse.Safetalk.Client.Tests.Infrastructure;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// The signed request target must be the path and query that go on the wire, not the scheme, host, port or fragment.
/// </summary>
public sealed class HmacSigningHandlerRequestTargetTests : IDisposable
{
    private readonly SigningPipeline _pipeline = new();

    public void Dispose() => _pipeline.Dispose();

    [Theory]
    [InlineData("https://api.example.com/", "api/orders?id=5", "/api/orders?id=5")]
    [InlineData("https://api.example.com/v1/", "orders?id=5&sort=desc", "/v1/orders?id=5&sort=desc")]
    [InlineData("https://api.example.com/v1", "orders", "/orders")]
    [InlineData("https://api.example.com/v1/", "/orders", "/orders")]
    [InlineData("https://api.example.com:8443/", "api/orders", "/api/orders")]
    [InlineData("http://localhost:5000/", "api/orders?id=5", "/api/orders?id=5")]
    [InlineData("https://api.example.com/", "api/v1/../orders", "/api/orders")]
    [InlineData("https://api.example.com/", "api/orders?id=5#details", "/api/orders?id=5")]
    public async Task SendAsync_BaseAddressAndRelativeUri_SignsResolvedPathAndQuery(string baseAddress, string relativeUri, string expectedPathAndQuery)
    {
        CapturedRequest sent = await GetAsync(new Uri(baseAddress), new Uri(relativeUri, UriKind.Relative));

        AssertSignedTarget(sent, expectedPathAndQuery);
    }

    [Theory]
    [InlineData("https://api.example.com")]
    [InlineData("https://api.example.com/")]
    [InlineData("https://api.example.com:443")]
    public async Task SendAsync_RootUri_SignsSingleSlash(string uri)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        AssertSignedTarget(sent, "/");
    }

    [Fact]
    public async Task SendAsync_BaseAddressWithEmptyRelativeUri_SignsBaseAddressPath()
    {
        CapturedRequest sent = await GetAsync(new Uri("https://api.example.com/v2/"), new Uri(string.Empty, UriKind.Relative));

        AssertSignedTarget(sent, "/v2/");
    }

    [Fact]
    public async Task SendAsync_AbsoluteUriWithBaseAddress_SignsAbsoluteUriTarget()
    {
        CapturedRequest sent = await GetAsync(new Uri("https://a.example.com/ignored/"), new Uri("https://b.example.com/api/orders?id=9"));

        AssertSignedTarget(sent, "/api/orders?id=9");
    }

    [Theory]
    [InlineData("https://api.example.com/api/files/a%2Fb%20c?q=x%26y", "/api/files/a%2Fb%20c?q=x%26y")]
    [InlineData("https://api.example.com/api/search?q=a%20b&tag=%23hot", "/api/search?q=a%20b&tag=%23hot")]
    [InlineData("https://api.example.com/api/search?q=a+b", "/api/search?q=a+b")]
    [InlineData("https://api.example.com/api/items?ids=1,2,3&empty=", "/api/items?ids=1,2,3&empty=")]
    public async Task SendAsync_PercentEncodedTarget_SignsEncodedFormVerbatim(string uri, string expectedPathAndQuery)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        AssertSignedTarget(sent, expectedPathAndQuery);
    }

    [Theory]
    [InlineData("https://api.example.com/api/ürünler/çay", "/api/%C3%BCr%C3%BCnler/%C3%A7ay")]
    [InlineData("https://api.example.com/api/search?şehir=İstanbul", "/api/search?%C5%9Fehir=%C4%B0stanbul")]
    [InlineData("https://api.example.com/api/emoji/🍵?x=日本", "/api/emoji/%F0%9F%8D%B5?x=%E6%97%A5%E6%9C%AC")]
    [InlineData("https://api.example.com/api/with space?q=a b", "/api/with%20space?q=a%20b")]
    public async Task SendAsync_UnicodeOrUnescapedTarget_SignsPercentEncodedWireForm(string uri, string expectedPathAndQuery)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        AssertSignedTarget(sent, expectedPathAndQuery);
    }

    [Fact]
    public async Task SendAsync_DifferentQueryStrings_ProduceDifferentSignatures()
    {
        using var first = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders?id=5");
        using var second = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders?id=6");

        CapturedRequest firstSent = await _pipeline.SendAndCaptureAsync(first);
        CapturedRequest secondSent = await _pipeline.SendAndCaptureAsync(second);

        Assert.NotEqual(firstSent.Signature, secondSent.Signature);
    }

    [Fact]
    public async Task SendAsync_DifferentHosts_ProduceSameSignatureForSameTarget()
    {
        using var first = new HttpRequestMessage(HttpMethod.Get, "https://api-1.example.com/api/orders?id=5");
        using var second = new HttpRequestMessage(HttpMethod.Get, "http://api-2.example.com:8080/api/orders?id=5");

        CapturedRequest firstSent = await _pipeline.SendAndCaptureAsync(first);
        CapturedRequest secondSent = await _pipeline.SendAndCaptureAsync(second);

        Assert.Equal(firstSent.Signature, secondSent.Signature);
    }

    private async Task<CapturedRequest> GetAsync(Uri baseAddress, Uri requestUri)
    {
        using HttpClient client = _pipeline.CreateClient(baseAddress);
        using HttpResponseMessage response = await client.GetAsync(requestUri, TestContext.Current.CancellationToken);
        return _pipeline.Transport.LastRequest;
    }

    private static void AssertSignedTarget(CapturedRequest sent, string expectedPathAndQuery)
    {
        // What the transport puts on the request line...
        Assert.Equal(expectedPathAndQuery, sent.PathAndQuery);

        // ...is exactly what was signed.
        Assert.Equal(
            ReferenceSigner.Sign(SigningPipeline.DefaultSecret, "GET", expectedPathAndQuery, sent.Timestamp, []),
            sent.Signature);
    }
}
