using System.Globalization;
using System.Net;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Hand-framed HTTP/1.1 requests against Kestrel: whatever framing an attacker chooses, an endpoint only ever sees
/// the bytes that were signed.
/// </summary>
public sealed class WireFramingAttackTests
{
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("""{"amount":1000,"iban":"TR00 0000 0000"}""");

    /// <summary>
    /// <c>Transfer-Encoding: chunked</c> together with a conflicting <c>Content-Length</c> (a classic smuggling shape).
    /// Kestrel may reject the request or frame it by the chunked encoding; either way a body is only accepted when it
    /// is the one that was signed.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Kestrel_ChunkedBodyWithConflictingContentLength_IsNeverAcceptedWithUnsignedBytes(bool signOnlyTheContentLengthPrefix)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        const int ConflictingLength = 5;
        byte[] signedBody = signOnlyTheContentLengthPrefix ? Body[..ConflictingLength] : Body;
        KeyValuePair<string, string>[] signingHeaders = ManualSigner.CreateHeaders("POST", "/api/raw", signedBody);

        var request = new StringBuilder();
        request.Append("POST /api/raw HTTP/1.1\r\n");
        request.Append(CultureInfo.InvariantCulture, $"Host: {server.BaseAddress.Authority}\r\n");
        foreach ((string name, string value) in signingHeaders)
        {
            request.Append(CultureInfo.InvariantCulture, $"{name}: {value}\r\n");
        }

        request.Append(CultureInfo.InvariantCulture, $"Content-Length: {ConflictingLength}\r\n");
        request.Append("Transfer-Encoding: chunked\r\n");
        request.Append("Connection: close\r\n\r\n");
        request.Append(CultureInfo.InvariantCulture, $"{Body.Length:x}\r\n");
        byte[] bytes = [.. Encoding.ASCII.GetBytes(request.ToString()), .. Body, .. "\r\n0\r\n\r\n"u8];

        RawHttpResponse response = await RawHttpClient.SendBytesAsync(server.BaseAddress, bytes, ct);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            // Accepted: the endpoint must have read exactly the signed bytes.
            Assert.False(signOnlyTheContentLengthPrefix, "A signature over the Content-Length prefix authorized the full chunked body.");
            Assert.Contains(TestData.Sha256Hex(Body), response.Body, StringComparison.Ordinal);
        }
        else
        {
            Assert.True(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized, $"Unexpected status {response.StatusCode}.");
            Assert.DoesNotContain(server.ValidationResults, result => result.Succeeded);
        }
    }

    /// <summary>
    /// The declared size is checked before the request target: an oversized absolute-form request gets 413.
    /// </summary>
    [Fact]
    public async Task Kestrel_OversizedAbsoluteFormRequest_IsRejectedAsPayloadTooLargeFirst()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup { ConfigureOptions = options => options.MaxBodySize = 10 },
            ct);

        HttpStatusCode status = await RawHttpClient.SendAsync(
            server.BaseAddress,
            "POST",
            $"http://{server.BaseAddress.Authority}/api/raw",
            ManualSigner.CreateHeaders("POST", "/api/raw", Body),
            Body,
            ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, status);
        Assert.Equal(HmacValidationFailure.PayloadTooLarge, server.LastFailure);
    }

    /// <summary>
    /// Bytes pipelined after a signed request with an empty body are parsed as a separate request, which has to carry
    /// its own signature; they never become part of the first request's body.
    /// </summary>
    [Fact]
    public async Task Kestrel_UnsignedRequestPipelinedBehindASignedEmptyBodyRequest_IsRejectedOnItsOwn()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        var request = new StringBuilder();
        request.Append("POST /api/raw HTTP/1.1\r\n");
        request.Append(CultureInfo.InvariantCulture, $"Host: {server.BaseAddress.Authority}\r\n");
        foreach ((string name, string value) in ManualSigner.CreateHeaders("POST", "/api/raw", []))
        {
            request.Append(CultureInfo.InvariantCulture, $"{name}: {value}\r\n");
        }

        request.Append("Content-Length: 0\r\n\r\n");
        request.Append("POST /api/raw HTTP/1.1\r\n");
        request.Append(CultureInfo.InvariantCulture, $"Host: {server.BaseAddress.Authority}\r\n");
        request.Append(CultureInfo.InvariantCulture, $"Content-Length: {Body.Length}\r\n");
        request.Append("Connection: close\r\n\r\n");
        byte[] bytes = [.. Encoding.ASCII.GetBytes(request.ToString()), .. Body];

        RawHttpResponse first = await RawHttpClient.SendBytesAsync(server.BaseAddress, bytes, ct);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Contains(TestData.Sha256Hex([]), first.Body, StringComparison.Ordinal);
        Assert.Contains("HTTP/1.1 401", first.Body, StringComparison.Ordinal); // The pipelined request's own response.
        Assert.Equal(2, server.ValidationResults.Count);
        Assert.Equal(HmacValidationFailure.MissingHeaders, server.LastFailure);
    }
}
