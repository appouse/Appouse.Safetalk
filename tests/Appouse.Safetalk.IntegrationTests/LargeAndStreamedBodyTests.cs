using System.Net;
using System.Net.Http.Headers;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Large, streamed and chunked bodies: the signed bytes must be the sent bytes, and the server must verify them
/// through both the Content-Length and the unknown-length (chunked) reading paths.
/// </summary>
public sealed class LargeAndStreamedBodyTests
{
    private const int LargeBodySize = (3 * 1024 * 1024) - 123;

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Put_LargeBinaryBody_IsVerifiedAndFullyReadableByEndpoint(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(LargeBodySize, seed: 2026);
        using var content = new ByteArrayContent(payload);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using HttpResponseMessage response = await client.PutAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal("PUT", body.Method);
        Assert.Equal(LargeBodySize, body.ContentLength);
        Assert.Equal(LargeBodySize, body.Length);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Post_ChunkedStreamContentOverNonSeekableStream_IsBufferedSignedAndVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes((1024 * 1024) + 17, seed: 77);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative))
        {
            Content = new StreamContent(new NonSeekableReadStream(payload)),
        };
        request.Headers.TransferEncodingChunked = true;
        request.Content.Headers.ContentLength = null; // Unknown length, even after the signing handler buffered it.

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Null(body.ContentLength); // Exercises the server's unknown-length reading path.
        Assert.True(body.IsChunked);
        Assert.Equal(payload.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Post_ChunkedLargeBody_ThroughPipeReaderEndpoint_IsVerifiedAndFullyReadable(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(LargeBodySize, seed: 5);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw/pipe", UriKind.Relative))
        {
            Content = new StreamContent(new NonSeekableReadStream(payload, maxChunkSize: 65_537)),
        };
        request.Headers.TransferEncodingChunked = true;
        request.Content.Headers.ContentLength = null; // Unknown length, even after the signing handler buffered it.

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Null(body.ContentLength);
        Assert.Equal(payload.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Post_StreamContentOverNonSeekableStream_IsBufferedBeforeSigning_SoItIsSentWithContentLength(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(300_001, seed: 13);
        var stream = new NonSeekableReadStream(payload);
        using var content = new StreamContent(stream);

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(payload.Length, body.ContentLength);
        Assert.False(body.IsChunked);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Fact]
    public async Task Kestrel_ExpectContinue_BodyIsSentOnceTheValidatorStartsReading()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(256 * 1024, seed: 100);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative))
        {
            Content = new ByteArrayContent(payload),
        };
        request.Headers.ExpectContinue = true;

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Fact]
    public async Task Kestrel_ExpectContinue_UnknownClientIsRejectedWithoutReadingTheBody()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { ClientId = "partner-unknown" });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative))
        {
            Content = new ByteArrayContent(TestData.CreateBytes(256 * 1024)),
        };
        request.Headers.ExpectContinue = true;

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        response.AssertUnauthorized();
    }

    [Fact]
    public async Task Kestrel_Http2_RawTargetFromPathPseudoHeader_AndBodyAreVerified()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup { Protocols = HttpProtocols.Http2 },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { RequestVersion = HttpVersion.Version20 });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(150_000, seed: 2);
        using var content = new ByteArrayContent(payload);

        using HttpResponseMessage bodyResponse = await client.PostAsync("/api/raw?via=h2", content, ct);
        using HttpResponseMessage targetResponse = await client.GetAsync("/inspect/m%C3%BC%C5%9Fteri/a%2Fb?q=a%20b", ct);

        RawBodyResponse body = await bodyResponse.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal("HTTP/2", body.Protocol);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
        RequestInfoResponse info = await targetResponse.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("/inspect/m%C3%BC%C5%9Fteri/a%2Fb?q=a%20b", info.RawTarget);
    }

    [Fact]
    public async Task Kestrel_Http2_StreamedBodyWithoutContentLength_IsVerified()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup { Protocols = HttpProtocols.Http2 },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                RequestVersion = HttpVersion.Version20,

                // Removes the Content-Length computed after buffering, so the body goes out as bare DATA frames.
                HandlerAfterSigning = () => new RequestMutatingHandler(request => request.Content!.Headers.ContentLength = null),
            });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(400_000, seed: 21);
        using var content = new StreamContent(new NonSeekableReadStream(payload));

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal("HTTP/2", body.Protocol);
        Assert.Null(body.ContentLength);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }
}
