using System.Net;
using System.Net.Http.Headers;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// A 3 MiB body against the default and a lowered <see cref="HmacServerOptions.MaxBodySize"/>. The validator buffers
/// the body in memory only (no temporary file), whatever its size within the limit.
/// </summary>
public sealed class LargeBodyBufferingTests
{
    private const int ThreeMebibytes = 3 * 1024 * 1024;

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ThreeMebibyteBody_DefaultMaxBodySize_IsVerifiedAndBufferedInMemoryWithoutTemporaryFile(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        byte[] payload = TestData.CreateBytes(ThreeMebibytes, seed: 33);
        using var content = new ByteArrayContent(payload);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw/buffer", content, ct);

        BodyBufferResponse body = await response.ReadOkJsonAsync<BodyBufferResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, body.ClientId);
        Assert.Equal(ThreeMebibytes, body.Length);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
        Assert.Equal("FileBufferingReadStream", body.BodyStreamType);
        Assert.True(body.InMemory);
        Assert.Null(body.TempFileName);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ThreeMebibyteChunkedBody_DefaultMaxBodySize_IsVerifiedAndBufferedInMemory(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        byte[] payload = TestData.CreateBytes(ThreeMebibytes, seed: 34);
        using HttpRequestMessage request = CreateChunkedRequest("/api/raw/buffer", payload);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct);

        BodyBufferResponse body = await response.ReadOkJsonAsync<BodyBufferResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
        Assert.True(body.InMemory);
        Assert.Null(body.TempFileName);
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, false)]
    [InlineData(TestHostKind.Kestrel, false)]
    [InlineData(TestHostKind.TestServer, true)]
    [InlineData(TestHostKind.Kestrel, true)]
    public async Task ThreeMebibyteBody_MaxBodySizeLoweredToTwoMebibytes_IsRejectedWith413(TestHostKind kind, bool chunked)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureOptions = options => options.MaxBodySize = 2 * 1024 * 1024 },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        byte[] payload = TestData.CreateBytes(ThreeMebibytes, seed: 35);
        using HttpRequestMessage request = chunked
            ? CreateChunkedRequest("/api/raw", payload)
            : new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative)) { Content = new ByteArrayContent(payload) };

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal(HmacValidationFailure.PayloadTooLarge, server.LastFailure);
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, 0, HttpStatusCode.OK)]
    [InlineData(TestHostKind.Kestrel, 0, HttpStatusCode.OK)]
    [InlineData(TestHostKind.TestServer, 1, HttpStatusCode.RequestEntityTooLarge)]
    [InlineData(TestHostKind.Kestrel, 1, HttpStatusCode.RequestEntityTooLarge)]
    public async Task ThreeMebibyteBody_MaxBodySizeExactlyThreeMebibytes_BoundaryIsInclusive(TestHostKind kind, int extraBytes, HttpStatusCode expected)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureOptions = options => options.MaxBodySize = ThreeMebibytes },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        byte[] payload = TestData.CreateBytes(ThreeMebibytes + extraBytes, seed: 36);
        using HttpRequestMessage request = CreateChunkedRequest("/api/raw", payload);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct);

        Assert.Equal(expected, response.StatusCode);
    }

    /// <summary>
    /// After a large rejected body the connection is usable and a following large accepted body is verified.
    /// </summary>
    [Fact]
    public async Task Kestrel_LargeRejectedBodyFollowedByLargeAcceptedBody_BothAreHandled()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup { ConfigureOptions = options => options.MaxBodySize = 2 * 1024 * 1024 },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using HttpRequestMessage oversized = CreateChunkedRequest("/api/raw", TestData.CreateBytes(ThreeMebibytes, seed: 37));
        byte[] accepted = TestData.CreateBytes(2 * 1024 * 1024, seed: 38);
        using var acceptedContent = new ByteArrayContent(accepted);

        using HttpResponseMessage first = await client.SendAsync(oversized, ct);
        using HttpResponseMessage second = await client.PostAsync("/api/raw", acceptedContent, ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, first.StatusCode);
        RawBodyResponse body = await second.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(accepted), body.Sha256);
    }

    private static HttpRequestMessage CreateChunkedRequest(string pathAndQuery, byte[] payload)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(pathAndQuery, UriKind.Relative))
        {
            Content = new StreamContent(new NonSeekableReadStream(payload, maxChunkSize: 65_521)),
        };
        request.Headers.TransferEncodingChunked = true;
        request.Content.Headers.ContentLength = null;
        return request;
    }
}
