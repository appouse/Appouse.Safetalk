using System.Net;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Which request target the server signs: the raw target from the wire (Kestrel), the target rebuilt from the
/// decoded request components (TestServer, or any host without <see cref="IHttpRequestFeature.RawTarget"/>), or a
/// custom <see cref="HmacServerOptions.RequestTargetResolver"/>.
/// </summary>
public sealed class RequestTargetResolutionTests
{
    private const string UnicodeTarget = "/inspect/m%C3%BC%C5%9Fteri/a%2Fb?q=a%20b&x=%2F";

    [Fact]
    public async Task TestServer_DoesNotExposeRawTarget_FallbackRebuildsTheSignedTarget()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.TestServer, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using var content = new StringContent("payload");
        using HttpResponseMessage response = await client.PostAsync(UnicodeTarget, content, ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal(string.Empty, info.RawTarget); // Proves the fallback path was taken.
        Assert.Equal("/inspect/müşteri/a%2Fb", info.Path);
        Assert.Equal("?q=a%20b&x=%2F", info.QueryString);
    }

    [Fact]
    public async Task Kestrel_ExposesRawTarget_IdenticalToTheSignedPathAndQuery()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using var content = new StringContent("payload");
        using HttpResponseMessage response = await client.PostAsync(UnicodeTarget, content, ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal(UnicodeTarget, info.RawTarget); // Proves the raw target path was taken.
        Assert.Equal("/inspect/müşteri/a%2Fb", info.Path);
    }

    [Fact]
    public async Task Kestrel_WithoutRawTarget_FallbackVerifiesUnicodeAndEncodedSlash()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup { ConfigurePipeline = ClearRawTarget },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using var content = new StringContent("payload");
        using HttpResponseMessage response = await client.PostAsync(UnicodeTarget, content, ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal(string.Empty, info.RawTarget);
        Assert.Equal(TestCredentials.ClientId, info.ClientId);
    }

    /// <summary>
    /// Percent-encoded reserved characters are common in path segments, for example
    /// <c>Uri.EscapeDataString("john@example.com")</c>. On a host that exposes the raw target (Kestrel) the path is
    /// signed and verified exactly as sent, with every percent-encoding preserved.
    /// </summary>
    [Theory]
    [MemberData(nameof(PercentEncodedReservedCharacterTargets))]
    public async Task Kestrel_PercentEncodedReservedCharactersInPath_AreVerifiedAndReachTheEndpointVerbatim(string pathAndQuery)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync(pathAndQuery, ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal(pathAndQuery, info.RawTarget);
        Assert.Equal(TestCredentials.ClientId, info.ClientId);
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    public static TheoryData<string> PercentEncodedReservedCharacterTargets => new()
    {
        "/inspect/users/john%40example.com",
        "/inspect/time/12%3A30",
        "/inspect/tags/c%2B%2B",
        "/inspect/list/a%2Cb",
        "/inspect/matrix/a%3Bb",
        "/inspect/price/%2410",
        "/inspect/shout/hello%21",
        "/inspect/quote/it%27s",
        "/inspect/group/%28a%29",
        "/inspect/glob/%2A.txt",
        "/inspect/pair/a%26b",
        "/inspect/assign/a%3Db",
        "/inspect/files/report%2520final.pdf",
        "/inspect/all/%40%3A%2B%2C%3B%24%21%27%28%29%2A%26%3D%2541?q=%40%3A",
    };

    /// <summary>
    /// DOCUMENTED LIMITATION (README, "Testler"): TestServer / WebApplicationFactory do not expose the raw request
    /// target, so the validator rebuilds it from the decoded path, which cannot restore reserved characters the client
    /// percent-encoded. The same request verifies on Kestrel (see the theory above); on the TestServer it is rejected
    /// as an invalid signature, not accepted with a different target.
    /// </summary>
    [Fact]
    public async Task TestServer_PercentEncodedReservedCharacterInPath_IsRejected_DocumentedLimitation()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.TestServer, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/inspect/users/john%40example.com", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    /// <summary>
    /// The limitation lies in the fallback itself, not in the TestServer: Kestrel behaves the same once the raw target
    /// is hidden, and fails closed.
    /// </summary>
    [Fact]
    public async Task Kestrel_WithoutRawTarget_FallbackCannotRestorePercentEncodedAtSign_AndFailsClosed()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup { ConfigurePipeline = ClearRawTarget },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/inspect/users/john%40example.com", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    /// <summary>
    /// Absolute-form targets (<c>POST http://host/path HTTP/1.1</c>) are interpreted differently by Kestrel than
    /// <see cref="Uri.PathAndQuery"/>, so they are no longer reduced to path and query but rejected outright, even when
    /// the signature over the path and query is valid.
    /// </summary>
    [Fact]
    public async Task Kestrel_AbsoluteFormRequestTarget_IsRejectedAsInvalidRequestTarget()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        byte[] body = Encoding.UTF8.GetBytes("absolute-form");
        const string PathAndQuery = "/inspect/absolute?x=%2F";
        string absoluteTarget = new Uri(server.BaseAddress, PathAndQuery).AbsoluteUri;
        KeyValuePair<string, string>[] headers = ManualSigner.CreateHeaders("POST", PathAndQuery, body);

        HttpStatusCode absolute = await RawHttpClient.SendAsync(server.BaseAddress, "POST", absoluteTarget, headers, body, ct);
        HmacValidationFailure absoluteFailure = server.LastFailure;
        HttpStatusCode originForm = await RawHttpClient.SendAsync(server.BaseAddress, "POST", PathAndQuery, headers, body, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, absolute);
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, absoluteFailure);
        Assert.Equal(HttpStatusCode.OK, originForm); // Control: the very same headers are valid in origin-form.
    }

    [Fact]
    public async Task Kestrel_LowerCaseMethodOnTheWire_IsUpperCasedInCanonicalRequest()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        byte[] body = Encoding.UTF8.GetBytes("""{"productCode":"SKU-42"}""");
        const string PathAndQuery = "/inspect/orders?id=5";

        HttpStatusCode status = await RawHttpClient.SendAsync(
            server.BaseAddress,
            "post",
            PathAndQuery,
            ManualSigner.CreateHeaders("POST", PathAndQuery, body),
            body,
            ct);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    [Fact]
    public async Task Kestrel_LowerCasePercentEncodingOnTheWire_IsVerifiedExactlyAsSent()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        const string PathAndQuery = "/inspect/m%c3%bc%c5%9fteri?q=%c3%a7";

        HttpStatusCode status = await RawHttpClient.SendAsync(
            server.BaseAddress,
            "GET",
            PathAndQuery,
            ManualSigner.CreateHeaders("GET", PathAndQuery, []),
            ReadOnlyMemory<byte>.Empty,
            ct);

        Assert.Equal(HttpStatusCode.OK, status);
    }

    [Fact]
    public async Task Kestrel_SignatureOverNormalizedTargetButDifferentWireEncoding_IsRejected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);

        // Signed over upper-case escapes, sent with lower-case escapes: the raw target differs from what was signed.
        HttpStatusCode status = await RawHttpClient.SendAsync(
            server.BaseAddress,
            "GET",
            "/inspect/m%c3%bc",
            ManualSigner.CreateHeaders("GET", "/inspect/m%C3%BC", []),
            ReadOnlyMemory<byte>.Empty,
            ct);

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequestTargetResolver_RestoresPrefixStrippedByReverseProxy(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureOptions = options => options.RequestTargetResolver = context => "/gateway" + context.Request.GetEncodedPathAndQuery() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new StripPrefixProxyHandler(server.BaseAddress) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/gateway/inspect/orders?id=5", ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("/inspect/orders", info.Path);
        Assert.Equal(TestCredentials.ClientId, info.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task WithoutRequestTargetResolver_PrefixStrippedByReverseProxy_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new StripPrefixProxyHandler(server.BaseAddress) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/gateway/inspect/orders?id=5", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    private static void ClearRawTarget(IApplicationBuilder app)
        => app.Use((HttpContext context, RequestDelegate next) =>
        {
            context.Features.GetRequiredFeature<IHttpRequestFeature>().RawTarget = string.Empty;
            return next(context);
        });

    /// <summary>
    /// Simulates a reverse proxy that forwards the signed request after removing the <c>/gateway</c> prefix.
    /// </summary>
    private sealed class StripPrefixProxyHandler(Uri serverAddress) : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string pathAndQuery = request.RequestUri!.PathAndQuery;
            Assert.StartsWith("/gateway/", pathAndQuery, StringComparison.Ordinal);
            request.RequestUri = new Uri(serverAddress, pathAndQuery["/gateway".Length..]);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
