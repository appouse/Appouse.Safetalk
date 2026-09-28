using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The HMAC middleware next to other middleware that replaces the request body or re-executes the pipeline.
/// </summary>
public sealed class PipelineCompositionTests
{
    private static readonly byte[] CompressiblePayload = Encoding.UTF8.GetBytes(
        string.Concat(Enumerable.Repeat("""{"productCode":"SKU-42","quantity":3,"note":"çğıöşü"},""", 2_000)));

    /// <summary>
    /// The signature covers the gzip bytes on the wire. With <c>UseRequestDecompression()</c> in front of the HMAC
    /// middleware the validator would read decompressed bytes while <c>Content-Length</c> still announces the
    /// compressed size: it detects the mismatch and fails closed.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequestDecompressionBeforeHmac_GzipBodySignedOverWireBytes_IsRejectedAsContentLengthMismatch(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureServices = services => services.AddRequestDecompression(),
                ConfigurePipeline = app => app.UseRequestDecompression(),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpContent content = CreateGzipContent(CompressiblePayload);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", content, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequestDecompressionAfterHmac_GzipBodySignedOverWireBytes_IsVerifiedAndEndpointReadsDecompressedBody(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureServices = services => services.AddRequestDecompression(),
                ConfigurePipelineAfterHmac = app => app.UseRequestDecompression(),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpContent content = CreateGzipContent(CompressiblePayload);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, body.ClientId);
        Assert.Equal(CompressiblePayload.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(CompressiblePayload), body.Sha256);
    }

    /// <summary>
    /// A body stream replaced in front of the middleware that ends early (a truncated body) or yields extra bytes is
    /// detected by comparing the bytes read with <c>Content-Length</c>, never trusting either alone.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, -1)]
    [InlineData(TestHostKind.Kestrel, -1)]
    [InlineData(TestHostKind.TestServer, +1)]
    [InlineData(TestHostKind.Kestrel, +1)]
    [InlineData(TestHostKind.TestServer, -500)]
    [InlineData(TestHostKind.Kestrel, -500)]
    public async Task BodyReplacedBeforeHmacWithDifferentLength_IsRejectedAsContentLengthMismatch(TestHostKind kind, int lengthDelta)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        byte[] payload = TestData.CreateBytes(1_000, seed: 12);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigurePipeline = app => app.Use(async (HttpContext context, RequestDelegate next) =>
                {
                    using var original = new MemoryStream();
                    await context.Request.Body.CopyToAsync(original, context.RequestAborted);
                    byte[] replaced = lengthDelta < 0
                        ? original.ToArray()[..(payload.Length + lengthDelta)]
                        : [.. original.ToArray(), .. new byte[lengthDelta]];
                    context.Request.Body = new MemoryStream(replaced, writable: false) { Position = 0 }; // Content-Length unchanged.
                    await next(context);
                }),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var content = new ByteArrayContent(payload);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", content, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, server.LastFailure);
    }

    /// <summary>
    /// <c>UseStatusCodePagesWithReExecute</c> runs the pipeline a second time for the same request. With replay
    /// protection the second validation would report a replay and turn the 404 into a 401; the middleware recognises
    /// the request it already verified and lets the error page render.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task StatusCodePagesReExecute_WithReplayProtection_SignedRequestToMissingRoute_Returns404ErrorPage(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureHmac = hmac => hmac.AddReplayProtection(),
                ConfigurePipeline = app => app.UseStatusCodePagesWithReExecute("/errors/{0}"),
                ConfigureEndpoints = MapErrorPage,
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/does/not/exist", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("error-page 404 for partner-a", await response.Content.ReadAsStringAsync(ct));
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task StatusCodePagesReExecute_UnsignedRequest_IsStillRejectedAndTheErrorPageIsNotAuthenticated(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureHmac = hmac => hmac.AddReplayProtection(),
                ConfigurePipeline = app => app.UseStatusCodePagesWithReExecute("/errors/{0}"),
                ConfigureEndpoints = MapErrorPage,
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync(ct);
        Assert.DoesNotContain("partner-a", body, StringComparison.Ordinal);
        Assert.All(server.ValidationResults, result => Assert.False(result.Succeeded));
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ExceptionHandlerReExecute_WithReplayProtection_SignedRequestToThrowingEndpoint_Returns500ErrorPage(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureHmac = hmac => hmac.AddReplayProtection(),
                ConfigurePipeline = app => app.UseExceptionHandler("/errors/500"),
                ConfigureEndpoints = endpoints =>
                {
                    MapErrorPage(endpoints);
                    endpoints.MapPost("/api/throws", string (HttpContext _) => throw new InvalidOperationException("Endpoint failure."));
                },
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var content = new StringContent("""{"productCode":"SKU-42"}""", Encoding.UTF8, "application/json");

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/throws", content, ct);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("error-page 500 for partner-a", await response.Content.ReadAsStringAsync(ct));
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    /// <summary>
    /// The skip on re-execution is keyed on this library's own feature: a foreign <see cref="IHmacClientFeature"/>
    /// set by other middleware does not bypass validation.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ForeignHmacClientFeatureSetByOtherMiddleware_DoesNotBypassValidation(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigurePipeline = app => app.Use((HttpContext context, RequestDelegate next) =>
                {
                    context.Features.Set<IHmacClientFeature>(new ForgedClientFeature(TestCredentials.ClientId));
                    return next(context);
                }),
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.MissingHeaders, server.LastFailure);
    }

    private static void MapErrorPage(Microsoft.AspNetCore.Routing.IEndpointRouteBuilder endpoints)
        => endpoints.Map("/errors/{code:int}", (HttpContext context, int code) => $"error-page {code} for {context.GetHmacClientId() ?? "anonymous"}");

    private static ByteArrayContent CreateGzipContent(byte[] payload)
    {
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(payload);
        }

        var content = new ByteArrayContent(compressed.ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("gzip");
        return content;
    }

    private sealed class ForgedClientFeature(string clientId) : IHmacClientFeature
    {
        public string ClientId { get; } = clientId;
    }
}
