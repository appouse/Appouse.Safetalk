using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacBodyPipelineTests
{
    private const string Inspect = "/api/inspect";

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("partner-unknown", "not-registered")]
    [InlineData(TestCredentials.ClientId, TestCredentials.Secret)]
    public async Task OversizedContentLength_Returns413WithoutSecretLookup(string clientId, string secret)
    {
        var secretProvider = RecordingSecretProvider.ForTestCredentials();
        await using TestApplication app = await StartAsync(
            configureHmac: options => options.MaxBodySize = 16,
            configureServer: hmac => hmac.AddSecretProvider(_ => secretProvider, ServiceLifetime.Singleton));
        byte[] body = new byte[17];

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Post, Inspect, new ByteArrayContent(body), body, clientId, secret));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Empty(secretProvider.RequestedClientIds);
        HmacValidationResult validation = Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
        Assert.Equal(HmacValidationFailure.PayloadTooLarge, validation.Failure);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OneMebibyteBody_ReachesEndpointBufferedInMemoryAtPositionZero(bool sendContentLength)
    {
        await using TestApplication app = await StartAsync();
        byte[] body = RandomNumberGenerator.GetBytes(1024 * 1024);
        HttpContent content = sendContentLength ? new ByteArrayContent(body) : new UnknownLengthContent(body);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, Inspect, content, body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        BodyInspection? inspection = await response.Content.ReadFromJsonAsync<BodyInspection>(CancellationToken);
        Assert.NotNull(inspection);
        Assert.True(inspection.IsFileBuffered);
        Assert.True(inspection.InMemory);
        Assert.Null(inspection.TempFileName);
        Assert.Equal(0, inspection.Position);
        Assert.Equal(body.Length, inspection.Length);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(body)), inspection.Sha256);
    }

    [Fact]
    public async Task RequestDecompressionBeforeHmac_Returns401WithContentLengthMismatch()
    {
        // The signature covers the compressed bytes on the wire; when the body is decompressed before validation the
        // validator sees different bytes, which must never be accepted.
        await using TestApplication app = await StartAsync(
            configureServices: services => services.AddRequestDecompression(),
            beforeHmac: pipeline => pipeline.UseRequestDecompression());
        byte[] plain = CreateCompressiblePayload();
        byte[] compressed = Gzip(plain);
        var content = new ByteArrayContent(compressed);
        content.Headers.ContentEncoding.Add("gzip");

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, Inspect, content, compressed));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        HmacValidationResult validation = Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, validation.Failure);
    }

    [Fact]
    public async Task RequestDecompressionBeforeHmac_SignatureOverDecompressedBody_IsStillRejected()
    {
        await using TestApplication app = await StartAsync(
            configureServices: services => services.AddRequestDecompression(),
            beforeHmac: pipeline => pipeline.UseRequestDecompression());
        byte[] plain = CreateCompressiblePayload();
        var content = new ByteArrayContent(Gzip(plain));
        content.Headers.ContentEncoding.Add("gzip");

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, Inspect, content, plain));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RequestDecompressionAfterHmac_VerifiesWireBytesAndEndpointReadsDecompressedBody()
    {
        await using TestApplication app = await StartAsync(
            configureServices: services => services.AddRequestDecompression(),
            afterHmac: pipeline => pipeline.UseRequestDecompression());
        byte[] plain = CreateCompressiblePayload();
        byte[] compressed = Gzip(plain);
        var content = new ByteArrayContent(compressed);
        content.Headers.ContentEncoding.Add("gzip");

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, Inspect, content, compressed));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        BodyInspection? inspection = await response.Content.ReadFromJsonAsync<BodyInspection>(CancellationToken);
        Assert.Equal(plain.Length, inspection?.Length);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(plain)), inspection?.Sha256);
    }

    [Fact]
    public async Task BodyReplacedByEarlierMiddlewareWithLongerContent_Returns401()
    {
        byte[] signed = """{"orderId":1}"""u8.ToArray();
        await using TestApplication app = await StartAsync(beforeHmac: pipeline => pipeline.Use(async (HttpContext context, RequestDelegate next) =>
        {
            context.Request.Body = new MemoryStream([.. signed, .. ""","extra":true}"""u8.ToArray()]);
            await next(context);
        }));

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, Inspect, signed));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(
            HmacValidationFailure.ContentLengthMismatch,
            Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    private static byte[] CreateCompressiblePayload() =>
        [.. Enumerable.Range(0, 2000).SelectMany(i => """{"orderId":42,"quantity":3},"""u8.ToArray())];

    private static byte[] Gzip(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(data);
        }

        return output.ToArray();
    }

    private static Task<TestApplication> StartAsync(
        Action<IServiceCollection>? configureServices = null,
        Action<IHmacServerBuilder>? configureServer = null,
        Action<HmacServerOptions>? configureHmac = null,
        Action<WebApplication>? beforeHmac = null,
        Action<WebApplication>? afterHmac = null)
    {
        return TestApplication.StartAsync(
            builder =>
            {
                configureServices?.Invoke(builder.Services);
                IHmacServerBuilder server = builder.Services
                    .AddHmacServer(configureHmac)
                    .AddInMemorySecrets(TestCredentials.Secrets);
                configureServer?.Invoke(server);
                builder.Services.AddValidationRecorder();
            },
            app =>
            {
                beforeHmac?.Invoke(app);
                app.UseHmacAuthentication();
                afterHmac?.Invoke(app);
                app.MapPost(Inspect, async (HttpContext context) =>
                {
                    Stream body = context.Request.Body;
                    var buffered = body as FileBufferingReadStream;
                    long? position = body.CanSeek ? body.Position : null;
                    bool? inMemory = buffered?.InMemory;
                    string? tempFileName = buffered?.TempFileName;
                    using var copy = new MemoryStream();
                    await body.CopyToAsync(copy, context.RequestAborted);
                    byte[] bytes = copy.ToArray();
                    return Results.Ok(new BodyInspection(
                        buffered is not null,
                        inMemory,
                        tempFileName,
                        position,
                        bytes.Length,
                        Convert.ToHexString(SHA256.HashData(bytes))));
                });
            });
    }

    public sealed record BodyInspection(bool IsFileBuffered, bool? InMemory, string? TempFileName, long? Position, long Length, string Sha256);
}
