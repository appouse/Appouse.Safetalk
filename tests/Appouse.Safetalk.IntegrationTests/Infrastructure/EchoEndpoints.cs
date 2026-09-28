using System.IO.Pipelines;
using System.Security.Claims;
using System.Security.Cryptography;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Controller-free endpoints of the protected test application. They echo the authenticated client and read the
/// request body in different ways, proving that the body is still readable after signature verification.
/// </summary>
internal static class EchoEndpoints
{
    /// <summary>
    /// Authorization policy that only admits the client <see cref="TestCredentials.ClientId"/>.
    /// </summary>
    public const string PartnerAOnlyPolicy = "PartnerAOnly";

    private static readonly string[] BodyMethods = ["POST", "PUT", "PATCH", "DELETE"];

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/whoami", WhoAmI);
        endpoints.MapPost("/api/orders", ReadOrderAsync);
        endpoints.MapPost("/api/orders/bound", (OrderRequest order, HttpContext context) => new OrderEchoResponse(context.GetHmacClientId(), order));
        endpoints.MapMethods("/api/raw", BodyMethods, ReadRawBodyAsync);
        endpoints.MapPost("/api/raw/pipe", ReadRawBodyWithPipeReaderAsync);
        endpoints.MapPost("/api/raw/buffer", InspectBodyBufferAsync);
        endpoints.MapMethods("/api/headers", BodyMethods, EchoContentHeadersAsync);
        endpoints.MapPost("/api/form", ReadFormAsync);
        endpoints.MapGet("/api/müşteri", (HttpContext context, string? q, string? x) =>
            new CustomerQueryResponse(context.GetHmacClientId(), context.Request.Path.Value ?? string.Empty, q, x));
        endpoints.Map("/inspect/{**rest}", InspectAsync);
        endpoints.MapGet("/health", () => "Healthy").SkipHmacValidation();
        endpoints.MapGet("/api/authorized/any-client", WhoAmI).RequireAuthorization();
        endpoints.MapGet("/api/authorized/partner-a-only", WhoAmI).RequireAuthorization(PartnerAOnlyPolicy);
    }

    private static WhoAmIResponse WhoAmI(HttpContext context)
    {
        ClaimsIdentity? identity = context.User.Identities.FirstOrDefault(i => i.AuthenticationType == HmacAuthenticationDefaults.AuthenticationType);

        return new WhoAmIResponse(
            context.GetHmacClientId(),
            context.User.Identity?.IsAuthenticated == true,
            context.User.Identity?.Name,
            context.User.Identity?.AuthenticationType,
            identity?.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value);
    }

    private static async Task<OrderEchoResponse> ReadOrderAsync(HttpContext context, CancellationToken cancellationToken)
    {
        OrderRequest? order = await context.Request.ReadFromJsonAsync<OrderRequest>(cancellationToken);
        return new OrderEchoResponse(context.GetHmacClientId(), order);
    }

    private static async Task<RawBodyResponse> ReadRawBodyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, cancellationToken);

        return CreateRawBodyResponse(context, body.Length, TestData.Sha256Hex(body.GetBuffer().AsSpan(0, (int)body.Length)));
    }

    private static async Task<RawBodyResponse> ReadRawBodyWithPipeReaderAsync(HttpContext context, CancellationToken cancellationToken)
    {
        PipeReader reader = context.Request.BodyReader;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long length = 0;

        while (true)
        {
            ReadResult result = await reader.ReadAsync(cancellationToken);
            foreach (ReadOnlyMemory<byte> segment in result.Buffer)
            {
                hash.AppendData(segment.Span);
                length += segment.Length;
            }

            reader.AdvanceTo(result.Buffer.End);
            if (result.IsCompleted)
            {
                break;
            }
        }

        return CreateRawBodyResponse(context, length, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static async Task<BodyBufferResponse> InspectBodyBufferAsync(HttpContext context, CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, cancellationToken);

        // The validator enabled buffering; report where the buffered body lives (memory or a temporary file).
        var buffered = context.Request.Body as FileBufferingReadStream;
        return new BodyBufferResponse(
            context.GetHmacClientId(),
            context.Request.Body.GetType().Name,
            buffered?.InMemory,
            buffered?.TempFileName,
            body.Length,
            TestData.Sha256Hex(body.GetBuffer().AsSpan(0, (int)body.Length)));
    }

    private static async Task<ContentHeadersResponse> EchoContentHeadersAsync(HttpContext context, CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, cancellationToken);

        HttpRequest request = context.Request;
        return new ContentHeadersResponse(
            context.GetHmacClientId(),
            request.ContentLength,
            request.ContentType,
            request.Headers.ContentLanguage.ToString(),
            request.Headers.ContentDisposition.ToString(),
            request.Headers["X-Content-Custom"].ToString(),
            body.Length,
            TestData.Sha256Hex(body.GetBuffer().AsSpan(0, (int)body.Length)));
    }

    private static async Task<FormEchoResponse> ReadFormAsync(HttpContext context, CancellationToken cancellationToken)
    {
        IFormCollection form = await context.Request.ReadFormAsync(cancellationToken);

        var fields = form.ToDictionary(field => field.Key, field => field.Value.ToString(), StringComparer.Ordinal);
        var files = new List<FormFileEcho>();
        foreach (IFormFile file in form.Files)
        {
            using var content = new MemoryStream();
            await file.CopyToAsync(content, cancellationToken);
            files.Add(new FormFileEcho(file.Name, file.FileName, file.Length, TestData.Sha256Hex(content.GetBuffer().AsSpan(0, (int)content.Length))));
        }

        return new FormEchoResponse(context.GetHmacClientId(), fields, files);
    }

    private static async Task<RequestInfoResponse> InspectAsync(HttpContext context, CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, cancellationToken);

        HttpRequest request = context.Request;
        return new RequestInfoResponse(
            context.GetHmacClientId(),
            request.Method,
            request.PathBase.Value ?? string.Empty,
            request.Path.Value ?? string.Empty,
            request.QueryString.Value ?? string.Empty,
            context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? string.Empty,
            body.Length);
    }

    private static RawBodyResponse CreateRawBodyResponse(HttpContext context, long length, string sha256)
    {
        HttpRequest request = context.Request;
        bool isChunked = request.Headers.TransferEncoding.ToString().Contains("chunked", StringComparison.OrdinalIgnoreCase);

        return new RawBodyResponse(
            context.GetHmacClientId(),
            request.Method,
            request.ContentLength,
            isChunked,
            request.Protocol,
            length,
            sha256);
    }
}
