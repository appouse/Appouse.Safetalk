using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// <see cref="HttpClient.Send(HttpRequestMessage, CancellationToken)"/> goes through <c>HttpMessageHandler.Send</c>;
/// the signing handler signs there too, serializing the body synchronously. Kestrel only: the TestServer handler has
/// no synchronous send.
/// </summary>
public sealed class SynchronousSendTests
{
    private const string ClientName = "sync-partner";

    public static TheoryData<string> ContentKinds => new() { "None", "ByteArray", "String", "Json", "NonSeekableStream", "Multipart" };

    [Theory]
    [MemberData(nameof(ContentKinds))]
    public async Task SynchronousSend_ThroughTheFactoryClient_IsSignedAndVerified(string contentKind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using ServiceProvider clientServices = CreateNamedClient(server);
        using HttpClient client = clientServices.GetRequiredService<IHttpClientFactory>().CreateClient(ClientName);
        byte[] expected = [];
        if (contentKind != "None")
        {
            using HttpContent reference = CreateContent(contentKind); // Identical, never-sent instance.
            expected = await reference.ReadAsByteArrayAsync(ct);
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw?sync=true", UriKind.Relative))
        {
            Content = contentKind == "None" ? null : CreateContent(contentKind),
        };

        using HttpResponseMessage response = client.Send(request, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, body.ClientId);
        Assert.Equal(expected.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(expected), body.Sha256);
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    [Fact]
    public async Task SynchronousSend_Get_AuthenticatesTheClient()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using ServiceProvider clientServices = CreateNamedClient(server);
        using HttpClient client = clientServices.GetRequiredService<IHttpClientFactory>().CreateClient(ClientName);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/whoami", UriKind.Relative));

        using HttpResponseMessage response = client.Send(request, ct);

        WhoAmIResponse whoAmI = await response.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    /// <summary>
    /// A synchronous retry handler registered after the signing registration re-sends the same message; each attempt
    /// is re-signed synchronously, so replay protection accepts the retry.
    /// </summary>
    [Fact]
    public async Task SynchronousSend_RetryHandler_WithReplayProtection_EachAttemptIsReSigned()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var received = new ReceivedRequests();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup
            {
                ConfigureHmac = hmac => hmac.AddReplayProtection(),
                ConfigureEndpoints = endpoints => endpoints.MapPost("/api/flaky", (HttpContext context, OrderRequest order) =>
                    received.Add(context) == 1
                        ? Results.StatusCode(StatusCodes.Status503ServiceUnavailable)
                        : Results.Ok(new OrderEchoResponse(context.GetHmacClientId(), order))),
            },
            ct);
        var attempts = new ConcurrentQueue<SendAttempt>();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(DateTimeOffset.UtcNow)); // Both attempts in one second.
        services
            .AddHmacClient(ClientName, options =>
            {
                options.ClientId = TestCredentials.ClientId;
                options.Secret = TestCredentials.Secret;
            })
            .AddHttpMessageHandler(() => new RetryOnStatusHandler(attempts))
            .UseServer(server);
        await using ServiceProvider clientServices = services.BuildServiceProvider();
        using HttpClient client = clientServices.GetRequiredService<IHttpClientFactory>().CreateClient(ClientName);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/flaky", UriKind.Relative))
        {
            Content = JsonContent.Create(new OrderRequest("SKU-42", 1, "sync")),
        };

        using HttpResponseMessage response = client.Send(request, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal("sync", echo.Order?.Note);
        Assert.Equal(new[] { HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK }, attempts.Select(attempt => attempt.StatusCode));
        Assert.Equal(2, received.Signatures.Distinct(StringComparer.Ordinal).Count());
        Assert.DoesNotContain(server.ValidationResults, result => result.Failure == HmacValidationFailure.ReplayDetected);
    }

    [Fact]
    public async Task SynchronousSend_AlreadyCancelledToken_ThrowsWithoutSigningOrSending()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using ServiceProvider clientServices = CreateNamedClient(server);
        using HttpClient client = clientServices.GetRequiredService<IHttpClientFactory>().CreateClient(ClientName);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative)) { Content = new StringContent("x") };
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        Assert.ThrowsAny<OperationCanceledException>(() => client.Send(request, cancelled.Token));

        Assert.False(request.Headers.Contains(SafetalkHeaderNames.Signature));
        Assert.Empty(server.ValidationResults);
    }

    private static ServiceProvider CreateNamedClient(SafetalkServer server)
    {
        var services = new ServiceCollection();
        services
            .AddHmacClient(ClientName, options =>
            {
                options.ClientId = TestCredentials.ClientId;
                options.Secret = TestCredentials.Secret;
            })
            .UseServer(server);
        return services.BuildServiceProvider();
    }

    private static HttpContent CreateContent(string contentKind) => contentKind switch
    {
        "ByteArray" => new ByteArrayContent(TestData.CreateBytes(70_000, seed: 3)),
        "String" => new StringContent("Senkron gönderim — çğıöşü 🚀", Encoding.UTF8, "text/plain"),
        "Json" => JsonContent.Create(new OrderRequest("SKU-42", 2, "senkron")),
        "NonSeekableStream" => new StreamContent(new NonSeekableReadStream(TestData.CreateBytes(120_000, seed: 8))),
        "Multipart" => CreateMultipart(),
        _ => throw new ArgumentOutOfRangeException(nameof(contentKind), contentKind, "Unknown content kind."),
    };

    private static MultipartFormDataContent CreateMultipart()
    {
        var content = new MultipartFormDataContent("sync-boundary");
        content.Add(new StringContent("fatura-2026"), "reference");
        var file = new ByteArrayContent(TestData.CreateBytes(9_000, seed: 4));
        file.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        content.Add(file, "document", "invoice.pdf");
        return content;
    }
}
