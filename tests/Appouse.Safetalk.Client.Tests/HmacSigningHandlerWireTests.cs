using System.Net.Http.Json;
using System.Text;
using Appouse.Safetalk.Client.Tests.DependencyInjection;
using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// End-to-end through <see cref="SocketsHttpHandler"/> to a loopback socket: the request target, headers, framing and
/// body bytes that actually cross the wire must verify against the signature, on the synchronous and the asynchronous
/// path.
/// </summary>
public sealed class HmacSigningHandlerWireTests : IDisposable
{
    private const string Secret = "wire-secret-0123456789abcdef0123456789";

    private readonly LoopbackHttpServer _server = new();
    private readonly CancellationTokenSource _timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

    public HmacSigningHandlerWireTests()
    {
        _timeout.CancelAfter(TimeSpan.FromSeconds(30));
    }

    public void Dispose()
    {
        _timeout.Dispose();
        _server.Dispose();
    }

    [Theory]
    [InlineData("none", false)]
    [InlineData("none", true)]
    [InlineData("string", false)]
    [InlineData("string", true)]
    [InlineData("stream", false)]
    [InlineData("stream", true)]
    [InlineData("stream-wrong-length", false)]
    [InlineData("stream-wrong-length", true)]
    [InlineData("json", false)]
    [InlineData("json", true)]
    [InlineData("multipart", false)]
    [InlineData("multipart", true)]
    public async Task Send_ThroughSocketsHttpHandler_WireRequestVerifiesAgainstItsSignature(string contentKind, bool synchronous)
    {
        using var handler = new HmacSigningHandler(
            new HmacClientOptions { ClientId = "wire-client", Secret = Secret },
            HmacSha256SignatureService.Instance,
            TimeProvider.System,
            NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = new SocketsHttpHandler { UseProxy = false },
        };
        using var client = new HttpClient(handler) { BaseAddress = _server.BaseAddress };
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("api/files/a%2Fb%20c?q=x%26y&city=İstanbul", UriKind.Relative))
        {
            Content = CreateContent(contentKind),
        };

        WireRequest received = await SendAndReceiveAsync(client, request, synchronous);

        Assert.Equal("POST", received.Method);
        Assert.Equal("/api/files/a%2Fb%20c?q=x%26y&city=%C4%B0stanbul", received.Target);
        Assert.Equal("wire-client", received.Header("X-Client-Id"));
        AssertVerifies(received);
        if (contentKind != "none")
        {
            Assert.False(received.Chunked, "Signed content must be sent with a Content-Length.");
            Assert.Equal(received.Body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), received.Header("Content-Length"));
        }

        if (contentKind == "stream-wrong-length")
        {
            Assert.Equal("0123456789"u8.ToArray(), received.Body);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Send_CallerForcesChunkedTransferEncoding_WireBodyStillVerifies(bool synchronous)
    {
        using var handler = new HmacSigningHandler(new HmacClientOptions { ClientId = "wire-client", Secret = Secret })
        {
            InnerHandler = new SocketsHttpHandler { UseProxy = false },
        };
        using var client = new HttpClient(handler) { BaseAddress = _server.BaseAddress };
        using var request = new HttpRequestMessage(HttpMethod.Put, new Uri("api/blobs/7", UriKind.Relative))
        {
            Content = new StreamContent(new NonSeekableReadStream(new byte[9_000], maxChunkSize: 1_000)),
        };
        request.Headers.TransferEncodingChunked = true;

        WireRequest received = await SendAndReceiveAsync(client, request, synchronous);

        Assert.True(received.Chunked);
        Assert.Equal(9_000, received.Body.Length);
        AssertVerifies(received);
    }

    [Fact]
    public async Task SendAsync_TypedClientFromConfigurationWithBaseAddress_WireRequestVerifies()
    {
        var services = new ServiceCollection();
        services.AddHmacClient<OrdersApiClient>(options =>
            {
                options.ClientId = "wire-client";
                options.Secret = Secret;
                options.BaseAddress = new Uri(_server.BaseAddress, "v1/");
            })
            .AddHttpMessageHandler(() => new CountingRetryHandler(2));
        using ServiceProvider provider = services.BuildServiceProvider(validateScopes: true);
        HttpClient client = provider.GetRequiredService<OrdersApiClient>().HttpClient;
        using var content = new StreamContent(new NonSeekableReadStream(Encoding.UTF8.GetBytes("{\"order\":\"çay\"}"), maxChunkSize: 3));

        Task<WireRequest> first = _server.AcceptOneAsync(_timeout.Token);
        Task<HttpResponseMessage> sending = client.PostAsync(new Uri("orders?id=5", UriKind.Relative), content, _timeout.Token);
        WireRequest firstAttempt = await first;
        WireRequest secondAttempt = await _server.AcceptOneAsync(_timeout.Token);
        using HttpResponseMessage response = await sending;

        Assert.Equal("/v1/orders?id=5", firstAttempt.Target);
        Assert.Equal(Encoding.UTF8.GetBytes("{\"order\":\"çay\"}"), secondAttempt.Body);
        Assert.True(long.Parse(secondAttempt.Header("X-Timestamp"), System.Globalization.CultureInfo.InvariantCulture)
            > long.Parse(firstAttempt.Header("X-Timestamp"), System.Globalization.CultureInfo.InvariantCulture));
        AssertVerifies(firstAttempt);
        AssertVerifies(secondAttempt);
    }

    private async Task<WireRequest> SendAndReceiveAsync(HttpClient client, HttpRequestMessage request, bool synchronous)
    {
        Task<WireRequest> accept = _server.AcceptOneAsync(_timeout.Token);
        if (synchronous)
        {
            using HttpResponseMessage response = await Task.Run(() => client.Send(request, _timeout.Token), _timeout.Token);
            Assert.True(response.IsSuccessStatusCode);
        }
        else
        {
            using HttpResponseMessage response = await client.SendAsync(request, _timeout.Token);
            Assert.True(response.IsSuccessStatusCode);
        }

        return await accept;
    }

    private static void AssertVerifies(WireRequest received)
    {
        string signature = received.Header("X-Signature");
        Assert.Equal(ReferenceSigner.Sign(Secret, received.Method, received.Target, received.Header("X-Timestamp"), received.Body), signature);
        Assert.True(HmacSha256SignatureService.Instance.VerifySignature(
            Secret, received.Method, received.Target, received.Header("X-Timestamp"), received.Body, signature));
    }

    private static HttpContent? CreateContent(string kind)
    {
        switch (kind)
        {
            case "none":
                return null;
            case "string":
                return new StringContent("{\"name\":\"çay\"}", Encoding.UTF8, "application/json");
            case "stream":
                return new StreamContent(new NonSeekableReadStream(Encoding.UTF8.GetBytes(new string('x', 70_000)), maxChunkSize: 4_096));
            case "stream-wrong-length":
                var wrong = new StreamContent(new NonSeekableReadStream("0123456789"u8.ToArray(), maxChunkSize: 3));
                wrong.Headers.ContentLength = 3;
                return wrong;
            case "json":
                return JsonContent.Create(new { id = 5, name = "tea" });
            case "multipart":
                var multipart = new MultipartFormDataContent("wire-boundary");
                multipart.Add(new StringContent("Ahmet Yılmaz"), "name");
                multipart.Add(new StreamContent(new NonSeekableReadStream(new byte[2_000], maxChunkSize: 100)), "file", "a.bin");
                return multipart;
            default:
                throw new ArgumentOutOfRangeException(nameof(kind), kind, null);
        }
    }
}
