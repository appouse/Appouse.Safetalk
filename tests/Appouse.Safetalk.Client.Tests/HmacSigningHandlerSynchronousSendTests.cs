using System.Globalization;
using System.Net.Http.Json;
using System.Text;
using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// <see cref="HttpClient.Send(HttpRequestMessage, CancellationToken)"/> and
/// <see cref="HttpMessageInvoker.Send(HttpRequestMessage, CancellationToken)"/> run the synchronous handler pipeline;
/// the request must be signed there exactly as on the asynchronous path.
/// </summary>
public sealed class HmacSigningHandlerSynchronousSendTests : IDisposable
{
    private readonly SigningPipeline _pipeline = new();

    public void Dispose() => _pipeline.Dispose();

    [Fact]
    public void Send_GetWithoutContent_IsSignedOnTheSynchronousPath()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders?id=5");

        using HttpResponseMessage response = _pipeline.Invoker.Send(request, TestContext.Current.CancellationToken);

        Assert.Equal(1, _pipeline.Transport.SynchronousInvocationCount);
        CapturedRequest sent = _pipeline.Transport.SingleRequest;
        Assert.Null(sent.Body);
        Assert.Equal(SigningPipeline.DefaultClientId, sent.ClientId);
        Assert.Equal("1790000000", sent.Timestamp);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, "GET", "/api/orders?id=5", "1790000000", []), sent.Signature);
    }

    [Fact]
    public void Send_StringContent_SignsBodyAndKeepsTheOriginalContentInstance()
    {
        using var content = new StringContent("{\"product\":\"çay\"}", Encoding.UTF8, "application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = content };

        using HttpResponseMessage response = _pipeline.Invoker.Send(request, TestContext.Current.CancellationToken);

        CapturedRequest sent = _pipeline.Transport.SingleRequest;
        Assert.Same(content, request.Content);
        Assert.Equal(Encoding.UTF8.GetBytes("{\"product\":\"çay\"}"), sent.Body);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
        Assert.Equal("application/json; charset=utf-8", Assert.Single(sent.ContentHeaders["Content-Type"]));
    }

    [Fact]
    public void Send_NonSeekableStreamContent_SendsTheSignedBytesThroughAReplacementContent()
    {
        byte[] payload = CreatePayload(20_000);
        var source = new NonSeekableReadStream(payload, maxChunkSize: 777);
        var content = new StreamContent(source);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/uploads") { Content = content };

        using HttpResponseMessage response = _pipeline.Invoker.Send(request, TestContext.Current.CancellationToken);

        CapturedRequest sent = _pipeline.Transport.SingleRequest;
        Assert.NotSame(content, request.Content);
        Assert.Equal(payload, sent.Body);
        Assert.Equal(payload.Length, sent.ContentLength);
        Assert.Equal(payload.Length, source.TotalBytesRead);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("string")]
    [InlineData("stream")]
    [InlineData("json")]
    [InlineData("multipart")]
    [InlineData("form")]
    [InlineData("bytes")]
    [InlineData("memory")]
    public async Task Send_SameRequestAsAsynchronousSend_ProducesIdenticalHeadersAndBody(string contentKind)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var syncRequest = new HttpRequestMessage(HttpMethod.Put, "https://api.example.com/api/orders/7?v=2") { Content = CreateContent(contentKind) };
        using var asyncRequest = new HttpRequestMessage(HttpMethod.Put, "https://api.example.com/api/orders/7?v=2") { Content = CreateContent(contentKind) };

        using (_pipeline.Invoker.Send(syncRequest, cancellationToken))
        using (await _pipeline.Invoker.SendAsync(asyncRequest, cancellationToken))
        {
        }

        Assert.Equal(1, _pipeline.Transport.SynchronousInvocationCount);
        CapturedRequest sync = _pipeline.Transport.Requests[0];
        CapturedRequest async = _pipeline.Transport.Requests[1];
        Assert.Equal(async.Body, sync.Body);
        Assert.Equal(async.Timestamp, sync.Timestamp);
        Assert.Equal(async.Signature, sync.Signature);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sync), sync.Signature);
        Assert.True(HmacSha256SignatureService.Instance.VerifySignature(
            SigningPipeline.DefaultSecret, "PUT", sync.PathAndQuery, sync.Timestamp, sync.BodyOrEmpty, sync.Signature));
    }

    [Fact]
    public void Send_WithLogger_LogsTheSameDebugEventAsTheAsynchronousPath()
    {
        var logger = new ListLogger<HmacSigningHandler>();
        using var pipeline = new SigningPipeline(logger: logger);
        using var request = new HttpRequestMessage(HttpMethod.Delete, "https://api.example.com/api/orders/9");

        using HttpResponseMessage response = pipeline.Invoker.Send(request, TestContext.Current.CancellationToken);

        LogEntry entry = Assert.Single(logger.Entries);
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Debug, entry.Level);
        Assert.Equal(1, entry.EventId.Id);
        Assert.Contains("DELETE", entry.Message, StringComparison.Ordinal);
        Assert.Contains("/api/orders/9", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(SigningPipeline.DefaultSecret, entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void HttpClientSend_RelativeUriAgainstBaseAddress_IsSigned()
    {
        using HttpClient client = _pipeline.CreateClient(new Uri("https://api.example.com/v1/"));
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("orders?id=5", UriKind.Relative))
        {
            Content = new StreamContent(new NonSeekableReadStream("{\"id\":5}"u8.ToArray(), maxChunkSize: 2)),
        };

        using HttpResponseMessage response = client.Send(request, TestContext.Current.CancellationToken);

        Assert.Equal(1, _pipeline.Transport.SynchronousInvocationCount);
        CapturedRequest sent = _pipeline.Transport.SingleRequest;
        Assert.Equal("/v1/orders?id=5", sent.PathAndQuery);
        Assert.Equal("{\"id\":5}"u8.ToArray(), sent.Body);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Fact]
    public void Send_RelativeRequestUri_ThrowsInvalidOperationExceptionAndDoesNotSend()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/orders", UriKind.Relative));

        Assert.Throws<InvalidOperationException>(() => _pipeline.Invoker.Send(request, TestContext.Current.CancellationToken));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.False(request.Headers.Contains(CapturedRequest.SignatureHeader));
    }

    [Fact]
    public void Send_ContentWithoutSynchronousSerialization_ThrowsNotSupportedAndDoesNotSend()
    {
        // ChangingContent only implements SerializeToStreamAsync; a synchronous transport could not send it either.
        var content = new ChangingContent();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = content };

        Assert.Throws<NotSupportedException>(() => _pipeline.Invoker.Send(request, TestContext.Current.CancellationToken));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.Same(content, request.Content);
        Assert.False(request.Headers.Contains(CapturedRequest.SignatureHeader));
    }

    [Fact]
    public void Send_ContentSerializationFails_PropagatesAndDoesNotSend()
    {
        var source = new NonSeekableReadStream(new byte[100], onRead: () => throw new IOException("The source broke."));
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new StreamContent(source) };

        Exception exception = Assert.ThrowsAny<Exception>(() => _pipeline.Invoker.Send(request, TestContext.Current.CancellationToken));

        Assert.True(exception is IOException or HttpRequestException, $"Unexpected exception {exception.GetType()}.");
        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.IsType<StreamContent>(request.Content);
    }

    [Fact]
    public void Send_RetryHandlerOutsideSigning_ReSignsEverySynchronousAttempt()
    {
        var transport = new CapturingHandler();
        var signing = new HmacSigningHandler(_pipeline.Options, HmacSha256SignatureService.Instance, _pipeline.Time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        using var retry = new CountingRetryHandler(3) { InnerHandler = signing };
        using var invoker = new HttpMessageInvoker(retry);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders")
        {
            Content = new StreamContent(new NonSeekableReadStream("{\"order\":1}"u8.ToArray(), maxChunkSize: 3)),
        };

        using HttpResponseMessage response = invoker.Send(request, TestContext.Current.CancellationToken);

        Assert.Equal(3, transport.SynchronousInvocationCount);
        Assert.Equal(["1790000000", "1790000001", "1790000002"], transport.Requests.Select(r => r.Timestamp));
        Assert.Equal(3, transport.Requests.Select(r => r.Signature).Distinct(StringComparer.Ordinal).Count());
        Assert.All(transport.Requests, attempt =>
        {
            Assert.Equal("{\"order\":1}"u8.ToArray(), attempt.Body);
            Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, attempt), attempt.Signature);
        });
    }

    [Fact]
    public async Task Send_ConcurrentSynchronousRequestsThroughOneHandler_EachRequestIsSignedOverItsOwnBody()
    {
        using HttpClient client = _pipeline.CreateClient(new Uri("https://api.example.com/"));
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await Task.WhenAll(Enumerable.Range(0, 48).Select(i => Task.Run(
            () =>
            {
                byte[] body = Encoding.ASCII.GetBytes(new string((char)('a' + (i % 26)), 50 + (i * 41)));
                using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"api/items/{i}", UriKind.Relative))
                {
                    Content = i % 2 == 0 ? new ByteArrayContent(body) : new StreamContent(new NonSeekableReadStream(body, maxChunkSize: 13)),
                };
                using HttpResponseMessage response = client.Send(request, cancellationToken);
            },
            cancellationToken)));

        IReadOnlyList<CapturedRequest> requests = _pipeline.Transport.Requests;
        Assert.Equal(48, requests.Count);
        Assert.Equal(48, _pipeline.Transport.SynchronousInvocationCount);
        Assert.All(requests, sent =>
        {
            int index = int.Parse(sent.PathAndQuery["/api/items/".Length..], CultureInfo.InvariantCulture);
            Assert.Equal(50 + (index * 41), sent.BodyOrEmpty.Length);
            Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
        });
    }

    private static HttpContent? CreateContent(string kind) => kind switch
    {
        "none" => null,
        "string" => new StringContent("{\"status\":\"shipped\"}", Encoding.UTF8, "application/json"),
        "stream" => new StreamContent(new NonSeekableReadStream(CreatePayload(3_000), maxChunkSize: 100)),
        "json" => JsonContent.Create(new { id = 7, status = "shipped" }),
        "multipart" => CreateMultipart(),
        "form" => new FormUrlEncodedContent([new KeyValuePair<string, string>("status", "shipped")]),
        "bytes" => new ByteArrayContent(CreatePayload(64), 3, 50),
        "memory" => new ReadOnlyMemoryContent(CreatePayload(80).AsMemory(10, 60)),
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };

    private static MultipartFormDataContent CreateMultipart()
    {
        var multipart = new MultipartFormDataContent("fixed-boundary");
        multipart.Add(new StringContent("Ahmet"), "name");
        multipart.Add(new StreamContent(new NonSeekableReadStream(CreatePayload(500), maxChunkSize: 7)), "file", "a.bin");
        return multipart;
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)((i * 7) + 3);
        }

        return payload;
    }
}
