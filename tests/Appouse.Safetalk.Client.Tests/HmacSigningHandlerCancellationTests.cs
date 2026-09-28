using Appouse.Safetalk.Client.Tests.Infrastructure;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// A request whose token is already cancelled must not be signed and forwarded to the transport.
/// </summary>
public sealed class HmacSigningHandlerCancellationTests : IDisposable
{
    private readonly SigningPipeline _pipeline = new();

    public void Dispose() => _pipeline.Dispose();

    [Fact]
    public async Task SendAsync_CancelledTokenWithStringContent_ThrowsAndDoesNotSend()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new StringContent("{}") };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _pipeline.Invoker.SendAsync(request, new CancellationToken(canceled: true)));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.False(request.Headers.Contains("X-Signature"));
    }

    [Fact]
    public async Task SendAsync_CancelledTokenWithStreamContent_ThrowsAndDoesNotSend()
    {
        var source = new NonSeekableReadStream(new byte[128]);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new StreamContent(source) };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _pipeline.Invoker.SendAsync(request, new CancellationToken(canceled: true)));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.Equal(0, source.TotalBytesRead);
    }

    [Fact]
    public async Task SendAsync_CancelledTokenWithoutContent_ThrowsAndDoesNotSend()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _pipeline.Invoker.SendAsync(request, new CancellationToken(canceled: true)));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.False(request.Headers.Contains("X-Signature"));
    }

    [Fact]
    public async Task SendAsync_CancelledTokenThroughHttpClient_ThrowsTaskCanceledAndDoesNotSend()
    {
        using HttpClient client = _pipeline.CreateClient(new Uri("https://api.example.com/"));
        using var content = new StringContent("{}");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.PostAsync(new Uri("api/orders", UriKind.Relative), content, new CancellationToken(canceled: true)));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
    }

    [Theory]
    [InlineData("GET", false)]
    [InlineData("GET", true)]
    [InlineData("POST", false)]
    [InlineData("POST", true)]
    public async Task Send_CancelledToken_ThrowsBeforeContentIsReadReplacedOrSigned(string method, bool synchronous)
    {
        var source = new NonSeekableReadStream(new byte[256]);
        HttpContent? content = method == "POST" ? new StreamContent(source) : null;
        using var request = new HttpRequestMessage(new HttpMethod(method), "https://api.example.com/api/orders") { Content = content };
        var cancelled = new CancellationToken(canceled: true);

        if (synchronous)
        {
            Assert.ThrowsAny<OperationCanceledException>(() => _pipeline.Invoker.Send(request, cancelled));
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _pipeline.Invoker.SendAsync(request, cancelled));
        }

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.Same(content, request.Content);
        Assert.Equal(0, source.TotalBytesRead);
        Assert.False(source.IsDisposed);
        Assert.False(request.Headers.Contains(CapturedRequest.SignatureHeader));
        Assert.False(request.Headers.Contains(CapturedRequest.TimestampHeader));
        Assert.False(request.Headers.Contains(CapturedRequest.ClientIdHeader));
        Assert.False(request.Options.TryGetValue(new HttpRequestOptionsKey<long>("Appouse.Safetalk.LastSignedTimestamp"), out _));
    }

    [Fact]
    public async Task SendAsync_CancelledAttemptThenRetriedWithLiveToken_UsesCurrentTimestampNotABumpedOne()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new StringContent("{}") };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _pipeline.Invoker.SendAsync(request, new CancellationToken(canceled: true)));
        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        // The cancelled attempt never reached signing, so it did not consume a timestamp.
        Assert.Equal("1790000000", sent.Timestamp);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Fact]
    public void Send_CancelledTokenThroughHttpClient_ThrowsAndDoesNotSend()
    {
        using HttpClient client = _pipeline.CreateClient(new Uri("https://api.example.com/"));
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("api/orders", UriKind.Relative)) { Content = new StringContent("{}") };

        Assert.ThrowsAny<OperationCanceledException>(() => client.Send(request, new CancellationToken(canceled: true)));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
    }

    [Fact]
    public async Task SendAsync_CancelledWhileBufferingContent_ThrowsAndDoesNotSend()
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var source = new NonSeekableReadStream(new byte[4_096], maxChunkSize: 64, onRead: cancellation.Cancel);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new StreamContent(source) };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _pipeline.Invoker.SendAsync(request, cancellation.Token));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
    }
}
