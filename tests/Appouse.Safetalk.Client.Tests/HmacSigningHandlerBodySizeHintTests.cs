using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// The declared <c>Content-Length</c> is only a size hint for the pooled canonical buffer and is capped at 1 MiB: a
/// stale or hostile explicit value must neither rent a buffer of its size nor overflow, and bodies larger than the cap
/// must still be signed and sent intact (the buffer grows as bytes arrive).
/// </summary>
[Collection(ArrayPoolSensitiveGroup.Name)]
public sealed class HmacSigningHandlerBodySizeHintTests : IDisposable
{
    private const string Secret = "size-hint-secret-0123456789abcdef";
    private const int OneMiB = 1024 * 1024;
    private const long StaleDeclaredLength = 32L * OneMiB;

    private static readonly byte[] SmallBody = "0123456789"u8.ToArray();

    private readonly SigningPipeline _pipeline = new(new HmacClientOptions { ClientId = "size-client", Secret = Secret });
    private readonly LoopbackHttpServer _server = new();
    private readonly CancellationTokenSource _timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

    public HmacSigningHandlerBodySizeHintTests()
    {
        _timeout.CancelAfter(TimeSpan.FromSeconds(30));
    }

    public void Dispose()
    {
        _timeout.Dispose();
        _server.Dispose();
        _pipeline.Dispose();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Send_StaleExplicitContentLengthOf32MiBOnATenByteStream_RentsNoBufferOfTheDeclaredSizeAndTheWireBodyIsCorrect(bool synchronous)
    {
        using var handler = new HmacSigningHandler(
            new HmacClientOptions { ClientId = "size-client", Secret = Secret },
            HmacSha256SignatureService.Instance,
            TimeProvider.System,
            NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = new SocketsHttpHandler { UseProxy = false },
        };
        using var client = new HttpClient(handler) { BaseAddress = _server.BaseAddress };
        var content = new StreamContent(new NonSeekableReadStream(SmallBody, maxChunkSize: 3));
        content.Headers.ContentLength = StaleDeclaredLength;
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("api/uploads?id=9", UriKind.Relative)) { Content = content };
        using var listener = new ArrayPoolRentListener();

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

        WireRequest received = await accept;

        Assert.False(received.Chunked);
        Assert.Equal("10", received.Header("Content-Length"));
        Assert.Equal(SmallBody, received.Body);
        Assert.Equal(ReferenceSigner.Sign(Secret, received.Method, received.Target, received.Header("X-Timestamp"), received.Body), received.Header("X-Signature"));
        Assert.NotEmpty(listener.RentedSizes);
        Assert.DoesNotContain(listener.RentedSizes, size => size >= StaleDeclaredLength);
        Assert.DoesNotContain(listener.RentedSizes, size => size > 2 * OneMiB);
    }

    [Theory]
    [InlineData(OneMiB + 1L)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MaxValue + 1L)]
    [InlineData(3L * 1024 * OneMiB)]
    [InlineData(long.MaxValue)]
    public async Task SendAsync_DeclaredLengthBeyondTheCapOrBeyondInt32_IsCappedAndTheBodyIsSignedIntact(long declaredLength)
    {
        var content = new StreamContent(new NonSeekableReadStream(SmallBody, maxChunkSize: 4));
        content.Headers.ContentLength = declaredLength;
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/uploads") { Content = content };
        using var listener = new ArrayPoolRentListener();

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(SmallBody, sent.Body);
        Assert.Equal(SmallBody.Length, sent.ContentLength);
        Assert.Equal(ReferenceSigner.Sign(Secret, sent), sent.Signature);
        Assert.DoesNotContain(listener.RentedSizes, size => size > 2 * OneMiB);
    }

    [Theory]
    [InlineData(OneMiB - 64)]
    [InlineData(OneMiB)]
    [InlineData(OneMiB + 1)]
    [InlineData((3 * OneMiB) + 17)]
    public async Task SendAsync_StreamBodyAroundAndAboveTheCapWithCorrectContentLength_IsSignedAndSentIntact(int length)
    {
        byte[] payload = CreatePayload(length);
        var content = new StreamContent(new NonSeekableReadStream(payload, maxChunkSize: 64 * 1024));
        content.Headers.ContentLength = length;
        using var request = new HttpRequestMessage(HttpMethod.Put, "https://api.example.com/api/blobs/1") { Content = content };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(payload, sent.Body);
        Assert.Equal(length, sent.ContentLength);
        Assert.Equal(ReferenceSigner.Sign(Secret, sent), sent.Signature);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Send_ByteArrayContentLargerThanTheCap_IsSignedIntactAndNotReplaced(bool synchronous)
    {
        byte[] payload = CreatePayload((2 * OneMiB) + 5);
        var content = new ByteArrayContent(payload);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/blobs") { Content = content };

        if (synchronous)
        {
            using (_pipeline.Invoker.Send(request, TestContext.Current.CancellationToken))
            {
            }
        }
        else
        {
            using (await _pipeline.Invoker.SendAsync(request, TestContext.Current.CancellationToken))
            {
            }
        }

        CapturedRequest sent = _pipeline.Transport.SingleRequest;
        Assert.Same(content, request.Content);
        Assert.Equal(payload, sent.Body);
        Assert.Equal(ReferenceSigner.Sign(Secret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_StaleSmallerContentLengthOnALargeStream_SendsAndSignsTheWholeBody()
    {
        byte[] payload = CreatePayload((2 * OneMiB) + 3);
        var content = new StreamContent(new NonSeekableReadStream(payload, maxChunkSize: 100_000));
        content.Headers.ContentLength = 10;
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/blobs") { Content = content };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(payload, sent.Body);
        Assert.Equal(payload.Length, sent.ContentLength);
        Assert.Equal(ReferenceSigner.Sign(Secret, sent), sent.Signature);
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)((i * 31) + (i >> 11));
        }

        return payload;
    }
}
