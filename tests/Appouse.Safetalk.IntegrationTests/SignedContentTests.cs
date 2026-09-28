using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Content that cannot be serialized twice is serialized once into the signed buffer and replaced by exactly those
/// bytes: what is sent is always what was signed.
/// </summary>
public sealed class SignedContentTests
{
    /// <summary>
    /// A content that produces different bytes on every serialization (think of a generator, a timestamped payload or
    /// a buggy custom content). Without replacement the signed bytes and the sent bytes would differ.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ContentProducingDifferentBytesOnEachSerialization_IsSerializedOnce_AndTheSignedBytesAreSent(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var content = new GeneratorContent();

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        byte[] firstSerialization = Encoding.UTF8.GetBytes("generated-payload-1");
        Assert.Equal(TestData.Sha256Hex(firstSerialization), body.Sha256);
        Assert.Equal(1, content.Serializations);
    }

    /// <summary>
    /// Replayable content types are recognised by their exact type, so a subclass of <see cref="ByteArrayContent"/>
    /// with custom serialization is treated as non-replayable.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ByteArrayContentSubclassWithCustomSerialization_IsNotTrustedAsReplayable(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var content = new SuffixingByteArrayContent(Encoding.UTF8.GetBytes("base"));

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(Encoding.UTF8.GetBytes("base-1")), body.Sha256);
        Assert.Equal(1, content.Serializations);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task StreamContent_IsReplacedBySignedBytes_ContentHeadersAreKept_AndContentLengthIsComputed(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        byte[] payload = TestData.CreateBytes(40_000, seed: 17);
        var original = new StreamContent(new NonSeekableReadStream(payload));
        original.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        original.Headers.ContentLanguage.Add("tr-TR");
        original.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment") { FileName = "fatura.pdf" };
        original.Headers.TryAddWithoutValidation("X-Content-Custom", "kept");
        using var request = new HttpRequestMessage(HttpMethod.Put, new Uri("/api/headers", UriKind.Relative)) { Content = original };

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct);

        ContentHeadersResponse echo = await response.ReadOkJsonAsync<ContentHeadersResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, echo.ClientId);
        Assert.Equal("application/pdf", echo.ContentType);
        Assert.Equal("tr-TR", echo.ContentLanguage);
        Assert.Contains("fatura.pdf", echo.ContentDisposition, StringComparison.Ordinal);
        Assert.Equal("kept", echo.CustomContentHeader);
        Assert.Equal(payload.Length, echo.ContentLength);
        Assert.Equal(TestData.Sha256Hex(payload), echo.Sha256);

        // The message now carries the exact signed bytes and can be read (or re-sent) again.
        Assert.NotSame(original, request.Content);
        Assert.Equal(payload, await request.Content!.ReadAsByteArrayAsync(ct));
    }

    /// <summary>
    /// A stale explicit <c>Content-Length</c> on non-replayable content is not carried over to the replacement, which
    /// would otherwise corrupt the framing of the signed body. A huge stale value is only a size hint capped at 1 MiB,
    /// so it neither rents a huge pooled buffer nor fails the request.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, 10)]
    [InlineData(TestHostKind.Kestrel, 10)]
    [InlineData(TestHostKind.TestServer, 999_999)]
    [InlineData(TestHostKind.Kestrel, 999_999)]
    [InlineData(TestHostKind.TestServer, int.MaxValue)]
    [InlineData(TestHostKind.Kestrel, int.MaxValue)]
    [InlineData(TestHostKind.TestServer, long.MaxValue)]
    [InlineData(TestHostKind.Kestrel, long.MaxValue)]
    public async Task StaleExplicitContentLengthOnStreamContent_IsReplacedByTheSignedLength(TestHostKind kind, long staleLength)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        byte[] payload = TestData.CreateBytes(5_000, seed: 23);
        using var content = new StreamContent(new MemoryStream(payload));
        content.Headers.ContentLength = staleLength;

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(payload.Length, body.ContentLength);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayableByteArrayContent_IsSentAsIs_WithoutReplacement(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        var content = new ByteArrayContent(TestData.CreateBytes(1_000));
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative)) { Content = content };

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Same(content, request.Content);
    }

    /// <summary>
    /// The replaced original keeps its owner semantics: it is disposed with the request message, not earlier.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplacedOriginalContent_IsDisposedWithTheRequestMessage_NotBefore(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        var stream = new DisposeTrackingStream(TestData.CreateBytes(2_000, seed: 5));
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative)) { Content = new StreamContent(stream) };

        using (HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        bool disposedBeforeRequest = stream.IsDisposed;
        request.Dispose();

        Assert.False(disposedBeforeRequest);
        Assert.True(stream.IsDisposed);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AlreadyCancelledToken_ThrowsBeforeSigning_AndNothingIsSent(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        var content = new GeneratorContent();
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative)) { Content = content };
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, cancelled.Token));

        Assert.False(request.Headers.Contains(SafetalkHeaderNames.Signature));
        Assert.Equal(0, content.Serializations);
        Assert.Same(content, request.Content);
        Assert.Empty(server.ValidationResults);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ContentFailingDuringSerialization_PropagatesTheError_AndNothingIsSent(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative))
        {
            Content = new StreamContent(new FailingReadStream(failAfter: 3_000)),
        };

        Exception exception = await Assert.ThrowsAnyAsync<Exception>(() => clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct));

        // HttpContent.CopyToAsync wraps stream failures in an HttpRequestException.
        Assert.True(exception is IOException || exception.InnerException is IOException, exception.ToString());
        Assert.False(request.Headers.Contains(SafetalkHeaderNames.Signature));
        Assert.Empty(server.ValidationResults);
    }

    /// <summary>Produces <c>generated-payload-{n}</c>, n being the number of serializations so far.</summary>
    private sealed class GeneratorContent : HttpContent
    {
        private int _serializations;

        public int Serializations => Volatile.Read(ref _serializations);

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            int n = Interlocked.Increment(ref _serializations);
            return stream.WriteAsync(Encoding.UTF8.GetBytes($"generated-payload-{n}")).AsTask();
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    /// <summary>A <see cref="ByteArrayContent"/> subclass that appends <c>-{n}</c> on every serialization.</summary>
    private sealed class SuffixingByteArrayContent(byte[] content) : ByteArrayContent(content)
    {
        private readonly byte[] _content = content;
        private int _serializations;

        public int Serializations => Volatile.Read(ref _serializations);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            int n = Interlocked.Increment(ref _serializations);
            await stream.WriteAsync(_content);
            await stream.WriteAsync(Encoding.UTF8.GetBytes($"-{n}"));
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
            => SerializeToStreamAsync(stream, context);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class DisposeTrackingStream(byte[] data) : MemoryStream(data, writable: false)
    {
        public bool IsDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }

    /// <summary>A non-seekable stream that fails with an <see cref="IOException"/> after some bytes.</summary>
    private sealed class FailingReadStream(int failAfter) : Stream
    {
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_position >= failAfter)
            {
                throw new IOException("The source failed while being read.");
            }

            int read = Math.Min(count, failAfter - _position);
            Array.Fill(buffer, (byte)'x', offset, read);
            _position += read;
            return read;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
