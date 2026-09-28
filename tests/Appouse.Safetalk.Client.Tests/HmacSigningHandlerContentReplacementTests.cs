using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Appouse.Safetalk.Client.Tests.Infrastructure;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// Content that cannot be serialized twice is serialized once into the canonical request and replaced by the exact
/// signed bytes; in-memory content types are left untouched.
/// </summary>
[Collection(ArrayPoolSensitiveGroup.Name)]
public sealed class HmacSigningHandlerContentReplacementTests : IDisposable
{
    private const string TargetUri = "https://api.example.com/api/uploads";

    private readonly RecordingSignatureService _recorder = new();
    private readonly SigningPipeline _pipeline = new();
    private readonly SigningPipeline _recordingPipeline;

    public HmacSigningHandlerContentReplacementTests()
    {
        _recordingPipeline = new SigningPipeline(signatureService: _recorder);
    }

    public void Dispose()
    {
        _pipeline.Dispose();
        _recordingPipeline.Dispose();
    }

    [Theory]
    [InlineData("stream", false)]
    [InlineData("stream", true)]
    [InlineData("json", false)]
    [InlineData("json", true)]
    [InlineData("multipart", false)]
    [InlineData("multipart", true)]
    [InlineData("custom", false)]
    [InlineData("custom", true)]
    public async Task Send_NonReplayableContent_IsReplacedByContentHoldingExactlyTheSignedBytes(string kind, bool synchronous)
    {
        HttpContent original = CreateNonReplayableContent(kind);
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = original };

        await SendAsync(_recordingPipeline, request, synchronous);

        HttpContent replacement = Assert.IsType<SignedRequestContent>(request.Content);
        Assert.NotSame(original, replacement);
        Assert.Same(replacement, Assert.Single(_recordingPipeline.Transport.Contents));

        // The body the transport serialized, the replacement's bytes and the signed canonical body are all identical.
        byte[] signedBody = CanonicalBody(Assert.Single(_recorder.CanonicalRequests));
        CapturedRequest sent = _recordingPipeline.Transport.SingleRequest;
        Assert.Equal(signedBody, sent.Body);
        Assert.Equal(signedBody, await replacement.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));
        Assert.Equal(signedBody.Length, replacement.Headers.ContentLength);
        Assert.NotEmpty(signedBody);
    }

    [Theory]
    [InlineData("stream")]
    [InlineData("json")]
    [InlineData("multipart")]
    [InlineData("custom")]
    public async Task SendAsync_NonReplayableContent_SignatureVerifiesOverTheTransmittedBytes(string kind)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = CreateNonReplayableContent(kind) };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
        Assert.Equal(sent.BodyOrEmpty.Length, sent.ContentLength);
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("string")]
    [InlineData("form")]
    [InlineData("memory")]
    public async Task SendAsync_ReplayableContent_IsNotReplaced(string kind)
    {
        HttpContent original = kind switch
        {
            "bytes" => new ByteArrayContent([1, 2, 3]),
            "string" => new StringContent("{\"a\":1}", Encoding.UTF8, "application/json"),
            "form" => new FormUrlEncodedContent([new KeyValuePair<string, string>("a", "1")]),
            "memory" => new ReadOnlyMemoryContent(new byte[] { 4, 5, 6 }),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = original };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Same(original, request.Content);
        Assert.Same(original, Assert.Single(_pipeline.Transport.Contents));
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_SubclassesOfReplayableTypes_AreReplaced()
    {
        var changing = new ChangingStringContent();
        var derived = new DerivedByteArrayContent([9, 8, 7]);
        using var first = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = changing };
        using var second = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = derived };

        CapturedRequest firstSent = await _pipeline.SendAndCaptureAsync(first);
        CapturedRequest secondSent = await _pipeline.SendAndCaptureAsync(second);

        Assert.IsType<SignedRequestContent>(first.Content);
        Assert.IsType<SignedRequestContent>(second.Content);
        Assert.Equal("attempt-1"u8.ToArray(), firstSent.Body);
        Assert.Equal(new byte[] { 9, 8, 7 }, secondSent.Body);
        Assert.Equal(1, changing.SerializationCount);
    }

    [Fact]
    public async Task SendAsync_StreamContentHeaders_ArePreservedOnTheReplacement()
    {
        var content = new StreamContent(new NonSeekableReadStream("a;b\n1;2\n"u8.ToArray(), maxChunkSize: 3));
        content.Headers.ContentType = new MediaTypeHeaderValue("text/csv") { CharSet = "windows-1254" };
        content.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment") { FileName = "\"rapor 2026.csv\"", Name = "\"file\"" };
        content.Headers.ContentLanguage.Add("tr-TR");
        content.Headers.ContentLanguage.Add("en");
        content.Headers.ContentEncoding.Add("identity");
        content.Headers.ContentMD5 = [1, 2, 3, 4];
        content.Headers.LastModified = new DateTimeOffset(2026, 9, 1, 8, 30, 0, TimeSpan.Zero);
        content.Headers.TryAddWithoutValidation("X-Content-Checksum", "sha256=abc");
        content.Headers.TryAddWithoutValidation("X-Multi", ["one", "two"]);
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = content };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        HttpContentHeaders headers = Assert.IsType<SignedRequestContent>(request.Content).Headers;
        Assert.Equal("text/csv", headers.ContentType?.MediaType);
        Assert.Equal("windows-1254", headers.ContentType?.CharSet);
        Assert.Equal("attachment", headers.ContentDisposition?.DispositionType);
        Assert.Equal("\"rapor 2026.csv\"", headers.ContentDisposition?.FileName);
        Assert.Equal("\"file\"", headers.ContentDisposition?.Name);
        Assert.Equal(["tr-TR", "en"], headers.ContentLanguage);
        Assert.Equal(["identity"], headers.ContentEncoding);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, headers.ContentMD5);
        Assert.Equal(new DateTimeOffset(2026, 9, 1, 8, 30, 0, TimeSpan.Zero), headers.LastModified);
        Assert.Equal(["sha256=abc"], headers.GetValues("X-Content-Checksum"));
        Assert.Equal(["one", "two"], headers.GetValues("X-Multi"));

        // The transport sees the same headers.
        Assert.Equal("text/csv; charset=windows-1254", Assert.Single(sent.ContentHeaders["Content-Type"]));
        Assert.Equal(["sha256=abc"], sent.ContentHeaders["X-Content-Checksum"]);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_UnparsableRawContentHeaderValue_IsCarriedOverVerbatim()
    {
        const string rawContentType = "application/vnd.partner+json; version=\"2";
        var content = new StreamContent(new NonSeekableReadStream("x"u8.ToArray()));
        Assert.True(content.Headers.TryAddWithoutValidation("Content-Type", rawContentType));
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = content };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.IsType<SignedRequestContent>(request.Content);
        Assert.Equal(rawContentType, Assert.Single(sent.ContentHeaders["Content-Type"]));
    }

    [Fact]
    public async Task SendAsync_JsonContent_KeepsContentTypeWithCharset()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = JsonContent.Create(new { name = "çay" }) };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.IsType<SignedRequestContent>(request.Content);
        Assert.Equal("application/json; charset=utf-8", Assert.Single(sent.ContentHeaders["Content-Type"]));
        Assert.Equal("{\"name\":\"\\u00E7ay\"}"u8.ToArray(), sent.Body);
    }

    [Fact]
    public async Task SendAsync_MultipartContent_KeepsBoundaryInContentType()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = CreateMultipart() };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        MediaTypeHeaderValue? contentType = Assert.IsType<SignedRequestContent>(request.Content).Headers.ContentType;
        Assert.Equal("multipart/form-data", contentType?.MediaType);
        Assert.Contains(contentType!.Parameters, p => p.Name == "boundary" && p.Value == "\"safetalk-boundary\"");
        Assert.StartsWith("--safetalk-boundary\r\n", Encoding.UTF8.GetString(sent.BodyOrEmpty), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(3L)]
    [InlineData(0L)]
    [InlineData(1_000L)]
    public async Task SendAsync_StreamContentWithWrongExplicitContentLength_ReplacementAnnouncesTheActualLength(long wrongLength)
    {
        byte[] payload = "0123456789"u8.ToArray();
        var content = new StreamContent(new NonSeekableReadStream(payload));
        content.Headers.ContentLength = wrongLength;
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = content };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        HttpContent replacement = Assert.IsType<SignedRequestContent>(request.Content);
        Assert.Equal(payload.Length, replacement.Headers.ContentLength);
        Assert.Equal(["10"], replacement.Headers.GetValues("Content-Length"));
        Assert.Equal(payload, sent.Body);
        Assert.Equal(payload.Length, sent.ContentLength);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    /// <summary>
    /// A wrong explicit Content-Length is tolerated (the replacement announces the real length), so it must not be
    /// trusted to size the pooled canonical buffer either: a stale or hostile 32 MiB declaration for a 10-byte body
    /// would otherwise rent — and zero on dispose — tens of MiB per request. The server caps the same hint at 8 KiB.
    /// </summary>
    [Fact]
    public async Task SendAsync_ExplicitContentLengthFarLargerThanTheBody_DoesNotRentABufferOfTheDeclaredSize()
    {
        const long declaredLength = 32L * 1024 * 1024;
        const int largeRent = 4 * 1024 * 1024;
        var content = new StreamContent(new NonSeekableReadStream("0123456789"u8.ToArray()));
        content.Headers.ContentLength = declaredLength;
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = content };
        using var listener = new ArrayPoolRentListener();

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal("0123456789"u8.ToArray(), sent.Body);
        Assert.Equal(10, sent.ContentLength);
        Assert.NotEmpty(listener.RentedSizes);
        Assert.DoesNotContain(listener.RentedSizes, size => size >= largeRent);
    }

    [Theory]
    [InlineData(2L)]
    [InlineData(64L)]
    public async Task SendAsync_CustomContentAnnouncingWrongLength_ReplacementAnnouncesTheActualLength(long announcedLength)
    {
        byte[] payload = CreatePayload(20);
        var content = new TrackingContent(payload, announcedLength);
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = content };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(payload, sent.Body);
        Assert.Equal(payload.Length, sent.ContentLength);
        Assert.Equal(1, content.SerializationCount);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_ReplacedCustomContent_IsDisposedOnlyWhenTheRequestIsDisposed()
    {
        var original = new TrackingContent(CreatePayload(100));
        var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = original };

        HttpResponseMessage response = await _pipeline.Invoker.SendAsync(request, TestContext.Current.CancellationToken);
        response.Dispose();

        Assert.IsType<SignedRequestContent>(request.Content);
        Assert.False(original.IsDisposed);

        request.Dispose();

        Assert.True(original.IsDisposed);
    }

    /// <summary>
    /// Uses a seekable source: <see cref="StreamContent"/> itself disposes a non-seekable source as soon as it has
    /// consumed it, whoever reads it.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Send_ReplacedStreamContent_UnderlyingStreamIsDisposedOnlyWhenTheRequestIsDisposed(bool synchronous)
    {
        var source = new DisposeTrackingMemoryStream(CreatePayload(4_000));
        var original = new StreamContent(source);
        var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = original };

        await SendAsync(_pipeline, request, synchronous);

        Assert.NotSame(original, request.Content);
        Assert.False(source.IsDisposed);

        request.Dispose();

        Assert.True(source.IsDisposed);
    }

    [Fact]
    public async Task SendAsync_ReplacementDisposedDirectly_DisposesTheOriginalContent()
    {
        var original = new TrackingContent(CreatePayload(10));
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = original };
        await _pipeline.SendAndCaptureAsync(request);

        request.Content!.Dispose();
        request.Content.Dispose();

        Assert.True(original.IsDisposed);
    }

    [Fact]
    public async Task SendAsync_OriginalDisposedByCallerFirst_RequestDisposalStillSucceeds()
    {
        var original = new TrackingContent(CreatePayload(10));
        var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = original };
        await _pipeline.SendAndCaptureAsync(request);

        original.Dispose();
        request.Dispose();

        Assert.True(original.IsDisposed);
    }

    [Fact]
    public async Task SendAsync_ReplacedContentSentAgain_IsReusedWithoutRewrappingOrReserializingTheOriginal()
    {
        var original = new TrackingContent("{\"id\":1}"u8.ToArray());
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = original };

        CapturedRequest first = await _pipeline.SendAndCaptureAsync(request);
        HttpContent? afterFirst = request.Content;
        CapturedRequest second = await _pipeline.SendAndCaptureAsync(request);

        Assert.IsType<SignedRequestContent>(afterFirst);
        Assert.Same(afterFirst, request.Content);
        Assert.Equal(1, original.SerializationCount);
        Assert.Equal(first.Body, second.Body);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, second), second.Signature);
    }

    [Fact]
    public async Task SendAsync_EmptyNonReplayableContent_IsReplacedByZeroLengthContent()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = new StreamContent(new NonSeekableReadStream([])) };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.IsType<SignedRequestContent>(request.Content);
        Assert.Equal(0, request.Content.Headers.ContentLength);
        Assert.NotNull(sent.Body);
        Assert.Empty(sent.Body);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, "POST", "/api/uploads", sent.Timestamp, []), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_ContentSerializationFails_OriginalContentIsKept()
    {
        var content = new ThrowingContent();
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = content };

        await Assert.ThrowsAnyAsync<Exception>(() => _pipeline.Invoker.SendAsync(request, TestContext.Current.CancellationToken));

        Assert.Same(content, request.Content);
        Assert.Equal(0, _pipeline.Transport.InvocationCount);
    }

    [Fact]
    public async Task SendAsync_ReplacementContent_CanBeReadRepeatedlyAndIsReadOnly()
    {
        byte[] payload = CreatePayload(300);
        using var request = new HttpRequestMessage(HttpMethod.Post, TargetUri) { Content = new StreamContent(new NonSeekableReadStream(payload)) };
        await _pipeline.SendAndCaptureAsync(request);
        HttpContent replacement = request.Content!;
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        Assert.Equal(payload, await replacement.ReadAsByteArrayAsync(cancellationToken));
        Assert.Equal(payload, await replacement.ReadAsByteArrayAsync(cancellationToken));
        using Stream stream = await replacement.ReadAsStreamAsync(cancellationToken);
        Assert.False(stream.CanWrite);
        using var copy = new MemoryStream();
        replacement.CopyTo(copy, context: null, cancellationToken);
        Assert.Equal(payload, copy.ToArray());
    }

    private static async Task SendAsync(SigningPipeline pipeline, HttpRequestMessage request, bool synchronous)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using HttpResponseMessage response = synchronous
            ? pipeline.Invoker.Send(request, cancellationToken)
            : await pipeline.Invoker.SendAsync(request, cancellationToken);
    }

    private static byte[] CanonicalBody(byte[] canonicalRequest)
    {
        // "{METHOD}\n{PATH-AND-QUERY}\n{TIMESTAMP}\n{BODY}": the body starts after the third line feed.
        int start = 0;
        for (int i = 0; i < 3; i++)
        {
            start = Array.IndexOf(canonicalRequest, (byte)'\n', start) + 1;
        }

        return canonicalRequest[start..];
    }

    private static HttpContent CreateNonReplayableContent(string kind) => kind switch
    {
        "stream" => new StreamContent(new NonSeekableReadStream(CreatePayload(5_000), maxChunkSize: 321)),
        "json" => JsonContent.Create(new { id = 5, name = "tea", price = 12.5m }),
        "multipart" => CreateMultipart(),
        "custom" => new TrackingContent(CreatePayload(777)),
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };

    private static MultipartFormDataContent CreateMultipart()
    {
        var multipart = new MultipartFormDataContent("safetalk-boundary");
        multipart.Add(new StringContent("Ahmet Yılmaz"), "name");
        multipart.Add(new StreamContent(new NonSeekableReadStream(CreatePayload(1_500), maxChunkSize: 11)), "file", "invoice.pdf");
        return multipart;
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)((i * 13) + 5);
        }

        return payload;
    }

    private sealed class DerivedByteArrayContent(byte[] content) : ByteArrayContent(content);

    private sealed class DisposeTrackingMemoryStream(byte[] buffer) : MemoryStream(buffer)
    {
        public bool IsDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }
}
