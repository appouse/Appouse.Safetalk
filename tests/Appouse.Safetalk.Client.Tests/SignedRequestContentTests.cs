using System.Net.Http.Headers;
using Appouse.Safetalk.Client.Tests.Infrastructure;

namespace Appouse.Safetalk.Client.Tests;

public sealed class SignedRequestContentTests
{
    private static readonly byte[] Body = "{\"id\":42,\"name\":\"çay\"}"u8.ToArray();

    [Fact]
    public async Task Constructor_CopiesTheBodySoLaterChangesToTheSourceDoNotLeak()
    {
        byte[] source = [.. Body];
        using var original = new TrackingContent([]);
        using var content = new SignedRequestContent(original, source);

        source.AsSpan().Clear();

        Assert.Equal(Body, await content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Constructor_CopiesEveryContentHeaderExceptContentLength()
    {
        using var original = new StreamContent(new MemoryStream(Body));
        original.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        original.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data") { Name = "\"payload\"" };
        original.Headers.ContentLength = 999;
        original.Headers.TryAddWithoutValidation("X-Custom", ["a", "b"]);

        using var content = new SignedRequestContent(original, Body);

        Assert.Equal("application/json; charset=utf-8", content.Headers.ContentType?.ToString());
        Assert.Equal("form-data; name=\"payload\"", content.Headers.ContentDisposition?.ToString());
        Assert.Equal(["a", "b"], content.Headers.GetValues("X-Custom"));
        Assert.Equal(Body.Length, content.Headers.ContentLength);
        Assert.Equal([Body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)], content.Headers.GetValues("Content-Length"));
    }

    [Fact]
    public void Constructor_OriginalWithoutHeaders_HasOnlyTheComputedContentLength()
    {
        using var original = new TrackingContent([]);
        using var content = new SignedRequestContent(original, Body);

        Assert.Equal(Body.Length, content.Headers.ContentLength);
        Assert.Equal(["Content-Length"], content.Headers.Select(h => h.Key));
    }

    [Fact]
    public async Task EmptyBody_HasZeroContentLengthAndSerializesNothing()
    {
        using var original = new TrackingContent([]);
        using var content = new SignedRequestContent(original, []);

        Assert.Equal(0, content.Headers.ContentLength);
        Assert.Empty(await content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Serialization_IsRepeatableThroughEveryApi()
    {
        using var original = new TrackingContent([]);
        using var content = new SignedRequestContent(original, Body);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using var asyncCopy = new MemoryStream();
        await content.CopyToAsync(asyncCopy, cancellationToken);
        using var syncCopy = new MemoryStream();
        content.CopyTo(syncCopy, context: null, cancellationToken);
        using var secondAsyncCopy = new MemoryStream();
        await content.CopyToAsync(secondAsyncCopy, cancellationToken);
        using Stream asyncStream = await content.ReadAsStreamAsync(cancellationToken);
        using var fromAsyncStream = new MemoryStream();
        await asyncStream.CopyToAsync(fromAsyncStream, cancellationToken);

        Assert.Equal(Body, asyncCopy.ToArray());
        Assert.Equal(Body, syncCopy.ToArray());
        Assert.Equal(Body, secondAsyncCopy.ToArray());
        Assert.Equal(Body, fromAsyncStream.ToArray());
        Assert.False(asyncStream.CanWrite);
        Assert.Equal(0, original.SerializationCount);
    }

    [Fact]
    public void ReadAsStream_Synchronous_ReturnsReadOnlyStreamOverTheBody()
    {
        // HttpContent caches the read stream and forbids mixing ReadAsStream with ReadAsStreamAsync on one instance.
        using var original = new TrackingContent([]);
        using var content = new SignedRequestContent(original, Body);

        using Stream stream = content.ReadAsStream(TestContext.Current.CancellationToken);
        using var copy = new MemoryStream();
        stream.CopyTo(copy);

        Assert.Equal(Body, copy.ToArray());
        Assert.False(stream.CanWrite);
        Assert.Equal(Body.Length, stream.Length);
    }

    [Fact]
    public void Dispose_DisposesTheOriginalContentOnceAndIsIdempotent()
    {
        var original = new TrackingContent([]);
        var content = new SignedRequestContent(original, Body);

        Assert.False(original.IsDisposed);
        content.Dispose();
        content.Dispose();

        Assert.True(original.IsDisposed);
    }

    [Fact]
    public async Task Dispose_ThenRead_ThrowsObjectDisposedException()
    {
        var content = new SignedRequestContent(new TrackingContent([]), Body);
        content.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));
    }
}
