using System.Net;

namespace Appouse.Safetalk.Client;

/// <summary>
/// Replaces request content that cannot be serialized twice (streams, JSON, multipart, ...) with the exact bytes that
/// were signed. The original content is serialized once, straight into the canonical request buffer, instead of being
/// buffered by <see cref="HttpContent.LoadIntoBufferAsync()"/> and copied again.
/// </summary>
/// <remarks>
/// The original content keeps its owner semantics: it is disposed together with this instance (that is, when the
/// <see cref="HttpRequestMessage"/> is disposed), not earlier.
/// </remarks>
internal sealed class SignedRequestContent : HttpContent
{
    private const string ContentLengthHeader = "Content-Length";

    private readonly byte[] _body;
    private readonly HttpContent _original;

    public SignedRequestContent(HttpContent original, ReadOnlySpan<byte> body)
    {
        _original = original;
        _body = body.ToArray();

        foreach (KeyValuePair<string, IEnumerable<string>> header in original.Headers)
        {
            // Content-Length is computed from the signed bytes; a stale explicit value would corrupt framing.
            if (!string.Equals(header.Key, ContentLengthHeader, StringComparison.OrdinalIgnoreCase))
            {
                Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        => SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        => stream.WriteAsync(_body, cancellationToken).AsTask();

    protected override void SerializeToStream(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        => stream.Write(_body);

    protected override Task<Stream> CreateContentReadStreamAsync()
        => Task.FromResult<Stream>(new MemoryStream(_body, writable: false));

    protected override Stream CreateContentReadStream(CancellationToken cancellationToken)
        => new MemoryStream(_body, writable: false);

    protected override bool TryComputeLength(out long length)
    {
        length = _body.Length;
        return true;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _original.Dispose();
        }

        base.Dispose(disposing);
    }
}
