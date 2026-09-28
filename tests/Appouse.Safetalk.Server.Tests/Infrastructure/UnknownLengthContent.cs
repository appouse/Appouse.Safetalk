using System.Net;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// HTTP content whose length is not known up front, so it is sent without a <c>Content-Length</c> header
/// (chunked transfer).
/// </summary>
internal sealed class UnknownLengthContent(byte[] content) : HttpContent
{
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        stream.WriteAsync(content).AsTask();

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken) =>
        stream.WriteAsync(content, cancellationToken).AsTask();

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}
