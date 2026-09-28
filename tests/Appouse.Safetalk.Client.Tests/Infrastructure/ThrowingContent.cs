using System.Net;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Content whose serialization fails, like a source stream that breaks mid-read.
/// </summary>
internal sealed class ThrowingContent : HttpContent
{
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        throw new IOException("The content source failed.");

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}
