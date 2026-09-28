using System.Globalization;
using System.Net;
using System.Text;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Content that produces different bytes every time it is serialized (for example a payload that embeds a nonce).
/// Signing it by serializing twice would send bytes that differ from the signed ones.
/// </summary>
internal sealed class ChangingContent : HttpContent
{
    private int _serializationCount;

    public int SerializationCount => Volatile.Read(ref _serializationCount);

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        int serialization = Interlocked.Increment(ref _serializationCount);
        byte[] payload = Encoding.UTF8.GetBytes("{\"serialization\":" + serialization.ToString(CultureInfo.InvariantCulture) + "}");
        await stream.WriteAsync(payload.AsMemory(), cancellationToken);
    }

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}
