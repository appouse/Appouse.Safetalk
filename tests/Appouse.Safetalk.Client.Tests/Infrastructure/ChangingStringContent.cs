using System.Globalization;
using System.Net;
using System.Text;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// A <see cref="StringContent"/> subclass with custom, non-repeatable serialization. The handler must not treat it
/// like a plain <see cref="StringContent"/> (whose serialization is repeatable).
/// </summary>
internal sealed class ChangingStringContent() : StringContent("ignored")
{
    private int _serializationCount;

    public int SerializationCount => Volatile.Read(ref _serializationCount);

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        int serialization = Interlocked.Increment(ref _serializationCount);
        byte[] payload = Encoding.UTF8.GetBytes("attempt-" + serialization.ToString(CultureInfo.InvariantCulture));
        await stream.WriteAsync(payload.AsMemory(), cancellationToken);
    }

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}
