using System.Collections.Concurrent;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Records whether the request already carried an <c>X-Signature</c> header when it reached this handler, which
/// reveals the handler's position relative to the signing handler.
/// </summary>
internal sealed class HeaderProbeHandler(ConcurrentQueue<bool> observations) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        observations.Enqueue(request.Headers.Contains(CapturedRequest.SignatureHeader));
        return base.SendAsync(request, cancellationToken);
    }
}
