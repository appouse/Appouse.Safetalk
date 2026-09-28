using System.Net;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Placed after the signing handler, it records each signed request as it goes to the network.
/// </summary>
/// <param name="capture">Receives the captured requests.</param>
/// <param name="forward">
/// <see langword="false"/> to capture the signed request without sending it (the caller receives <c>202 Accepted</c>),
/// which yields a pristine, never-used signed request for replay tests.
/// </param>
internal sealed class RequestCaptureHandler(RequestCapture capture, bool forward = true) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await capture.AddAsync(request, cancellationToken);

        return forward
            ? await base.SendAsync(request, cancellationToken)
            : new HttpResponseMessage(HttpStatusCode.Accepted) { RequestMessage = request };
    }
}
