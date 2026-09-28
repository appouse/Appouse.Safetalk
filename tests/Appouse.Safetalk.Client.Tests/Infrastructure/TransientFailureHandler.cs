using System.Net;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Wraps the transport (<see cref="CapturingHandler"/>): every request is recorded by the inner handler, and the first
/// <c>failures</c> responses are turned into a transient failure (503 by default) so that resilience handlers retry or
/// hedge the request.
/// </summary>
internal sealed class TransientFailureHandler(int failures, HttpStatusCode status = HttpStatusCode.ServiceUnavailable) : DelegatingHandler
{
    private int _responseCount;

    public int ResponseCount => Volatile.Read(ref _responseCount);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Shape(await base.SendAsync(request, cancellationToken));

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        => Shape(base.Send(request, cancellationToken));

    private HttpResponseMessage Shape(HttpResponseMessage response)
    {
        if (Interlocked.Increment(ref _responseCount) <= failures)
        {
            response.StatusCode = status;
        }

        return response;
    }
}
