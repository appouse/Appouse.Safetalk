using System.Collections.Concurrent;
using System.Net;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// A minimal retry handler (stand-in for Polly / <c>AddStandardResilienceHandler()</c>): it re-sends the same
/// <see cref="HttpRequestMessage"/> while the response has <paramref name="retryStatus"/>, up to
/// <paramref name="maxAttempts"/> attempts, recording each attempt. Supports asynchronous and synchronous sends.
/// </summary>
internal sealed class RetryOnStatusHandler(
    ConcurrentQueue<SendAttempt> attempts,
    HttpStatusCode retryStatus = HttpStatusCode.ServiceUnavailable,
    int maxAttempts = 3) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            HttpResponseMessage response = await base.SendAsync(request, cancellationToken);
            attempts.Enqueue(SendAttempt.From(request, response));
            if (response.StatusCode != retryStatus || attempt == maxAttempts)
            {
                return response;
            }

            response.Dispose();
        }
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            HttpResponseMessage response = base.Send(request, cancellationToken);
            attempts.Enqueue(SendAttempt.From(request, response));
            if (response.StatusCode != retryStatus || attempt == maxAttempts)
            {
                return response;
            }

            response.Dispose();
        }
    }
}
