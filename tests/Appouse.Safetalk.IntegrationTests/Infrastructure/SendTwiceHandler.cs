using System.Collections.Concurrent;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// A naive retry handler: it sends the same <see cref="HttpRequestMessage"/> twice and returns the second response.
/// Where it sits relative to the signing handler decides whether the retry is re-signed.
/// </summary>
internal sealed class SendTwiceHandler(ConcurrentQueue<SendAttempt> attempts, Action? beforeRetry = null) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (HttpResponseMessage first = await base.SendAsync(request, cancellationToken))
        {
            attempts.Enqueue(SendAttempt.From(request, first));
        }

        beforeRetry?.Invoke();

        HttpResponseMessage second = await base.SendAsync(request, cancellationToken);
        attempts.Enqueue(SendAttempt.From(request, second));
        return second;
    }
}
