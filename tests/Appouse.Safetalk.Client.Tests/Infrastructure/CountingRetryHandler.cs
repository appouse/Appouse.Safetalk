namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// A retry policy that sends the same <see cref="HttpRequestMessage"/> through the rest of the pipeline a fixed number
/// of times (synchronously or asynchronously), counting the attempts, and returns the last response.
/// </summary>
internal sealed class CountingRetryHandler(int attempts, Action<int>? beforeAttempt = null) : DelegatingHandler
{
    private int _attemptCount;

    public int AttemptCount => Volatile.Read(ref _attemptCount);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            Interlocked.Increment(ref _attemptCount);
            beforeAttempt?.Invoke(attempt);
            HttpResponseMessage response = await base.SendAsync(request, cancellationToken);
            if (attempt >= attempts)
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
            Interlocked.Increment(ref _attemptCount);
            beforeAttempt?.Invoke(attempt);
            HttpResponseMessage response = base.Send(request, cancellationToken);
            if (attempt >= attempts)
            {
                return response;
            }

            response.Dispose();
        }
    }
}
