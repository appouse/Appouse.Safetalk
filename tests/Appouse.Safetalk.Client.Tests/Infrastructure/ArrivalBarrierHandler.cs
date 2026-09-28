namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Wraps the transport (<see cref="CapturingHandler"/>): every request is recorded by the inner handler as soon as it
/// arrives, but no response is released until <c>expectedArrivals</c> requests are in flight at the same time. It
/// proves that attempts (for example parallel hedging) really were signed concurrently.
/// </summary>
internal sealed class ArrivalBarrierHandler(int expectedArrivals, TimeSpan timeout) : DelegatingHandler
{
    private readonly TaskCompletionSource _allArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _arrivals;

    public int Arrivals => Volatile.Read(ref _arrivals);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        HttpResponseMessage response = await base.SendAsync(request, cancellationToken);
        if (Interlocked.Increment(ref _arrivals) >= expectedArrivals)
        {
            _allArrived.TrySetResult();
        }

        try
        {
            await _allArrived.Task.WaitAsync(timeout, cancellationToken);
        }
        catch
        {
            response.Dispose();
            throw;
        }

        return response;
    }
}
