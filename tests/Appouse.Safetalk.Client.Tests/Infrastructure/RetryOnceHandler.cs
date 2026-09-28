namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Sends every request twice through the rest of the pipeline (a minimal retry policy), invoking a callback between
/// the attempts, and returns the second response.
/// </summary>
internal sealed class RetryOnceHandler(Action beforeRetry) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (await base.SendAsync(request, cancellationToken))
        {
        }

        beforeRetry();
        return await base.SendAsync(request, cancellationToken);
    }
}
