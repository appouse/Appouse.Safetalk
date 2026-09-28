namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Placed after the signing handler, it simulates a man-in-the-middle that alters the signed request in transit.
/// </summary>
internal sealed class RequestMutatingHandler(Func<HttpRequestMessage, CancellationToken, Task> mutateAsync) : DelegatingHandler
{
    public RequestMutatingHandler(Action<HttpRequestMessage> mutate)
        : this((request, _) =>
        {
            mutate(request);
            return Task.CompletedTask;
        })
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await mutateAsync(request, cancellationToken);
        return await base.SendAsync(request, cancellationToken);
    }
}
