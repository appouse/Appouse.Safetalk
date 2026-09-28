namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Rewrites every request that passes through it: appends a query-string parameter and, when
/// <paramref name="newBody"/> is given, replaces the body. Placed outside the signing handler, the signature must cover
/// the rewritten request; placed inside it (around the transport), the rewrite is a tampering attempt.
/// </summary>
internal sealed class RequestMutatingHandler(string queryParameter, string? newBody = null) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Mutate(request);
        return base.SendAsync(request, cancellationToken);
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Mutate(request);
        return base.Send(request, cancellationToken);
    }

    private void Mutate(HttpRequestMessage request)
    {
        Assert.NotNull(request.RequestUri);
        var builder = new UriBuilder(request.RequestUri);
        builder.Query = builder.Query.Length > 1 ? builder.Query[1..] + "&" + queryParameter : queryParameter;
        request.RequestUri = builder.Uri;

        if (newBody is not null)
        {
            request.Content = new StringContent(newBody);
        }
    }
}
