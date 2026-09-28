namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Emulates the hedging handler of <c>Microsoft.Extensions.Http.Resilience</c> (<c>AddStandardHedgingHandler()</c>):
/// every attempt is a fresh <see cref="HttpRequestMessage"/> cloned from a snapshot of the original (method, URI,
/// version, headers and options copied; the content instance shared), never the original message itself. Attempts are
/// sent one after another here so the outcome is deterministic.
/// </summary>
internal sealed class CloningHedgingHandler(int attempts) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            HttpRequestMessage clone = Clone(request);
            HttpResponseMessage response = await base.SendAsync(clone, cancellationToken);
            if (attempt >= attempts)
            {
                return response;
            }

            response.Dispose();
        }
    }

    /// <summary>
    /// Creates one attempt the way the standard hedging handler does: a new message sharing the content instance and
    /// the option values (by reference) of <paramref name="request"/>.
    /// </summary>
    public static HttpRequestMessage Clone(HttpRequestMessage request)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Content = request.Content,
            Version = request.Version,
            VersionPolicy = request.VersionPolicy,
        };

        foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        foreach (KeyValuePair<string, object?> option in request.Options)
        {
            ((IDictionary<string, object?>)clone.Options).Add(option.Key, option.Value);
        }

        return clone;
    }
}
