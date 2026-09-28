using System.Net;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// The outcome and signing headers of one attempt made by <see cref="SendTwiceHandler"/>.
/// </summary>
internal sealed record SendAttempt(HttpStatusCode StatusCode, IReadOnlyList<string> Timestamps, IReadOnlyList<string> Signatures)
{
    public static SendAttempt From(HttpRequestMessage request, HttpResponseMessage response)
        => new(response.StatusCode, GetValues(request, SafetalkHeaderNames.Timestamp), GetValues(request, SafetalkHeaderNames.Signature));

    private static string[] GetValues(HttpRequestMessage request, string name)
        => request.Headers.TryGetValues(name, out IEnumerable<string>? values) ? values.ToArray() : [];
}
