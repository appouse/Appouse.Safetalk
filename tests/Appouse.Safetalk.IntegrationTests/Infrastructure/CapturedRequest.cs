using System.Net.Http.Headers;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// A snapshot of a signed request exactly as it left the signing handler, used to replay it verbatim.
/// </summary>
internal sealed class CapturedRequest(
    HttpMethod method,
    Uri requestUri,
    IReadOnlyList<KeyValuePair<string, string>> signingHeaders,
    ReadOnlyMemory<byte>? body,
    MediaTypeHeaderValue? contentType)
{
    public HttpMethod Method { get; } = method;

    public Uri RequestUri { get; } = requestUri;

    public IReadOnlyList<KeyValuePair<string, string>> SigningHeaders { get; } = signingHeaders;

    public ReadOnlyMemory<byte>? Body { get; } = body;

    public MediaTypeHeaderValue? ContentType { get; } = contentType;

    public string ClientId => GetHeader(SafetalkHeaderNames.ClientId);

    public string Timestamp => GetHeader(SafetalkHeaderNames.Timestamp);

    public string Signature => GetHeader(SafetalkHeaderNames.Signature);

    /// <summary>
    /// Builds a byte-identical copy of the signed request.
    /// </summary>
    public HttpRequestMessage ToRequestMessage()
    {
        var request = new HttpRequestMessage(Method, RequestUri);
        foreach ((string name, string value) in SigningHeaders)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        if (Body is { } body)
        {
            request.Content = new ReadOnlyMemoryContent(body);
            request.Content.Headers.ContentType = ContentType;
        }

        return request;
    }

    private string GetHeader(string name)
        => SigningHeaders.Single(header => string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase)).Value;
}
