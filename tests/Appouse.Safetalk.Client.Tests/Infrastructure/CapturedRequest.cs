using System.Net.Http.Headers;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// An immutable snapshot of a request exactly as a transport observed it: method, target, headers and the body bytes
/// produced by serializing the content the way a real transport does.
/// </summary>
internal sealed class CapturedRequest
{
    public const string ClientIdHeader = "X-Client-Id";
    public const string TimestampHeader = "X-Timestamp";
    public const string SignatureHeader = "X-Signature";

    private CapturedRequest(
        string method,
        Uri requestUri,
        Dictionary<string, string[]> headers,
        Dictionary<string, string[]> contentHeaders,
        byte[]? body,
        long? contentLength)
    {
        Method = method;
        RequestUri = requestUri;
        Headers = headers;
        ContentHeaders = contentHeaders;
        Body = body;
        ContentLength = contentLength;
    }

    public string Method { get; }

    public Uri RequestUri { get; }

    public string PathAndQuery => RequestUri.PathAndQuery;

    public IReadOnlyDictionary<string, string[]> Headers { get; }

    public IReadOnlyDictionary<string, string[]> ContentHeaders { get; }

    /// <summary>
    /// Gets the serialized body, or <see langword="null"/> when the request had no content.
    /// </summary>
    public byte[]? Body { get; }

    public byte[] BodyOrEmpty => Body ?? [];

    public long? ContentLength { get; }

    public string ClientId => GetSingleHeader(ClientIdHeader);

    public string Timestamp => GetSingleHeader(TimestampHeader);

    public string Signature => GetSingleHeader(SignatureHeader);

    public static CapturedRequest Create(HttpRequestMessage request, byte[]? body)
    {
        Assert.NotNull(request.RequestUri);

        return new CapturedRequest(
            request.Method.Method,
            request.RequestUri,
            Snapshot(request.Headers),
            request.Content is null ? new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) : Snapshot(request.Content.Headers),
            body,
            request.Content?.Headers.ContentLength);
    }

    public string GetSingleHeader(string name)
    {
        Assert.True(Headers.TryGetValue(name, out string[]? values), $"Header '{name}' was not sent.");
        return Assert.Single(values);
    }

    public bool HasHeader(string name) => Headers.ContainsKey(name);

    private static Dictionary<string, string[]> Snapshot(HttpHeaders headers)
    {
        var snapshot = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, HeaderStringValues> header in headers.NonValidated)
        {
            snapshot[header.Key] = [.. header.Value];
        }

        return snapshot;
    }
}
