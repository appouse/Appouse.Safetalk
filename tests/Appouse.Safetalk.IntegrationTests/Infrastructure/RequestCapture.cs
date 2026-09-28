using System.Collections.Concurrent;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Collects the signed requests observed by <see cref="RequestCaptureHandler"/>.
/// </summary>
internal sealed class RequestCapture
{
    private static readonly string[] SigningHeaderNames =
    [
        SafetalkHeaderNames.ClientId,
        SafetalkHeaderNames.Timestamp,
        SafetalkHeaderNames.Signature,
    ];

    private readonly ConcurrentQueue<CapturedRequest> _requests = new();

    public IReadOnlyCollection<CapturedRequest> Requests => _requests;

    public async Task AddAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new List<KeyValuePair<string, string>>();
        foreach (string name in SigningHeaderNames)
        {
            if (request.Headers.TryGetValues(name, out IEnumerable<string>? values))
            {
                headers.AddRange(values.Select(value => new KeyValuePair<string, string>(name, value)));
            }
        }

        ReadOnlyMemory<byte>? body = request.Content is null
            ? null
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);

        _requests.Enqueue(new CapturedRequest(
            request.Method,
            request.RequestUri!,
            headers,
            body,
            request.Content?.Headers.ContentType));
    }
}
