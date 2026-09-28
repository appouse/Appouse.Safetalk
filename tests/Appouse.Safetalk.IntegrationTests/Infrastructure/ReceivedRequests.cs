using System.Collections.Concurrent;
using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Records, on the server, the signing headers of the requests that reached an endpoint (i.e. passed validation).
/// </summary>
internal sealed class ReceivedRequests
{
    private readonly ConcurrentQueue<(string Timestamp, string Signature)> _requests = new();
    private int _count;

    public int Count => Volatile.Read(ref _count);

    public IEnumerable<string> Signatures => _requests.Select(request => request.Signature);

    public IEnumerable<string> Timestamps => _requests.Select(request => request.Timestamp);

    /// <summary>Records the request and returns its 1-based arrival number.</summary>
    public int Add(HttpContext context)
    {
        IHeaderDictionary headers = context.Request.Headers;
        _requests.Enqueue((headers[SafetalkHeaderNames.Timestamp].ToString(), headers[SafetalkHeaderNames.Signature].ToString()));
        return Interlocked.Increment(ref _count);
    }
}
