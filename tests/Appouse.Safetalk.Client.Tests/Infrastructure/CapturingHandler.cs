using System.Collections.Concurrent;
using System.Net;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// A terminal handler that stands in for the network transport. It serializes the request content through
/// <see cref="HttpContent.CopyToAsync(Stream, CancellationToken)"/> (as <c>SocketsHttpHandler</c> does) — or through
/// the synchronous <see cref="HttpContent.CopyTo(Stream, TransportContext?, CancellationToken)"/> for a synchronous
/// send — and records a snapshot of every request it receives.
/// </summary>
/// <remarks>
/// The handler deliberately does not observe the cancellation token before recording the invocation, so tests can
/// tell whether a component upstream forwarded a request that should never have reached the transport.
/// </remarks>
internal sealed class CapturingHandler : HttpMessageHandler
{
    private readonly ConcurrentQueue<CapturedRequest> _requests = new();
    private readonly ConcurrentQueue<HttpContent?> _contents = new();
    private int _invocationCount;
    private int _synchronousInvocationCount;

    public int InvocationCount => Volatile.Read(ref _invocationCount);

    /// <summary>
    /// Gets the number of requests that arrived through the synchronous <c>Send</c> path.
    /// </summary>
    public int SynchronousInvocationCount => Volatile.Read(ref _synchronousInvocationCount);

    public IReadOnlyList<CapturedRequest> Requests => [.. _requests];

    /// <summary>
    /// Gets the <see cref="HttpContent"/> instances (not copies) the transport received, in arrival order.
    /// </summary>
    public IReadOnlyList<HttpContent?> Contents => [.. _contents];

    public CapturedRequest SingleRequest => Assert.Single(_requests);

    public CapturedRequest LastRequest => Requests[^1];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _invocationCount);

        byte[]? body = null;
        if (request.Content is not null)
        {
            using var stream = new MemoryStream();
            await request.Content.CopyToAsync(stream, cancellationToken);
            body = stream.ToArray();
        }

        return Record(request, body);
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _invocationCount);
        Interlocked.Increment(ref _synchronousInvocationCount);

        byte[]? body = null;
        if (request.Content is not null)
        {
            using var stream = new MemoryStream();
            request.Content.CopyTo(stream, context: null, cancellationToken);
            body = stream.ToArray();
        }

        return Record(request, body);
    }

    private HttpResponseMessage Record(HttpRequestMessage request, byte[]? body)
    {
        _contents.Enqueue(request.Content);
        _requests.Enqueue(CapturedRequest.Create(request, body));
        return new HttpResponseMessage(HttpStatusCode.OK) { RequestMessage = request };
    }
}
