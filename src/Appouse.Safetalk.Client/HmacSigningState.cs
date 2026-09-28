namespace Appouse.Safetalk.Client;

/// <summary>
/// Signing state shared by every attempt of one logical request: the original message and any clone created from it.
/// It makes each signature of that request use a strictly increasing timestamp, so attempts never share a signature
/// and are never mistaken for replays by the server.
/// </summary>
/// <remarks>
/// The state lives in <see cref="HttpRequestMessage.Options"/>. Resilience handlers that clone the request per attempt
/// (for example the standard hedging handler) copy the options by reference, so clones share this instance.
/// </remarks>
internal sealed class HmacSigningState
{
    private static readonly HttpRequestOptionsKey<HmacSigningState> Key = new("Appouse.Safetalk.SigningState");

    private long _lastTimestamp;

    public static HmacSigningState GetOrAttach(HttpRequestMessage request)
    {
        if (!request.Options.TryGetValue(Key, out HmacSigningState? state))
        {
            state = new HmacSigningState();
            request.Options.Set(Key, state);
        }

        return state;
    }

    /// <summary>
    /// Atomically returns <c>max(now, last + 1)</c> and records it; safe for attempts signed concurrently.
    /// </summary>
    public long NextTimestamp(long now)
    {
        long last = Interlocked.Read(ref _lastTimestamp);
        while (true)
        {
            long next = Math.Max(now, last + 1);
            long observed = Interlocked.CompareExchange(ref _lastTimestamp, next, last);
            if (observed == last)
            {
                return next;
            }

            last = observed;
        }
    }
}

/// <summary>
/// Outermost handler added by the <c>IHttpClientFactory</c> integration. It attaches <see cref="HmacSigningState"/>
/// before retry or hedging handlers take their snapshot of the request, so that every attempt shares it.
/// </summary>
internal sealed class HmacSigningStateHandler : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        HmacSigningState.GetOrAttach(request);
        return base.SendAsync(request, cancellationToken);
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        HmacSigningState.GetOrAttach(request);
        return base.Send(request, cancellationToken);
    }
}
