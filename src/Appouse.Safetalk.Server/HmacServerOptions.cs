using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server;

/// <summary>
/// Options that control how signed requests are verified.
/// </summary>
public sealed class HmacServerOptions
{
    /// <summary>
    /// The default <see cref="AllowedClockSkew"/>: five minutes.
    /// </summary>
    public static readonly TimeSpan DefaultAllowedClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The maximum value accepted for <see cref="AllowedClockSkew"/>: one day.
    /// </summary>
    public static readonly TimeSpan MaxAllowedClockSkew = TimeSpan.FromDays(1);

    /// <summary>
    /// The default <see cref="MaxBodySize"/>: 4 MiB.
    /// </summary>
    public const int DefaultMaxBodySize = 4 * 1024 * 1024;

    /// <summary>
    /// Gets or sets how far the <c>X-Timestamp</c> value may deviate from the server clock, in either direction.
    /// Requests outside this window are rejected with <c>401 Unauthorized</c>. Defaults to five minutes.
    /// </summary>
    /// <remarks>
    /// While <see cref="EnableReplayProtection"/> is on, a configuration reload can narrow the window immediately, but a
    /// wider window than the one in effect when the first request was validated only applies after a restart (a warning
    /// is logged): replay entries recorded under the narrower window cannot be extended, so widening it at runtime
    /// would let earlier requests be replayed.
    /// </remarks>
    public TimeSpan AllowedClockSkew { get; set; } = DefaultAllowedClockSkew;

    /// <summary>
    /// Gets or sets the maximum request body size, in bytes, that is buffered (in memory) for signature verification.
    /// Requests declaring a larger <c>Content-Length</c> are rejected with <c>413 Payload Too Large</c> before any
    /// secret lookup or buffering; chunked bodies are cut off as soon as they exceed the limit. Defaults to 4 MiB.
    /// </summary>
    /// <remarks>
    /// The body is read before the signature can be checked, and verifying a body of <c>N</c> bytes costs roughly
    /// <c>2N</c> of transient allocations (the rewind buffer) plus a pooled canonical buffer rounded up to a power of
    /// two. Set the limit to what partners actually send, and combine it with Kestrel limits and rate limiting.
    /// </remarks>
    public int MaxBodySize { get; set; } = DefaultMaxBodySize;

    /// <summary>
    /// Gets or sets which requests the middleware validates. Defaults to <see cref="HmacEnforcementMode.AllRequests"/>.
    /// </summary>
    public HmacEnforcementMode EnforcementMode { get; set; } = HmacEnforcementMode.AllRequests;

    /// <summary>
    /// Gets or sets a value indicating whether signatures of accepted requests are remembered through
    /// <see cref="IHmacReplayCache"/> so that identical requests cannot be replayed within the clock skew window.
    /// Defaults to <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// When enabled, two byte-identical requests sent by the same client within the same second have the same
    /// signature and the second one is rejected. Clients that legitimately send such requests should make them
    /// distinguishable (for example with a request id in the query string or body). The Appouse.Safetalk client
    /// re-signs retried requests with a strictly increasing timestamp, so its retries are never mistaken for replays.
    /// </remarks>
    public bool EnableReplayProtection { get; set; }

    /// <summary>
    /// Gets or sets a delegate that returns the path and query string used in the canonical request.
    /// </summary>
    /// <remarks>
    /// By default the raw origin-form request target received on the wire is used (for example
    /// <c>/api/orders?id=5</c>), which matches <see cref="Uri.PathAndQuery"/> on the client and is immune to URL
    /// rewriting and path-base handling inside the application. Override it when a reverse proxy rewrites the path
    /// before forwarding the request, for example to restore a stripped prefix. The delegate must return an
    /// origin-form target and should be derived from the raw target, not from the decoded <c>HttpRequest.Path</c>.
    /// </remarks>
    public Func<HttpContext, string>? RequestTargetResolver { get; set; }
}
