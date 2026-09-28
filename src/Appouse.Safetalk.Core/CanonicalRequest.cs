namespace Appouse.Safetalk;

/// <summary>
/// Describes the canonical request format that is signed by clients and verified by servers.
/// </summary>
/// <remarks>
/// <para>The canonical request is the UTF-8 encoding of:</para>
/// <code>{HTTP-METHOD}\n{PATH-AND-QUERY}\n{UNIX-TIMESTAMP}\n{BODY}</code>
/// <list type="bullet">
///   <item><description><c>HTTP-METHOD</c> is upper-cased (for example <c>POST</c>).</description></item>
///   <item><description><c>PATH-AND-QUERY</c> is the request target exactly as sent on the wire, for example <c>/api/orders?id=5</c>.</description></item>
///   <item><description><c>UNIX-TIMESTAMP</c> is the value of the <c>X-Timestamp</c> header (seconds since epoch).</description></item>
///   <item><description><c>BODY</c> is the raw request body bytes (empty when the request has no body).</description></item>
/// </list>
/// <para>
/// Use <see cref="CanonicalRequestBuffer"/> for the allocation-free production code path. <see cref="Format"/> is a
/// readable reference implementation intended for diagnostics, documentation and partner integrations.
/// </para>
/// </remarks>
public static class CanonicalRequest
{
    /// <summary>
    /// The separator placed between the components of the canonical request.
    /// </summary>
    public const char Separator = '\n';

    /// <summary>
    /// Builds the canonical request string for a textual body.
    /// </summary>
    /// <param name="method">The HTTP method, for example <c>POST</c>. It is upper-cased.</param>
    /// <param name="pathAndQuery">The request path and query string, for example <c>/api/orders?id=5</c>.</param>
    /// <param name="timestamp">The Unix timestamp (seconds) sent in the <c>X-Timestamp</c> header.</param>
    /// <param name="body">The request body, or <see langword="null"/> when the request has no body.</param>
    /// <returns>The canonical request string.</returns>
    public static string Format(string method, string pathAndQuery, string timestamp, string? body)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentException.ThrowIfNullOrEmpty(pathAndQuery);
        ArgumentException.ThrowIfNullOrEmpty(timestamp);

        return $"{method.ToUpperInvariant()}{Separator}{pathAndQuery}{Separator}{timestamp}{Separator}{body}";
    }
}
