namespace Appouse.Safetalk;

/// <summary>
/// Names of the HTTP headers that carry the HMAC authentication data.
/// </summary>
public static class SafetalkHeaderNames
{
    /// <summary>
    /// Header carrying the lower-case hexadecimal HMAC-SHA256 signature of the canonical request.
    /// </summary>
    public const string Signature = "X-Signature";

    /// <summary>
    /// Header carrying the Unix time (seconds since epoch, UTC) at which the request was signed.
    /// </summary>
    public const string Timestamp = "X-Timestamp";

    /// <summary>
    /// Header carrying the identifier of the calling client, used by the server to look up the shared secret.
    /// </summary>
    public const string ClientId = "X-Client-Id";

    /// <summary>
    /// The maximum length of an <see cref="ClientId"/> value. Client identifiers consist of printable ASCII
    /// characters; longer or other values are rejected before the secret store is queried.
    /// </summary>
    public const int MaxClientIdLength = 256;
}
