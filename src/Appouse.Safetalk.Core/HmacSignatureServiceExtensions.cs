using System.Buffers;

namespace Appouse.Safetalk;

/// <summary>
/// Convenience extensions that build the canonical request and sign or verify it in one call.
/// </summary>
/// <remarks>
/// Useful for transports other than <see cref="HttpClient"/> and for tests. The HTTP pipeline components use
/// <see cref="CanonicalRequestBuffer"/> directly so that the body is streamed into pooled memory.
/// </remarks>
public static class HmacSignatureServiceExtensions
{
    /// <summary>
    /// Builds the canonical request from its components and computes its signature.
    /// </summary>
    /// <param name="service">The signature service.</param>
    /// <param name="secret">The shared secret of the client.</param>
    /// <param name="method">The HTTP method, for example <c>POST</c>.</param>
    /// <param name="pathAndQuery">The request path and query string, for example <c>/api/orders?id=5</c>.</param>
    /// <param name="timestamp">The Unix timestamp (seconds) sent in the <c>X-Timestamp</c> header.</param>
    /// <param name="body">The raw request body bytes.</param>
    /// <returns>The lower-case hexadecimal signature.</returns>
    public static string ComputeSignature(
        this IHmacSignatureService service,
        string secret,
        string method,
        string pathAndQuery,
        string timestamp,
        ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(service);

        using CanonicalRequestBuffer canonicalRequest = CanonicalRequestBuffer.Create(method, pathAndQuery, timestamp, body.Length);
        canonicalRequest.Write(body);
        return service.ComputeSignature(secret, canonicalRequest.WrittenSpan);
    }

    /// <summary>
    /// Builds the canonical request from its components and verifies the signature in constant time.
    /// </summary>
    /// <param name="service">The signature service.</param>
    /// <param name="secret">The shared secret of the client.</param>
    /// <param name="method">The HTTP method, for example <c>POST</c>.</param>
    /// <param name="pathAndQuery">The request path and query string, for example <c>/api/orders?id=5</c>.</param>
    /// <param name="timestamp">The Unix timestamp (seconds) sent in the <c>X-Timestamp</c> header.</param>
    /// <param name="body">The raw request body bytes.</param>
    /// <param name="signature">The hexadecimal signature received with the request.</param>
    /// <returns><see langword="true"/> when the signature is valid; otherwise <see langword="false"/>.</returns>
    public static bool VerifySignature(
        this IHmacSignatureService service,
        string secret,
        string method,
        string pathAndQuery,
        string timestamp,
        ReadOnlySpan<byte> body,
        ReadOnlySpan<char> signature)
    {
        ArgumentNullException.ThrowIfNull(service);

        using CanonicalRequestBuffer canonicalRequest = CanonicalRequestBuffer.Create(method, pathAndQuery, timestamp, body.Length);
        canonicalRequest.Write(body);
        return service.VerifySignature(secret, canonicalRequest.WrittenSpan, signature);
    }
}
