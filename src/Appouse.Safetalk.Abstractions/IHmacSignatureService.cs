namespace Appouse.Safetalk;

/// <summary>
/// Computes and verifies request signatures over canonical request bytes.
/// </summary>
/// <remarks>
/// The default implementation is <c>HmacSha256SignatureService</c> (Appouse.Safetalk.Core). Both the client and the server must use
/// the same implementation (and therefore the same key derivation and output encoding).
/// </remarks>
public interface IHmacSignatureService
{
    /// <summary>
    /// Computes the signature of a canonical request.
    /// </summary>
    /// <param name="secret">The shared secret of the client.</param>
    /// <param name="canonicalRequest">The UTF-8 encoded canonical request.</param>
    /// <returns>The signature, encoded as lower-case hexadecimal.</returns>
    string ComputeSignature(string secret, ReadOnlySpan<byte> canonicalRequest);

    /// <summary>
    /// Verifies a signature against a canonical request using a constant-time comparison.
    /// </summary>
    /// <param name="secret">The shared secret of the client.</param>
    /// <param name="canonicalRequest">The UTF-8 encoded canonical request.</param>
    /// <param name="signature">The hexadecimal signature received with the request.</param>
    /// <returns><see langword="true"/> when the signature is valid; otherwise <see langword="false"/>.</returns>
    bool VerifySignature(string secret, ReadOnlySpan<byte> canonicalRequest, ReadOnlySpan<char> signature);
}
