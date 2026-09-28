using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Appouse.Safetalk;

/// <summary>
/// HMAC-SHA256 implementation of <see cref="IHmacSignatureService"/>.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>The HMAC key is the UTF-8 encoding of the shared secret.</description></item>
///   <item><description>The MAC is computed with the one-shot <see cref="HMACSHA256.HashData(ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte})"/> API (no per-call <see cref="HMAC"/> instances).</description></item>
///   <item><description>Signatures are emitted as lower-case hexadecimal (64 characters).</description></item>
///   <item><description>Verification decodes the received signature and compares raw MAC bytes with <see cref="CryptographicOperations.FixedTimeEquals"/>, preventing timing attacks.</description></item>
///   <item><description>Key material is kept on the stack (or in pooled memory for very long secrets) and zeroed after use.</description></item>
/// </list>
/// This type is stateless and thread-safe.
/// </remarks>
public sealed class HmacSha256SignatureService : IHmacSignatureService
{
    /// <summary>
    /// The size of an HMAC-SHA256 signature in bytes.
    /// </summary>
    public const int SignatureSizeInBytes = HMACSHA256.HashSizeInBytes;

    /// <summary>
    /// The length of a hexadecimal encoded HMAC-SHA256 signature.
    /// </summary>
    public const int SignatureHexLength = SignatureSizeInBytes * 2;

    private const int MaxStackallocKeySize = 256;

    /// <summary>
    /// Gets a shared instance of the service.
    /// </summary>
    public static HmacSha256SignatureService Instance { get; } = new();

    /// <inheritdoc />
    public string ComputeSignature(string secret, ReadOnlySpan<byte> canonicalRequest)
    {
        Span<byte> mac = stackalloc byte[SignatureSizeInBytes];
        ComputeMac(secret, canonicalRequest, mac);
        return HexEncoding.ToLowerHex(mac);
    }

    /// <inheritdoc />
    public bool VerifySignature(string secret, ReadOnlySpan<byte> canonicalRequest, ReadOnlySpan<char> signature)
    {
        Span<byte> provided = stackalloc byte[SignatureSizeInBytes];
        if (!HexEncoding.TryDecode(signature, provided))
        {
            // The expected length and alphabet are public knowledge; rejecting early leaks nothing secret.
            return false;
        }

        Span<byte> expected = stackalloc byte[SignatureSizeInBytes];
        ComputeMac(secret, canonicalRequest, expected);

        return CryptographicOperations.FixedTimeEquals(expected, provided);
    }

    private static void ComputeMac(string secret, ReadOnlySpan<byte> canonicalRequest, Span<byte> destination)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);

        int keySize = Encoding.UTF8.GetByteCount(secret);
        byte[]? rentedKey = null;
        Span<byte> key = keySize <= MaxStackallocKeySize
            ? stackalloc byte[MaxStackallocKeySize]
            : (rentedKey = ArrayPool<byte>.Shared.Rent(keySize));

        key = key[..Encoding.UTF8.GetBytes(secret, key)];
        try
        {
            HMACSHA256.HashData(key, canonicalRequest, destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (rentedKey is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedKey);
            }
        }
    }
}
