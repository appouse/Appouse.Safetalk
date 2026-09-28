using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Appouse.Safetalk.Core.Tests.Infrastructure;

/// <summary>
/// An HMAC-SHA256 oracle that is independent of the library under test: it uses the instance-based
/// <see cref="HMACSHA256"/> API (not the one-shot <c>HashData</c> used by the library) and its own hex encoder.
/// </summary>
internal static class ReferenceHmac
{
    public static string Compute(string secret, ReadOnlySpan<byte> message) =>
        Compute(Encoding.UTF8.GetBytes(secret), message);

    public static string Compute(byte[] key, ReadOnlySpan<byte> message)
    {
        using var hmac = new HMACSHA256(key);
        byte[] mac = hmac.ComputeHash(message.ToArray());
        return ToLowerHex(mac);
    }

    public static byte[] ComputeBytes(string secret, ReadOnlySpan<byte> message)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return hmac.ComputeHash(message.ToArray());
    }

    public static string ToLowerHex(ReadOnlySpan<byte> bytes)
    {
        var builder = new StringBuilder(bytes.Length * 2);
        foreach (byte value in bytes)
        {
            builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }
}
