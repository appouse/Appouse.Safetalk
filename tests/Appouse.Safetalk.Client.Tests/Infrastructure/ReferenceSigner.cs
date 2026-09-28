using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// An independent implementation of the Safetalk signature scheme, written directly from the specification
/// (<c>HMAC-SHA256(UTF8(secret), UTF8("{METHOD}\n{PATH-AND-QUERY}\n{TIMESTAMP}\n") + body)</c>, lower-case hex).
/// It intentionally shares no code with the library.
/// </summary>
internal static class ReferenceSigner
{
    public static byte[] BuildCanonicalRequest(string method, string pathAndQuery, string timestamp, ReadOnlySpan<byte> body)
    {
        byte[] header = Encoding.UTF8.GetBytes(method + "\n" + pathAndQuery + "\n" + timestamp + "\n");
        byte[] canonicalRequest = new byte[header.Length + body.Length];
        header.CopyTo(canonicalRequest, 0);
        body.CopyTo(canonicalRequest.AsSpan(header.Length));
        return canonicalRequest;
    }

    /// <summary>
    /// Signs a request. <paramref name="method"/> is used verbatim (callers pass the upper-case form).
    /// </summary>
    public static string Sign(string secret, string method, string pathAndQuery, string timestamp, ReadOnlySpan<byte> body)
    {
        byte[] mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), BuildCanonicalRequest(method, pathAndQuery, timestamp, body));

        var hex = new StringBuilder(mac.Length * 2);
        foreach (byte value in mac)
        {
            hex.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }

        return hex.ToString();
    }

    /// <summary>
    /// Signs a captured request using the method, target, timestamp header and body bytes the transport received.
    /// </summary>
    public static string Sign(string secret, CapturedRequest request) =>
        Sign(secret, request.Method.ToUpperInvariant(), request.PathAndQuery, request.Timestamp, request.BodyOrEmpty);

    public static string UnixSeconds(DateTimeOffset instant) =>
        instant.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
}
