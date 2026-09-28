using System.Globalization;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Signs hand-crafted requests (sent over raw sockets) with the public Core API, independent of the client handler.
/// </summary>
internal static class ManualSigner
{
    public static KeyValuePair<string, string>[] CreateHeaders(
        string method,
        string pathAndQuery,
        ReadOnlySpan<byte> body,
        string clientId = TestCredentials.ClientId,
        string secret = TestCredentials.Secret)
    {
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        string signature = HmacSha256SignatureService.Instance.ComputeSignature(secret, method, pathAndQuery, timestamp, body);

        return
        [
            new(SafetalkHeaderNames.ClientId, clientId),
            new(SafetalkHeaderNames.Timestamp, timestamp),
            new(SafetalkHeaderNames.Signature, signature),
        ];
    }
}
