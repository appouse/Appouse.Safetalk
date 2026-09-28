using System.Globalization;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// Shared client credentials, a fixed clock origin and a signing helper that mirrors what a client does.
/// </summary>
internal static class TestCredentials
{
    public const string ClientId = "partner-a";
    public const string Secret = "partner-a-shared-secret-3f9c1e7d";
    public const string OtherClientId = "partner-b";
    public const string OtherSecret = "partner-b-shared-secret-8a2b4c6e";

    /// <summary>
    /// A whole-second instant, so that clock skew boundaries are exact.
    /// </summary>
    public static readonly DateTimeOffset Now = new(2026, 3, 14, 15, 9, 26, TimeSpan.Zero);

    public static IReadOnlyDictionary<string, string> Secrets { get; } = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [ClientId] = Secret,
        [OtherClientId] = OtherSecret,
    };

    public static InMemoryHmacSecretProvider CreateSecretProvider() => new(Secrets);

    public static string FormatTimestamp(long unixSeconds) => unixSeconds.ToString(CultureInfo.InvariantCulture);

    public static string Sign(string method, string pathAndQuery, string timestamp, ReadOnlySpan<byte> body, string secret = Secret) =>
        HmacSha256SignatureService.Instance.ComputeSignature(secret, method, pathAndQuery, timestamp, body);
}
