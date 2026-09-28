namespace Appouse.Safetalk.Client;

/// <summary>
/// Settings used to sign outgoing requests with <see cref="HmacSigningHandler"/>.
/// </summary>
/// <remarks>
/// Options are resolved through <c>IOptionsMonitor&lt;HmacClientOptions&gt;</c> on every request. When they are
/// registered from configuration (<c>AddHmacClient&lt;TClient&gt;(IConfiguration)</c> or
/// <c>AddHmacSigning(IConfiguration)</c>), a reload of the section — for example a secret rotated in Azure Key Vault —
/// is applied to the next request without a restart. Options configured with a delegate are evaluated once.
/// </remarks>
public sealed class HmacClientOptions
{
    /// <summary>
    /// Gets or sets the client identifier sent in the <c>X-Client-Id</c> header. It must consist of at most
    /// <see cref="SafetalkHeaderNames.MaxClientIdLength"/> printable ASCII characters (0x20-0x7E) without leading or
    /// trailing whitespace.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the shared secret used as the HMAC-SHA256 key (UTF-8 encoded).
    /// Use at least 32 bytes of cryptographically random data, for example a Base64 encoded random value.
    /// </summary>
    public string Secret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the base address applied to the <see cref="HttpClient"/> when the client is registered through
    /// <c>AddHmacClient</c>/<c>AddHmacSigning</c> and no base address is configured on the client itself: any
    /// <c>ConfigureHttpClient</c> that sets one — including one inside <c>ConfigureHttpClientDefaults</c> — takes
    /// precedence. Optional; when set it must be an absolute http or https URI.
    /// A <see cref="HmacSigningHandler"/> constructed manually validates but ignores it.
    /// </summary>
    public Uri? BaseAddress { get; set; }
}
