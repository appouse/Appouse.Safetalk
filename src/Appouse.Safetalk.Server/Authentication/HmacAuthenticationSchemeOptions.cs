using Microsoft.AspNetCore.Authentication;

namespace Appouse.Safetalk.Server.Authentication;

/// <summary>
/// Options of the HMAC authentication scheme registered with <c>AddAuthentication().AddHmac()</c>.
/// Validation itself is configured through <see cref="HmacServerOptions"/>.
/// </summary>
public sealed class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
}
