namespace Appouse.Safetalk.Server;

/// <summary>
/// Constants used when an HMAC authenticated client is attached to the request.
/// </summary>
public static class HmacAuthenticationDefaults
{
    /// <summary>
    /// The default name of the ASP.NET Core authentication scheme registered by <c>AddAuthentication().AddHmac()</c>.
    /// </summary>
    public const string AuthenticationScheme = "HMAC";

    /// <summary>
    /// The authentication type of the <see cref="System.Security.Claims.ClaimsIdentity"/> created for authenticated clients.
    /// </summary>
    public const string AuthenticationType = "HMAC";

    /// <summary>
    /// The scheme advertised in the <c>WWW-Authenticate</c> header of <c>401 Unauthorized</c> responses.
    /// </summary>
    public const string ChallengeScheme = "HMAC-SHA256";

    /// <summary>
    /// The claim type that carries the authenticated client identifier.
    /// </summary>
    public const string ClientIdClaimType = "client_id";
}
