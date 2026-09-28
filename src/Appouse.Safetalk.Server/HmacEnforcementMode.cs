namespace Appouse.Safetalk.Server;

/// <summary>
/// Determines which requests <see cref="HmacAuthenticationMiddleware"/> validates.
/// </summary>
public enum HmacEnforcementMode
{
    /// <summary>
    /// Every request that reaches the middleware must be signed, except endpoints marked with
    /// <see cref="SkipHmacValidationAttribute"/> or <c>.SkipHmacValidation()</c>. This is the default.
    /// </summary>
    AllRequests = 0,

    /// <summary>
    /// Only endpoints marked with <see cref="RequireHmacValidationAttribute"/> or <c>.RequireHmacValidation()</c> must
    /// be signed; every other request passes through. Useful when public and partner (B2B) endpoints share one
    /// application. Requires <c>UseHmacAuthentication()</c> after routing; when routing is registered after it, every
    /// request is validated instead (fail closed).
    /// </summary>
    MarkedEndpointsOnly = 1,
}
