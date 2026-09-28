namespace Appouse.Safetalk.Server;

/// <summary>
/// Endpoint metadata that overrides <see cref="HmacServerOptions.EnforcementMode"/> for an endpoint.
/// </summary>
/// <remarks>
/// <para>
/// Attributes and other metadata take precedence over the <c>SkipHmacValidation()</c>/<c>RequireHmacValidation()</c>
/// conventions. Within each kind the most specific one wins: an action attribute over a controller attribute, and an
/// endpoint convention over a route-group convention. A broad convention such as <c>MapControllers().SkipHmacValidation()</c>
/// therefore never overrides an explicit <see cref="RequireHmacValidationAttribute"/>.
/// </para>
/// <para>
/// Metadata is only visible when <c>UseHmacAuthentication()</c> runs after routing; otherwise every request is validated.
/// </para>
/// </remarks>
public interface IHmacValidationMetadata
{
    /// <summary>
    /// Gets a value indicating whether requests to the endpoint must carry a valid HMAC signature.
    /// </summary>
    bool RequiresValidation { get; }
}
