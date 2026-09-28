namespace Appouse.Safetalk.Server;

/// <summary>
/// Requires a valid HMAC signature for a controller, action or endpoint when
/// <see cref="HmacServerOptions.EnforcementMode"/> is <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/>.
/// </summary>
/// <remarks>
/// In <see cref="HmacEnforcementMode.AllRequests"/> mode every endpoint is already protected, so the attribute only
/// re-enables validation below a broader skip: a controller-level <see cref="SkipHmacValidationAttribute"/> or a
/// <c>SkipHmacValidation()</c> convention (attributes take precedence over conventions). For minimal APIs and route
/// groups use the <c>RequireHmacValidation()</c> endpoint convention.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class RequireHmacValidationAttribute : Attribute, IHmacValidationMetadata
{
    /// <inheritdoc />
    public bool RequiresValidation => true;
}
