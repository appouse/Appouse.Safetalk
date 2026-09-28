using Appouse.Safetalk.Server;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Endpoint conventions that control HMAC validation per endpoint or route group.
/// </summary>
public static class HmacEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Exempts the endpoint(s) from HMAC signature validation, for example health checks.
    /// </summary>
    /// <remarks>
    /// <see cref="SkipHmacValidationAttribute"/> and <see cref="RequireHmacValidationAttribute"/> on a controller, action
    /// or handler take precedence over this convention.
    /// </remarks>
    /// <typeparam name="TBuilder">The endpoint convention builder type.</typeparam>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static TBuilder SkipHmacValidation<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.WithMetadata(HmacValidationConventionMetadata.Skip);
    }

    /// <summary>
    /// Requires a valid HMAC signature for the endpoint(s). Needed when
    /// <see cref="HmacServerOptions.EnforcementMode"/> is <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="SkipHmacValidationAttribute"/> and <see cref="RequireHmacValidationAttribute"/> on a controller, action
    /// or handler take precedence over this convention.
    /// </remarks>
    /// <typeparam name="TBuilder">The endpoint convention builder type.</typeparam>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    /// <example>
    /// <code>
    /// app.MapGroup("/api/b2b").RequireHmacValidation();
    /// </code>
    /// </example>
    public static TBuilder RequireHmacValidation<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.WithMetadata(HmacValidationConventionMetadata.Require);
    }
}
