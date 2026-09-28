using Appouse.Safetalk.Server;
using Appouse.Safetalk.Server.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers HMAC as an ASP.NET Core authentication scheme.
/// </summary>
public static class HmacAuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds the HMAC authentication scheme (<see cref="HmacAuthenticationDefaults.AuthenticationScheme"/>), so that
    /// <c>[Authorize]</c>, <c>RequireAuthorization()</c> and authorization policies work with signed requests and
    /// produce proper <c>401</c>/<c>403</c> responses.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    /// <remarks>
    /// Secrets are still resolved through the services registered by <c>AddHmacServer()</c>
    /// (for example <c>AddHmacServer().AddSecretProvider&lt;T&gt;()</c>).
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Services.AddHmacServer().AddSecretProvider&lt;DatabaseSecretProvider&gt;();
    /// builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
    /// builder.Services.AddAuthorization(o => o.AddPolicy("PartnerA", p => p.RequireClaim("client_id", "partner-a")));
    /// </code>
    /// </example>
    public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder)
        => builder.AddHmac(HmacAuthenticationDefaults.AuthenticationScheme, configureOptions: null);

    /// <summary>
    /// Adds the HMAC authentication scheme with a custom name.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="authenticationScheme">The scheme name.</param>
    /// <param name="configureOptions">Configures the scheme options.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static AuthenticationBuilder AddHmac(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<HmacAuthenticationSchemeOptions>? configureOptions)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(authenticationScheme);

        builder.Services.AddHmacServer();
        return builder.AddScheme<HmacAuthenticationSchemeOptions, HmacAuthenticationHandler>(
            authenticationScheme,
            HmacAuthenticationDefaults.ChallengeScheme,
            configureOptions);
    }
}
