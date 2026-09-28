using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server.Authentication;

/// <summary>
/// ASP.NET Core authentication handler for HMAC signed requests, for applications that protect endpoints with
/// <c>[Authorize]</c>, <c>RequireAuthorization()</c> or authorization policies instead of (or in addition to)
/// <see cref="HmacAuthenticationMiddleware"/>.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>Requests without any HMAC header produce no result, so anonymous endpoints and other schemes keep working.</description></item>
///   <item><description>Signed requests are verified with <see cref="IHmacRequestValidator"/>. The default validator verifies a request once, so combining this scheme with the middleware never validates a request twice, whether it succeeds or fails.</description></item>
///   <item><description>Challenges return <c>401</c> with <c>WWW-Authenticate: HMAC-SHA256</c>; forbidden requests return <c>403</c>.</description></item>
/// </list>
/// </remarks>
public sealed class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationSchemeOptions>
{
    /// <summary>
    /// Initializes a new instance of the handler.
    /// </summary>
    /// <param name="options">The scheme options.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    public HmacAuthenticationHandler(
        IOptionsMonitor<HmacAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? clientId = HmacClientIdentity.GetVerifiedClientId(Context);
        if (clientId is null)
        {
            if (!HasHmacHeaders(Request.Headers))
            {
                return AuthenticateResult.NoResult();
            }

            IHmacRequestValidator validator = Context.RequestServices.GetRequiredService<IHmacRequestValidator>();
            HmacValidationResult result = await validator.ValidateAsync(Context, Context.RequestAborted).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return AuthenticateResult.Fail($"HMAC validation failed: {result.Failure}.");
            }

            clientId = result.ClientId;
            HmacClientIdentity.SetFeature(Context, clientId);
        }

        var principal = new ClaimsPrincipal(HmacClientIdentity.Create(clientId));
        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    /// <inheritdoc />
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = HmacAuthenticationDefaults.ChallengeScheme;
        return Task.CompletedTask;
    }

    private static bool HasHmacHeaders(IHeaderDictionary headers)
        => headers.ContainsKey(SafetalkHeaderNames.Signature)
            || headers.ContainsKey(SafetalkHeaderNames.ClientId)
            || headers.ContainsKey(SafetalkHeaderNames.Timestamp);
}
