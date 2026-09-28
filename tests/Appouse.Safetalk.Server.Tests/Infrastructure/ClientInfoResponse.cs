using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// What an endpoint observed about the caller after the HMAC middleware ran.
/// </summary>
public sealed record ClientInfoResponse(
    string? HmacClientId,
    string? PrimaryName,
    string? PrimaryAuthenticationType,
    bool IsAuthenticated,
    string? NameIdentifier,
    string? ClientIdClaim,
    string[] AuthenticationTypes,
    string Body)
{
    public static ClientInfoResponse From(HttpContext context, string body)
    {
        ArgumentNullException.ThrowIfNull(context);

        ClaimsPrincipal user = context.User;
        return new ClientInfoResponse(
            context.GetHmacClientId(),
            user.Identity?.Name,
            user.Identity?.AuthenticationType,
            user.Identity?.IsAuthenticated == true,
            user.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            user.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value,
            [.. user.Identities.Select(identity => identity.AuthenticationType ?? string.Empty)],
            body);
    }
}
