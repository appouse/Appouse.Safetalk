using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server;

/// <summary>
/// Builds the identity of an authenticated client and attaches it to the request. Shared by the middleware and the
/// authentication handler so they produce identical results.
/// </summary>
internal static class HmacClientIdentity
{
    public static ClaimsIdentity Create(string clientId) => new(
        [
            new Claim(ClaimTypes.NameIdentifier, clientId),
            new Claim(ClaimTypes.Name, clientId),
            new Claim(HmacAuthenticationDefaults.ClientIdClaimType, clientId),
        ],
        HmacAuthenticationDefaults.AuthenticationType);

    /// <summary>
    /// Records that the request was verified for <paramref name="clientId"/>.
    /// </summary>
    public static void SetFeature(HttpContext context, string clientId)
        => context.Features.Set<IHmacClientFeature>(new HmacClientFeature(clientId));

    /// <summary>
    /// Returns the client id verified earlier in this request by this library, if any. Only the internal feature type
    /// counts, so other components cannot forge a verification.
    /// </summary>
    public static string? GetVerifiedClientId(HttpContext context)
        => context.Features.Get<IHmacClientFeature>() is HmacClientFeature feature ? feature.ClientId : null;

    /// <summary>
    /// Attaches the verified client to <see cref="HttpContext.User"/>. Idempotent: a re-executed request does not get
    /// a second HMAC identity.
    /// </summary>
    public static void SignIn(HttpContext context, string clientId)
    {
        SetFeature(context, clientId);

        ClaimsPrincipal user = context.User;
        if (user.Identities.Any(identity => identity.IsAuthenticated
            && identity.AuthenticationType == HmacAuthenticationDefaults.AuthenticationType
            && identity.HasClaim(HmacAuthenticationDefaults.ClientIdClaimType, clientId)))
        {
            return;
        }

        ClaimsIdentity hmacIdentity = Create(clientId);

        // Keep identities established by other authentication mechanisms; otherwise make HMAC the primary identity.
        if (user.Identity?.IsAuthenticated == true)
        {
            user.AddIdentity(hmacIdentity);
        }
        else
        {
            context.User = new ClaimsPrincipal(hmacIdentity);
        }
    }
}
