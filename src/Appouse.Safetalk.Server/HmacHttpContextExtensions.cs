using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server;

/// <summary>
/// <see cref="HttpContext"/> helpers for HMAC authenticated requests.
/// </summary>
public static class HmacHttpContextExtensions
{
    /// <summary>
    /// Gets the identifier of the client whose HMAC signature was verified for the current request.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The client identifier, or <see langword="null"/> when the request was not HMAC authenticated.</returns>
    public static string? GetHmacClientId(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<IHmacClientFeature>()?.ClientId;
    }
}
