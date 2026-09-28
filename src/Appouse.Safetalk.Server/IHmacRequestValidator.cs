using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server;

/// <summary>
/// Validates the HMAC signature, timestamp and client of an incoming request.
/// </summary>
/// <remarks>
/// <para>
/// Used by <see cref="HmacAuthenticationMiddleware"/> and by the <c>AddHmac()</c> authentication handler. It can also
/// be called from custom middleware that runs <em>before</em> the request body is consumed; it cannot be used from
/// minimal API endpoint filters or MVC action filters, because the body has already been read by model binding.
/// </para>
/// <para>
/// The default <see cref="HmacRequestValidator"/> validates a request once and returns the same result to every later
/// call within that request, so custom callers, decorators, the middleware and the authentication scheme can be
/// combined. A request is marked as verified (<see cref="IHmacClientFeature"/>) only by the middleware and the
/// authentication scheme, after the <em>registered</em> validator succeeded, so a decorator that rejects a request
/// (for example an IP allow-list) is always honoured. Custom implementations should also cache their result: a second
/// verification of the same request would otherwise be reported as a replay.
/// </para>
/// </remarks>
public interface IHmacRequestValidator
{
    /// <summary>
    /// Validates the request. The request body is buffered and remains readable by later components.
    /// </summary>
    /// <param name="context">The HTTP context of the request.</param>
    /// <param name="cancellationToken">A token that is cancelled when the request is aborted.</param>
    /// <returns>The validation result.</returns>
    ValueTask<HmacValidationResult> ValidateAsync(HttpContext context, CancellationToken cancellationToken = default);
}
