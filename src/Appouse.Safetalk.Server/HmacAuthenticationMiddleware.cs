using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server;

/// <summary>
/// ASP.NET Core middleware that rejects requests whose HMAC signature cannot be verified before they reach
/// controllers or endpoints.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>Which requests are validated is decided by per-endpoint <see cref="IHmacValidationMetadata"/> and, when an endpoint has none, by <see cref="HmacServerOptions.EnforcementMode"/>. Attributes (<see cref="SkipHmacValidationAttribute"/>, <see cref="RequireHmacValidationAttribute"/>) take precedence over the <c>SkipHmacValidation()</c>/<c>RequireHmacValidation()</c> conventions; within each kind the most specific (last) one wins.</description></item>
///   <item><description>When the middleware is registered before <c>UseRouting()</c>, endpoint metadata is not available, so every request is validated (fail closed) and a warning is logged at start-up. When routing cannot be proven to run first (a <c>UseWhen</c>/<c>Map</c> branch without routing before it, or manual <c>UseMiddleware</c> registration), requests for which no endpoint has been selected are validated in every mode.</description></item>
///   <item><description>Invalid, expired or replayed requests are short-circuited with <c>401 Unauthorized</c> (and a <c>WWW-Authenticate</c> challenge); oversized bodies with <c>413 Payload Too Large</c>.</description></item>
///   <item><description>When <see cref="IProblemDetailsService"/> is registered (<c>AddProblemDetails()</c>), an RFC 9457 problem details body is written. The failure reason is logged but never disclosed to the caller.</description></item>
///   <item><description>Authenticated requests get an <see cref="IHmacClientFeature"/> and a <see cref="System.Security.Claims.ClaimsPrincipal"/> carrying the client identifier.</description></item>
///   <item><description>A request is validated at most once, also when it is re-executed (<c>UseExceptionHandler</c>, <c>UseStatusCodePagesWithReExecute</c>) or already validated by the <c>AddHmac()</c> authentication scheme.</description></item>
/// </list>
/// </remarks>
public sealed partial class HmacAuthenticationMiddleware
{
    private const string FailureDetail = "The request signature could not be verified.";

    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<HmacServerOptions> _options;
    private readonly RoutingOrder _routingOrder;
    private readonly ILogger? _logger;
    private int _routingAfterReported;
    private volatile bool _routingDetectedAfter;

    /// <summary>
    /// Initializes a new instance of the middleware. Registered this way (for example with <c>UseMiddleware</c>), it
    /// cannot tell whether routing runs before it, so requests without a selected endpoint are always validated;
    /// prefer <c>UseHmacAuthentication()</c>.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="options">The server options.</param>
    public HmacAuthenticationMiddleware(RequestDelegate next, IOptionsMonitor<HmacServerOptions> options)
        : this(next, options, RoutingOrder.Unknown, logger: null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the middleware, knowing where routing runs relative to it.
    /// </summary>
    internal HmacAuthenticationMiddleware(
        RequestDelegate next,
        IOptionsMonitor<HmacServerOptions> options,
        RoutingOrder routingOrder,
        ILogger<HmacAuthenticationMiddleware>? logger)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(options);

        _next = next;
        _options = options;
        _routingOrder = routingOrder;
        _logger = logger;
    }

    /// <summary>
    /// Where endpoint routing runs relative to the middleware.
    /// </summary>
    internal enum RoutingOrder
    {
        /// <summary>Routing is known to run first: a missing endpoint means no route matched.</summary>
        Before,

        /// <summary>Unknown (pipeline branch, manual registration): a missing endpoint may mean routing has not run yet.</summary>
        Unknown,

        /// <summary>Routing is known to run later: endpoint metadata is never available.</summary>
        After,
    }

    /// <summary>
    /// Processes a request.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="validator">The request validator (resolved per request, so it may depend on scoped services).</param>
    /// <returns>A task that completes when the request has been processed.</returns>
    public async Task InvokeAsync(HttpContext context, IHmacRequestValidator validator)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(validator);

        string? verifiedClientId = HmacClientIdentity.GetVerifiedClientId(context);
        if (verifiedClientId is not null)
        {
            // Already verified in this request (re-execution, authentication scheme).
            HmacClientIdentity.SignIn(context, verifiedClientId);
            await InvokeNextAsync(context).ConfigureAwait(false);
            return;
        }

        if (!RequiresValidation(context))
        {
            await InvokeNextAsync(context).ConfigureAwait(false);
            return;
        }

        HmacValidationResult result = await validator.ValidateAsync(context, context.RequestAborted).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            await WriteFailureResponseAsync(context, result.Failure).ConfigureAwait(false);
            return;
        }

        HmacClientIdentity.SignIn(context, result.ClientId);
        await InvokeNextAsync(context).ConfigureAwait(false);
    }

    private async Task InvokeNextAsync(HttpContext context)
    {
        bool endpointPending = _routingOrder != RoutingOrder.After && !_routingDetectedAfter && context.GetEndpoint() is null;

        await _next(context).ConfigureAwait(false);

        // An endpoint that appears only after this middleware, on a successful response (error responses may have been
        // re-executed through an error endpoint), proves that routing runs later than the pipeline suggested: from then
        // on every request is validated (fail closed), and the misconfiguration is reported once.
        if (endpointPending && context.GetEndpoint() is not null && context.Response.StatusCode < StatusCodes.Status400BadRequest)
        {
            _routingDetectedAfter = true;
            if (_logger is not null && Interlocked.Exchange(ref _routingAfterReported, 1) == 0)
            {
                Log.RoutingRegisteredAfterMiddleware(_logger);
            }
        }
    }

    private bool RequiresValidation(HttpContext context)
    {
        if (_routingOrder == RoutingOrder.After || _routingDetectedAfter)
        {
            return true; // Routing runs after this middleware: metadata can never be read, so fail closed.
        }

        Endpoint? endpoint = context.GetEndpoint();
        if (endpoint is null && _routingOrder == RoutingOrder.Unknown)
        {
            return true; // Routing may not have run yet: the endpoint could be one that requires validation.
        }

        if (endpoint is not null)
        {
            // Attributes beat conventions: ASP.NET Core appends MapControllers() conventions after controller and
            // action attributes, and a broad convention must not silently override an explicit attribute.
            IHmacValidationMetadata? attribute = null;
            IHmacValidationMetadata? convention = null;
            foreach (IHmacValidationMetadata metadata in endpoint.Metadata.GetOrderedMetadata<IHmacValidationMetadata>())
            {
                if (metadata is HmacValidationConventionMetadata)
                {
                    convention = metadata;
                }
                else
                {
                    attribute = metadata;
                }
            }

            if ((attribute ?? convention) is { } decision)
            {
                return decision.RequiresValidation;
            }
        }

        // Anything but an explicit opt-in mode (including undefined values) fails closed.
        return _options.CurrentValue.EnforcementMode != HmacEnforcementMode.MarkedEndpointsOnly;
    }

    internal static partial class Log
    {
        [LoggerMessage(
            EventId = 10,
            Level = LogLevel.Warning,
            Message = "UseHmacAuthentication() is registered before UseRouting(): endpoint metadata ([SkipHmacValidation], [RequireHmacValidation] and their conventions) cannot be read, so every request is validated. Call UseHmacAuthentication() after UseRouting().")]
        public static partial void RoutingRegisteredAfterMiddleware(ILogger logger);
    }

    private static async Task WriteFailureResponseAsync(HttpContext context, HmacValidationFailure failure)
    {
        int statusCode = failure == HmacValidationFailure.PayloadTooLarge
            ? StatusCodes.Status413PayloadTooLarge
            : StatusCodes.Status401Unauthorized;

        HttpResponse response = context.Response;
        response.StatusCode = statusCode;
        if (statusCode == StatusCodes.Status401Unauthorized)
        {
            response.Headers.WWWAuthenticate = HmacAuthenticationDefaults.ChallengeScheme;
        }

        IProblemDetailsService? problemDetailsService = context.RequestServices.GetService<IProblemDetailsService>();
        if (problemDetailsService is null)
        {
            return;
        }

        await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            ProblemDetails = new ProblemDetails
            {
                Status = statusCode,
                Title = ReasonPhrases.GetReasonPhrase(statusCode),
                Detail = statusCode == StatusCodes.Status401Unauthorized ? FailureDetail : null,
            },
        }).ConfigureAwait(false);
    }
}
