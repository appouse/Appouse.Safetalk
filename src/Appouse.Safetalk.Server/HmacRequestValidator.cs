using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Appouse.Safetalk.Server;

/// <summary>
/// Default <see cref="IHmacRequestValidator"/>.
/// </summary>
/// <remarks>
/// Each request is validated once: the result is remembered for the request, so later calls (the middleware, the
/// authentication handler, custom callers, decorators, pipeline re-execution) return it without reading the body again.
/// Checks are ordered from cheapest to most expensive so that invalid requests are rejected before any I/O:
/// <list type="number">
///   <item><description>required headers are present exactly once, and <c>X-Client-Id</c> is at most <see cref="SafetalkHeaderNames.MaxClientIdLength"/> printable ASCII characters,</description></item>
///   <item><description>the timestamp is well-formed and inside the allowed clock skew window,</description></item>
///   <item><description>a declared <c>Content-Length</c> is within <see cref="HmacServerOptions.MaxBodySize"/> (checked before the secret lookup, as a cheap denial-of-service guard),</description></item>
///   <item><description>the request target is in origin-form and no unsigned <c>X-HTTP-Method-Override</c> is present,</description></item>
///   <item><description>the client is known to <see cref="IHmacSecretProvider"/>,</description></item>
///   <item><description>the body is buffered with <see cref="HttpRequestRewindExtensions.EnableBuffering(HttpRequest, int, long)"/> (in memory only), read to the end and rewound (<c>Position = 0</c>), and the signature is verified in constant time,</description></item>
///   <item><description>optionally, freshness is re-checked and the signature is recorded in <see cref="IHmacReplayCache"/>.</description></item>
/// </list>
/// Pooled memory grows with the bytes actually received, never with the untrusted <c>Content-Length</c> value.
/// Client identifiers are not secret: response codes and timing may reveal whether an identifier is known.
/// </remarks>
public sealed partial class HmacRequestValidator : IHmacRequestValidator
{
    /// <summary>
    /// How long replay entries outlive the last instant at which their timestamp is accepted. Covers the time between
    /// the freshness check and the cache insert, and clock drift between instances sharing a distributed cache.
    /// </summary>
    internal static readonly TimeSpan ReplayEntryExpirationMargin = TimeSpan.FromSeconds(30);

    private const int ReadChunkSize = 16 * 1024;
    private const int MaxInitialBodyBufferSize = 8 * 1024;
    private const string MethodOverrideHeader = "X-HTTP-Method-Override";

    private readonly IHmacSecretProvider _secretProvider;
    private readonly IHmacSignatureService _signatureService;
    private readonly IHmacReplayCache _replayCache;
    private readonly IOptionsMonitor<HmacServerOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<HmacRequestValidator> _logger;
    private readonly HmacClockSkewTracker? _clockSkewTracker;

    /// <summary>
    /// Initializes a new validator.
    /// </summary>
    /// <param name="secretProvider">Resolves client secrets.</param>
    /// <param name="signatureService">Verifies signatures.</param>
    /// <param name="replayCache">Remembers accepted signatures when replay protection is enabled.</param>
    /// <param name="options">The server options.</param>
    /// <param name="timeProvider">The clock used to validate timestamps.</param>
    /// <param name="logger">The logger.</param>
    public HmacRequestValidator(
        IHmacSecretProvider secretProvider,
        IHmacSignatureService signatureService,
        IHmacReplayCache replayCache,
        IOptionsMonitor<HmacServerOptions> options,
        TimeProvider timeProvider,
        ILogger<HmacRequestValidator> logger)
        : this(secretProvider, signatureService, replayCache, options, timeProvider, logger, clockSkewTracker: null)
    {
    }

    /// <summary>
    /// Initializes a new validator whose clock skew window is capped by <paramref name="clockSkewTracker"/> while replay
    /// protection is enabled. Used by the dependency injection registration.
    /// </summary>
    internal HmacRequestValidator(
        IHmacSecretProvider secretProvider,
        IHmacSignatureService signatureService,
        IHmacReplayCache replayCache,
        IOptionsMonitor<HmacServerOptions> options,
        TimeProvider timeProvider,
        ILogger<HmacRequestValidator> logger,
        HmacClockSkewTracker? clockSkewTracker)
    {
        ArgumentNullException.ThrowIfNull(secretProvider);
        ArgumentNullException.ThrowIfNull(signatureService);
        ArgumentNullException.ThrowIfNull(replayCache);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _secretProvider = secretProvider;
        _signatureService = signatureService;
        _replayCache = replayCache;
        _options = options;
        _timeProvider = timeProvider;
        _logger = logger;
        _clockSkewTracker = clockSkewTracker;
    }

    private enum BodyReadResult
    {
        Completed,
        TooLarge,
        LengthMismatch,
        AlreadyConsumed,
    }

    /// <inheritdoc />
    public async ValueTask<HmacValidationResult> ValidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        // The body has been consumed and, with replay protection, a second verification would report the request as
        // its own replay: every caller within the same request gets the first result.
        if (context.Features.Get<HmacValidationResultFeature>() is { } previous)
        {
            return previous.Result;
        }

        HmacValidationResult result = await ValidateCoreAsync(context, cancellationToken).ConfigureAwait(false);

        // Only the outcome is cached. The request is marked as verified by the consumers of the *registered*
        // validator (middleware, authentication handler), so a decorating validator can still reject it.
        context.Features.Set(new HmacValidationResultFeature(result));
        return result;
    }

    private async ValueTask<HmacValidationResult> ValidateCoreAsync(HttpContext context, CancellationToken cancellationToken)
    {
        HttpRequest request = context.Request;
        HmacServerOptions options = _options.CurrentValue;

        // All three headers are read before failing so the claimed client id can be logged.
        string? clientId = GetSingleHeader(request.Headers, SafetalkHeaderNames.ClientId);
        string? timestamp = GetSingleHeader(request.Headers, SafetalkHeaderNames.Timestamp);
        string? signature = GetSingleHeader(request.Headers, SafetalkHeaderNames.Signature);
        if (clientId is null || timestamp is null || signature is null)
        {
            return Reject(request, HmacValidationFailure.MissingHeaders, IsWellFormedClientId(clientId) ? clientId : null);
        }

        if (!IsWellFormedClientId(clientId))
        {
            // Arbitrary attacker-chosen data never reaches the secret store or the logs.
            return Reject(request, HmacValidationFailure.UnknownClient, clientId: null);
        }

        if (!long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out long unixSeconds))
        {
            return Reject(request, HmacValidationFailure.InvalidTimestamp, clientId);
        }

        TimeSpan clockSkew = GetEffectiveClockSkew(options);
        if (!IsFresh(unixSeconds, clockSkew))
        {
            return Reject(request, HmacValidationFailure.TimestampOutOfRange, clientId);
        }

        long? declaredLength = request.ContentLength;
        if (declaredLength > options.MaxBodySize)
        {
            return Reject(request, HmacValidationFailure.PayloadTooLarge, clientId);
        }

        if (!TryResolveRequestTarget(context, options, out string? requestTarget))
        {
            return Reject(request, HmacValidationFailure.InvalidRequestTarget, clientId);
        }

        // The override header is not signed. It is accepted only when it names the method being verified, i.e. when
        // UseHttpMethodOverride() already ran; otherwise it could route a signed request to a different handler. And the
        // verified method must be one the selected endpoint accepts: an override applied after routing (for example
        // with WebApplication's implicit routing) would otherwise run the handler selected for the wire method.
        bool methodOverridden = request.Headers.TryGetValue(MethodOverrideHeader, out StringValues methodOverride);
        if ((methodOverridden && !string.Equals(methodOverride.ToString(), request.Method, StringComparison.OrdinalIgnoreCase))
            || !IsMethodAcceptedBySelectedEndpoint(context, methodOverridden))
        {
            return Reject(request, HmacValidationFailure.UnsignedMethodOverride, clientId);
        }

        string? secret = await _secretProvider.GetSecretAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(secret))
        {
            return Reject(request, HmacValidationFailure.UnknownClient, clientId);
        }

        int bodyLengthHint = (int)Math.Min(declaredLength ?? 0, MaxInitialBodyBufferSize);
        using (CanonicalRequestBuffer canonicalRequest = CanonicalRequestBuffer.Create(request.Method, requestTarget, timestamp, bodyLengthHint))
        {
            BodyReadResult body = await ReadBodyAsync(context, canonicalRequest, options.MaxBodySize, cancellationToken).ConfigureAwait(false);
            if (body != BodyReadResult.Completed)
            {
                HmacValidationFailure failure = body switch
                {
                    BodyReadResult.TooLarge => HmacValidationFailure.PayloadTooLarge,
                    BodyReadResult.AlreadyConsumed => HmacValidationFailure.BodyAlreadyConsumed,
                    _ => HmacValidationFailure.ContentLengthMismatch,
                };
                return Reject(request, failure, clientId);
            }

            if (!_signatureService.VerifySignature(secret, canonicalRequest.WrittenSpan, signature))
            {
                return Reject(request, HmacValidationFailure.InvalidSignature, clientId);
            }
        }

        if (options.EnableReplayProtection)
        {
            // The body may have taken a while to arrive: freshness and replay must be decided at the same instant,
            // otherwise a request stalled past the window could slip in after its replay entry expired.
            if (!IsFresh(unixSeconds, clockSkew))
            {
                return Reject(request, HmacValidationFailure.TimestampOutOfRange, clientId);
            }

            // Entries live for the widest window that can ever be in effect, not just the current one.
            TimeSpan retentionSkew = _clockSkewTracker?.MaxClockSkew ?? clockSkew;
            DateTimeOffset expiresAt = GetAcceptanceWindowEnd(unixSeconds, retentionSkew) + ReplayEntryExpirationMargin;
            bool firstSeen = await _replayCache
                .TryAddAsync(signature.ToLowerInvariant(), expiresAt, cancellationToken)
                .ConfigureAwait(false);

            if (!firstSeen)
            {
                return Reject(request, HmacValidationFailure.ReplayDetected, clientId);
            }
        }

        Log.RequestValidated(_logger, request.Method, request.Path, clientId);
        return HmacValidationResult.Success(clientId);
    }

    /// <summary>
    /// Resolves the request target (path and query) exactly as the client sent it.
    /// </summary>
    /// <returns><see langword="false"/> when the target is not in origin-form.</returns>
    internal static bool TryResolveRequestTarget(HttpContext context, HmacServerOptions options, [NotNullWhen(true)] out string? requestTarget)
    {
        if (options.RequestTargetResolver is { } resolver)
        {
            requestTarget = resolver(context);
            return IsOriginForm(requestTarget);
        }

        string? rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(rawTarget))
        {
            // Hosts that do not expose the raw target (for example TestServer): rebuild it from the decoded
            // components. Reserved characters that the client percent-encoded (such as %40 or %3A) cannot be
            // restored exactly, so such paths only verify on hosts that expose the raw target (Kestrel, IIS, HTTP.sys).
            requestTarget = context.Request.GetEncodedPathAndQuery();
            return true;
        }

        // Only origin-form ("/path?query") is accepted. For absolute-form ("http://host/path") the server derives
        // Path and QueryString differently from Uri.PathAndQuery (fragments, %2F), so the verified bytes would not
        // be what routing and model binding consume.
        requestTarget = rawTarget;
        return IsOriginForm(rawTarget);
    }

    /// <summary>
    /// Returns the configured clock skew, capped by <see cref="HmacClockSkewTracker"/> while replay protection is on.
    /// </summary>
    private TimeSpan GetEffectiveClockSkew(HmacServerOptions options)
    {
        if (!options.EnableReplayProtection || _clockSkewTracker is null)
        {
            return options.AllowedClockSkew;
        }

        TimeSpan effective = _clockSkewTracker.GetEffectiveClockSkew(options.AllowedClockSkew, out bool firstWideningAttempt);
        if (firstWideningAttempt)
        {
            Log.ClockSkewWideningDeferred(_logger, options.AllowedClockSkew, effective);
        }

        return effective;
    }

    private static bool IsOriginForm([NotNullWhen(true)] string? target) => !string.IsNullOrEmpty(target) && target[0] == '/';

    /// <summary>
    /// Returns whether the endpoint already selected by routing accepts the method being verified. When the method may
    /// have been overridden, the endpoint must list it explicitly: any-method and fallback endpoints do not qualify,
    /// and the CORS preflight allowance only applies to a genuine preflight.
    /// </summary>
    private static bool IsMethodAcceptedBySelectedEndpoint(HttpContext context, bool methodOverridden)
    {
        Endpoint? endpoint = context.GetEndpoint();
        if (endpoint is null)
        {
            return true; // Routing has not selected an endpoint (yet); nothing to compare with.
        }

        if (endpoint.Metadata.GetMetadata<IHttpMethodMetadata>() is not { HttpMethods.Count: > 0 } methodMetadata)
        {
            return !methodOverridden; // Any-method endpoint: fine unless the method was rewritten.
        }

        HttpRequest request = context.Request;
        foreach (string accepted in methodMetadata.HttpMethods)
        {
            if (string.Equals(accepted, request.Method, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return !methodOverridden
            && methodMetadata.AcceptCorsPreflight
            && HttpMethods.IsOptions(request.Method)
            && request.Headers.ContainsKey(HeaderNames.Origin)
            && request.Headers.ContainsKey(HeaderNames.AccessControlRequestMethod);
    }

    private static bool IsWellFormedClientId([NotNullWhen(true)] string? clientId)
    {
        if (clientId is null || clientId.Length > SafetalkHeaderNames.MaxClientIdLength)
        {
            return false;
        }

        foreach (char c in clientId)
        {
            if (c is < ' ' or > '~')
            {
                return false;
            }
        }

        return true;
    }

    private bool IsFresh(long unixSeconds, TimeSpan allowedClockSkew)
    {
        long now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        long tolerance = (long)allowedClockSkew.TotalSeconds;

        return unixSeconds >= now - tolerance && unixSeconds <= now + tolerance;
    }

    /// <summary>
    /// Returns the first instant at which <see cref="IsFresh"/> rejects <paramref name="unixSeconds"/>: the check
    /// compares whole seconds, so the timestamp is accepted until <c>ts + tolerance + 1s</c> (exclusive).
    /// </summary>
    private static DateTimeOffset GetAcceptanceWindowEnd(long unixSeconds, TimeSpan allowedClockSkew)
        => DateTimeOffset.FromUnixTimeSeconds(unixSeconds + (long)allowedClockSkew.TotalSeconds + 1);

    private static async ValueTask<BodyReadResult> ReadBodyAsync(
        HttpContext context,
        CanonicalRequestBuffer canonicalRequest,
        int maxBodySize,
        CancellationToken cancellationToken)
    {
        HttpRequest request = context.Request;
        long? declaredLength = request.ContentLength;
        bool canHaveBody = context.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody ?? true;
        if (!canHaveBody || declaredLength == 0)
        {
            return BodyReadResult.Completed;
        }

        // A form read by earlier middleware (for example the form-field variant of UseHttpMethodOverride) has consumed a
        // body that cannot be rewound: what remains is not what was signed, and the form is cached for the endpoint.
        if (!request.Body.CanSeek && IsFormAlreadyRead(context))
        {
            return BodyReadResult.AlreadyConsumed;
        }

        // Makes the body re-readable for model binding. The memory threshold is unbounded so that bodies are never
        // spilled to temporary files (the size is capped by the limit instead), which also avoids failures on
        // read-only file systems.
        request.EnableBuffering(bufferThreshold: int.MaxValue, bufferLimit: (long)maxBodySize + 1);
        Stream body = request.Body;
        body.Position = 0;

        try
        {
            // Read to the end of the stream, never trusting Content-Length as the amount of data: at most one byte
            // beyond the limit is read to detect oversized or mismatching bodies.
            long limit = declaredLength ?? maxBodySize;
            long totalRead = 0;
            while (true)
            {
                int readSize = (int)Math.Min(limit - totalRead + 1, ReadChunkSize);
                Memory<byte> memory = canonicalRequest.GetMemory(readSize);
                int read = await body.ReadAsync(memory[..Math.Min(memory.Length, readSize)], cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                canonicalRequest.Advance(read);
                totalRead += read;
                if (totalRead > limit)
                {
                    return declaredLength is null ? BodyReadResult.TooLarge : BodyReadResult.LengthMismatch;
                }
            }

            return declaredLength is long expected && totalRead != expected
                ? BodyReadResult.LengthMismatch
                : BodyReadResult.Completed;
        }
        finally
        {
            body.Position = 0;
        }
    }

    private static bool IsFormAlreadyRead(HttpContext context)
    {
        if (context.Features.Get<IFormFeature>() is not { } formFeature)
        {
            return false;
        }

        try
        {
            return formFeature.Form is not null;
        }
        catch (InvalidOperationException)
        {
            // The antiforgery middleware read the form and recorded an invalid token: the body is consumed as well.
            return true;
        }
    }

    /// <summary>
    /// Returns the header value when it is present exactly once and not empty; otherwise <see langword="null"/>.
    /// Repeated headers are rejected because their combined value would be ambiguous.
    /// </summary>
    private static string? GetSingleHeader(IHeaderDictionary headers, string name)
    {
        StringValues values = headers[name];
        return values.Count == 1 && !string.IsNullOrEmpty(values[0]) ? values[0] : null;
    }

    private HmacValidationResult Reject(HttpRequest request, HmacValidationFailure failure, string? clientId)
    {
        Log.RequestRejected(_logger, request.Method, request.Path, failure, clientId);
        return HmacValidationResult.Fail(failure, clientId);
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "HMAC signature of {Method} {Path} verified for client '{ClientId}'.")]
        public static partial void RequestValidated(ILogger logger, string method, PathString path, string clientId);

        [LoggerMessage(EventId = 2, Level = LogLevel.Warning, Message = "Rejected {Method} {Path}: {Failure} (client '{ClientId}').")]
        public static partial void RequestRejected(ILogger logger, string method, PathString path, HmacValidationFailure failure, string? clientId);

        [LoggerMessage(
            EventId = 3,
            Level = LogLevel.Warning,
            Message = "AllowedClockSkew was widened to {Configured} at runtime while replay protection is enabled; {Effective} stays in effect until the application restarts, because replay entries recorded earlier cannot be extended.")]
        public static partial void ClockSkewWideningDeferred(ILogger logger, TimeSpan configured, TimeSpan effective);
    }
}
