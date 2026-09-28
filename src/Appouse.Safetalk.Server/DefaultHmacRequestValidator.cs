using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server;

/// <summary>
/// The <see cref="IHmacRequestValidator"/> registered by <c>AddHmacServer()</c>: a <see cref="HmacRequestValidator"/>
/// whose clock skew window is capped by <see cref="HmacClockSkewTracker"/>. Registered by type (not through a
/// factory) so that the container validates its dependencies, such as <see cref="IHmacSecretProvider"/>, at start-up.
/// </summary>
internal sealed class DefaultHmacRequestValidator(
    IHmacSecretProvider secretProvider,
    IHmacSignatureService signatureService,
    IHmacReplayCache replayCache,
    IOptionsMonitor<HmacServerOptions> options,
    TimeProvider timeProvider,
    ILogger<HmacRequestValidator> logger,
    HmacClockSkewTracker clockSkewTracker) : IHmacRequestValidator
{
    private readonly HmacRequestValidator _inner = new(secretProvider, signatureService, replayCache, options, timeProvider, logger, clockSkewTracker);

    public ValueTask<HmacValidationResult> ValidateAsync(HttpContext context, CancellationToken cancellationToken = default)
        => _inner.ValidateAsync(context, cancellationToken);
}
