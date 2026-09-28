using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// An <see cref="HmacRequestValidator"/> wired to a fake clock, in-memory secrets and mutable options.
/// </summary>
/// <remarks>
/// Without <paramref name="clockSkewTracker"/> the public constructor is used (no clock skew cap); with it, the internal
/// constructor used by the dependency injection registration.
/// </remarks>
internal sealed class ValidatorHarness
{
    public ValidatorHarness(
        IHmacSecretProvider? secretProvider = null,
        IHmacReplayCache? replayCache = null,
        HmacClockSkewTracker? clockSkewTracker = null,
        ILogger<HmacRequestValidator>? logger = null)
    {
        Time = new FakeTimeProvider(TestCredentials.Now);
        SecretProvider = secretProvider ?? TestCredentials.CreateSecretProvider();
        ReplayCache = replayCache ?? new InMemoryHmacReplayCache(Time);
        ClockSkewTracker = clockSkewTracker;
        var options = new StaticOptionsMonitor<HmacServerOptions>(Options);
        logger ??= NullLogger<HmacRequestValidator>.Instance;
        Validator = clockSkewTracker is null
            ? new HmacRequestValidator(SecretProvider, HmacSha256SignatureService.Instance, ReplayCache, options, Time, logger)
            : new HmacRequestValidator(SecretProvider, HmacSha256SignatureService.Instance, ReplayCache, options, Time, logger, clockSkewTracker);
    }

    public FakeTimeProvider Time { get; }

    public HmacServerOptions Options { get; } = new();

    public IHmacSecretProvider SecretProvider { get; }

    public IHmacReplayCache ReplayCache { get; }

    public HmacClockSkewTracker? ClockSkewTracker { get; }

    public HmacRequestValidator Validator { get; }

    public long UnixNow => Time.GetUtcNow().ToUnixTimeSeconds();

    public SignedRequestBuilder NewRequest() => new(UnixNow);

    public ValueTask<HmacValidationResult> ValidateAsync(HttpContext context) =>
        Validator.ValidateAsync(context, TestContext.Current.CancellationToken);
}
