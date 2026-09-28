using System.Globalization;
using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// <see cref="HmacServerOptions.AllowedClockSkew"/> changed through a configuration reload. With replay protection,
/// replay entries recorded under the window in effect at the first request cannot be extended afterwards, so the window
/// may be narrowed at runtime but never widened beyond that value until a restart (a warning is logged once).
/// Without replay protection the new value applies immediately.
/// </summary>
public sealed class ClockSkewReloadTests
{
    private const int WideningDeferredEventId = 3;

    private static readonly DateTimeOffset ServerNow = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayProtection_WideningTheWindowByReload_IsDeferredUntilRestart_AndLoggedOnce(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        IConfigurationRoot configuration = CreateConfiguration(replayProtection: true, clockSkew: "00:00:30");
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, CreateServer(configuration, logs), ct);

        HttpStatusCode first = await SendWithClockOffsetAsync(server, TimeSpan.Zero, ct); // Establishes the 30 s cap.
        configuration["Safetalk:AllowedClockSkew"] = "00:05:00";
        configuration.Reload();
        HttpStatusCode oneMinuteOld = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-60), ct);
        HmacValidationFailure oneMinuteOldFailure = server.LastFailure;
        HttpStatusCode oneMinuteOldAgain = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-60), ct);
        HttpStatusCode stillInsideCap = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-25), ct);

        Assert.Equal(
            (HttpStatusCode.OK, HttpStatusCode.Unauthorized, HmacValidationFailure.TimestampOutOfRange, HttpStatusCode.Unauthorized, HttpStatusCode.OK),
            (first, oneMinuteOld, oneMinuteOldFailure, oneMinuteOldAgain, stillInsideCap));
        CapturedLog warning = Assert.Single(logs.Find<HmacRequestValidator>(WideningDeferredEventId));
        Assert.Equal((TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(30)), ((TimeSpan)warning.GetValue("Configured")!, (TimeSpan)warning.GetValue("Effective")!));
    }

    /// <summary>
    /// Narrowing applies to the next request, and restoring the original value re-opens the window; replay entries
    /// keep the retention of the original (widest) window so none expires before its timestamp can no longer be accepted.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayProtection_NarrowingTheWindowByReload_AppliesImmediately_WhileEntriesKeepTheOriginalRetention(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        IConfigurationRoot configuration = CreateConfiguration(replayProtection: true, clockSkew: "00:00:30");
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, CreateServer(configuration, logs), ct);

        HttpStatusCode first = await SendWithClockOffsetAsync(server, TimeSpan.Zero, ct);
        configuration["Safetalk:AllowedClockSkew"] = "00:00:10";
        configuration.Reload();
        HttpStatusCode twentySecondsOld = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-20), ct);
        HttpStatusCode fiveSecondsOld = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-5), ct);
        configuration["Safetalk:AllowedClockSkew"] = "00:00:30";
        configuration.Reload();
        HttpStatusCode twentySecondsOldAfterRestore = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-20), ct);

        Assert.Equal(
            (HttpStatusCode.OK, HttpStatusCode.Unauthorized, HttpStatusCode.OK, HttpStatusCode.OK),
            (first, twentySecondsOld, fiveSecondsOld, twentySecondsOldAfterRestore));
        Assert.Empty(logs.Find<HmacRequestValidator>(WideningDeferredEventId));

        // Every entry, including the one recorded while the window was 10 s, lives until ts + 30 s + 1 s + 30 s margin.
        var cache = Assert.IsType<RecordingReplayCache>(server.Services.GetRequiredService<IHmacReplayCache>());
        long[] timestamps = [.. new[] { 0, -5, -20 }.Select(offset => ServerNow.AddSeconds(offset).ToUnixTimeSeconds())];
        Assert.Equal(
            timestamps.Select(timestamp => DateTimeOffset.FromUnixTimeSeconds(timestamp + 30 + 1) + TimeSpan.FromSeconds(30)),
            cache.Calls.Select(call => call.ExpiresAt));
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task WithoutReplayProtection_WideningTheWindowByReload_AppliesImmediately(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        IConfigurationRoot configuration = CreateConfiguration(replayProtection: false, clockSkew: "00:00:30");
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, CreateServer(configuration, logs, replayCache: false), ct);

        HttpStatusCode before = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-60), ct);
        configuration["Safetalk:AllowedClockSkew"] = "00:05:00";
        configuration.Reload();
        HttpStatusCode after = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-60), ct);

        Assert.Equal((HttpStatusCode.Unauthorized, HttpStatusCode.OK), (before, after));
        Assert.Empty(logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    /// <summary>
    /// Enabling replay protection by reload after the application served requests without it: the cap is the window
    /// captured at the first request, so a window widened earlier (while replay protection was off) stays in effect.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReplayProtectionEnabledByReload_CapsTheWindowAtTheValueOfTheFirstRequest(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        IConfigurationRoot configuration = CreateConfiguration(replayProtection: false, clockSkew: "00:00:30");
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, CreateServer(configuration, logs), ct);

        HttpStatusCode first = await SendWithClockOffsetAsync(server, TimeSpan.Zero, ct);
        configuration["Safetalk:AllowedClockSkew"] = "00:05:00";
        configuration["Safetalk:EnableReplayProtection"] = "true";
        configuration.Reload();
        HttpStatusCode oneMinuteOld = await SendWithClockOffsetAsync(server, TimeSpan.FromSeconds(-60), ct);
        HmacValidationFailure failure = server.LastFailure;

        Assert.Equal((HttpStatusCode.OK, HttpStatusCode.Unauthorized, HmacValidationFailure.TimestampOutOfRange), (first, oneMinuteOld, failure));
        Assert.Single(logs.Find<HmacRequestValidator>(WideningDeferredEventId));
    }

    private static async Task<HttpStatusCode> SendWithClockOffsetAsync(SafetalkServer server, TimeSpan offset, CancellationToken cancellationToken)
    {
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { TimeProvider = new FakeTimeProvider(ServerNow + offset) });
        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync(
            "/api/whoami?offset=" + offset.TotalSeconds.ToString(CultureInfo.InvariantCulture),
            cancellationToken);

        return response.StatusCode;
    }

    private static IConfigurationRoot CreateConfiguration(bool replayProtection, string clockSkew) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Safetalk:AllowedClockSkew"] = clockSkew,
            ["Safetalk:EnableReplayProtection"] = replayProtection ? "true" : "false",
            ["Safetalk:Clients:partner-a"] = TestCredentials.Secret,
        })
        .Build();

    private static ServerSetup CreateServer(IConfigurationRoot configuration, LogCapture logs, bool replayCache = true) => new()
    {
        Configuration = configuration.GetSection("Safetalk"),
        TimeProvider = new FakeTimeProvider(ServerNow),
        Logs = logs,
        ConfigureHmac = replayCache
            ? hmac =>
            {
                // A recording cache; replay protection itself stays driven by configuration.
                hmac.Services.AddSingleton<IHmacReplayCache, RecordingReplayCache>();
            }
            : null,
    };
}
