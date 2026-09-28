using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The <c>X-Timestamp</c> produced by the client clock must be within <see cref="HmacServerOptions.AllowedClockSkew"/>
/// (±5 minutes by default) of the server clock.
/// </summary>
public sealed class ClockSkewTests
{
    private static readonly DateTimeOffset ServerNow = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    public static TheoryData<TestHostKind, int> OffsetsWithinDefaultTolerance => Combine(-300, -299, -1, 0, 1, 299, 300);

    public static TheoryData<TestHostKind, int> OffsetsBeyondDefaultTolerance => Combine(-301, 301, -3_600, 3_600, -86_400);

    [Theory]
    [MemberData(nameof(OffsetsWithinDefaultTolerance))]
    public async Task ClientClockOffsetWithinFiveMinutes_IsAccepted(TestHostKind kind, int offsetSeconds)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { TimeProvider = new FakeTimeProvider(ServerNow) }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(ServerNow.AddSeconds(offsetSeconds)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse whoAmI = await client.GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    [Theory]
    [MemberData(nameof(OffsetsBeyondDefaultTolerance))]
    public async Task ClientClockOffsetBeyondFiveMinutes_IsRejected(TestHostKind kind, int offsetSeconds)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { TimeProvider = new FakeTimeProvider(ServerNow) }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(ServerNow.AddSeconds(offsetSeconds)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ExpiredTimestamp_FakeClientClockBehindRealServerClock_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow.AddMinutes(-6)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task FutureTimestamp_FakeClientClockAheadOfRealServerClock_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow.AddMinutes(6)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SlightlySkewedFakeClientClock_AgainstRealServerClock_IsAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow.AddMinutes(-4)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse whoAmI = await client.GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task FakeServerClockAheadOfRealClientClock_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow.AddMinutes(6)) },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, 30, HttpStatusCode.OK)]
    [InlineData(TestHostKind.Kestrel, 30, HttpStatusCode.OK)]
    [InlineData(TestHostKind.TestServer, -30, HttpStatusCode.OK)]
    [InlineData(TestHostKind.Kestrel, -30, HttpStatusCode.OK)]
    [InlineData(TestHostKind.TestServer, 31, HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.Kestrel, 31, HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.TestServer, -31, HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.Kestrel, -31, HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.TestServer, 120, HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.Kestrel, 120, HttpStatusCode.Unauthorized)]
    public async Task CustomAllowedClockSkew_IsEnforced(TestHostKind kind, int offsetSeconds, HttpStatusCode expected)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                TimeProvider = new FakeTimeProvider(ServerNow),
                ConfigureOptions = options => options.AllowedClockSkew = TimeSpan.FromSeconds(30),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(ServerNow.AddSeconds(offsetSeconds)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        Assert.Equal(expected, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ServerClockAdvancingPastTheWindow_RejectsTheSameClientClock(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var serverClock = new FakeTimeProvider(ServerNow);
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { TimeProvider = serverClock }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { TimeProvider = new FakeTimeProvider(ServerNow) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage fresh = await client.GetAsync("/api/whoami", ct);
        serverClock.Advance(TimeSpan.FromSeconds(300));
        using HttpResponseMessage atBoundary = await client.GetAsync("/api/whoami", ct);
        serverClock.Advance(TimeSpan.FromSeconds(1));
        using HttpResponseMessage expired = await client.GetAsync("/api/whoami", ct);

        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
        Assert.Equal(HttpStatusCode.OK, atBoundary.StatusCode);
        expired.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    private static TheoryData<TestHostKind, int> Combine(params int[] offsets)
    {
        var data = new TheoryData<TestHostKind, int>();
        foreach (TestHostKind host in Enum.GetValues<TestHostKind>())
        {
            foreach (int offset in offsets)
            {
                data.Add(host, offset);
            }
        }

        return data;
    }
}
