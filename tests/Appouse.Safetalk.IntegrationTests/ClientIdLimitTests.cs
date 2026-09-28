using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// <c>X-Client-Id</c> is at most <see cref="SafetalkHeaderNames.MaxClientIdLength"/> printable ASCII characters. Other
/// values are rejected as unknown clients before the secret store is queried, and never reach the logs.
/// </summary>
public sealed class ClientIdLimitTests
{
    public static TheoryData<TestHostKind, int> OversizedLengths => Combine(SafetalkHeaderNames.MaxClientIdLength + 1, 300, 8_000);

    /// <summary>Printable ASCII is 0x20..0x7E; HTAB and DEL are legal in HTTP header values but not in a client id.</summary>
    public static TheoryData<TestHostKind, string> NonPrintableClientIds => Combine("partner\ta", "partner-a\u007F", "\u007Fpartner-a");

    [Theory]
    [MemberData(nameof(OversizedLengths))]
    public async Task OversizedClientId_IsRejectedAsUnknownClient_WithoutQueryingTheSecretProvider(TestHostKind kind, int length)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithDatabaseSecrets(lookups, logs), ct);
        string clientId = CreateClientId(length);

        using HttpResponseMessage response = await SendManuallySignedAsync(server, clientId, ct);

        response.AssertUnauthorized();
        AssertRejectedWithoutLookup(server, lookups, logs, clientId);
    }

    [Theory]
    [MemberData(nameof(NonPrintableClientIds))]
    public async Task NonPrintableClientId_IsRejectedAsUnknownClient_WithoutQueryingTheSecretProvider(TestHostKind kind, string clientId)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithDatabaseSecrets(lookups, logs), ct);

        using HttpResponseMessage response = await SendManuallySignedAsync(server, clientId, ct);

        response.AssertUnauthorized();
        AssertRejectedWithoutLookup(server, lookups, logs, clientId);
    }

    /// <summary>
    /// Non-ASCII bytes are refused by Kestrel and by <see cref="HttpClient"/> themselves; the in-memory TestServer hands
    /// the decoded value to the validator, which must reject it on its own.
    /// </summary>
    [Theory]
    [InlineData("partner-ä")]
    [InlineData("partner-a​")]
    [InlineData("müşteri")]
    public async Task NonAsciiClientId_ReachingTheValidator_IsRejectedWithoutQueryingTheSecretProvider(string clientId)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.TestServer, WithDatabaseSecrets(lookups, logs), ct);

        using HttpResponseMessage response = await SendManuallySignedAsync(server, clientId, ct);

        response.AssertUnauthorized();
        AssertRejectedWithoutLookup(server, lookups, logs, clientId);
    }

    /// <summary>
    /// A malformed identifier is not echoed as the claimed client even when the request fails earlier (missing headers).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task OversizedClientId_WithMissingSignature_IsNotReportedAsTheClaimedClient(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithDatabaseSecrets(lookups, logs), ct);
        using HttpClient client = server.CreateUnsignedClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/whoami", UriKind.Relative));
        request.Headers.TryAddWithoutValidation(SafetalkHeaderNames.ClientId, CreateClientId(300));
        request.Headers.TryAddWithoutValidation(SafetalkHeaderNames.Timestamp, "1");

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        response.AssertUnauthorized();
        HmacValidationResult result = Assert.Single(server.ValidationResults);
        Assert.Equal((HmacValidationFailure.MissingHeaders, (string?)null), (result.Failure, result.ClientId));
        Assert.Null(Assert.Single(logs.Find<HmacRequestValidator>(eventId: 2)).GetValue("ClientId"));
        Assert.Empty(lookups.Lookups);
    }

    /// <summary>
    /// Exactly 256 characters is still a well-formed identifier: the provider is asked (and does not know it).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClientIdOfMaximumLength_IsLookedUp(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithDatabaseSecrets(lookups, logs), ct);
        string clientId = CreateClientId(SafetalkHeaderNames.MaxClientIdLength);

        using HttpResponseMessage response = await SendManuallySignedAsync(server, clientId, ct);

        response.AssertUnauthorized();
        HmacValidationResult result = Assert.Single(server.ValidationResults);
        Assert.Equal((HmacValidationFailure.UnknownClient, clientId), (result.Failure, result.ClientId));
        Assert.Equal(clientId, Assert.Single(lookups.Lookups).ClientId);
    }

    /// <summary>
    /// End to end with the real client: a registered client whose identifier has the maximum length authenticates.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RegisteredClientIdOfMaximumLength_Authenticates(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        string clientId = CreateClientId(SafetalkHeaderNames.MaxClientIdLength);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddInMemorySecrets([new(clientId, TestCredentials.OtherSecret)]) },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { ClientId = clientId, Secret = TestCredentials.OtherSecret });

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(clientId, whoAmI.ClientId);
        Assert.Equal(clientId, whoAmI.ClientIdClaim);
    }

    /// <summary>
    /// The client refuses to send an identifier the server would reject, before anything goes on the wire.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClientConfiguredWithOversizedClientId_FailsOptionsValidation_BeforeSending(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { ClientId = CreateClientId(SafetalkHeaderNames.MaxClientIdLength + 1) });

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(
            () => clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct));

        Assert.Contains(
            "ClientId must consist of at most 256 printable ASCII characters without leading or trailing whitespace.",
            exception.Failures);
        Assert.Empty(server.ValidationResults);
    }

    private static void AssertRejectedWithoutLookup(SafetalkServer server, SecretLookupLog lookups, LogCapture logs, string clientId)
    {
        HmacValidationResult result = Assert.Single(server.ValidationResults);
        Assert.Equal((HmacValidationFailure.UnknownClient, (string?)null), (result.Failure, result.ClientId));
        Assert.Empty(lookups.Lookups);

        // The attacker-chosen value is neither logged as the client nor anywhere in the message.
        CapturedLog rejected = Assert.Single(logs.Find<HmacRequestValidator>(eventId: 2));
        Assert.Null(rejected.GetValue("ClientId"));
        Assert.DoesNotContain(clientId, rejected.Message, StringComparison.Ordinal);
    }

    private static async Task<HttpResponseMessage> SendManuallySignedAsync(SafetalkServer server, string clientId, CancellationToken cancellationToken)
    {
        using HttpClient client = server.CreateUnsignedClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/whoami", UriKind.Relative));
        foreach ((string name, string value) in ManualSigner.CreateHeaders("GET", "/api/whoami", [], clientId))
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        return await client.SendAsync(request, cancellationToken);
    }

    /// <summary>A printable, realistic-looking identifier of exactly <paramref name="length"/> characters.</summary>
    private static string CreateClientId(int length)
        => string.Concat(Enumerable.Repeat("partner-", (length / 8) + 1))[..length];

    private static ServerSetup WithDatabaseSecrets(SecretLookupLog lookups, LogCapture logs) => new()
    {
        Logs = logs,
        ConfigureHmac = hmac => hmac.AddSecretProvider<DatabaseSecretProvider>(),
        ConfigureServices = services =>
        {
            services.AddScoped<ClientSecretsDbContext>();
            services.AddSingleton(lookups);
        },
    };

    private static TheoryData<TestHostKind, T> Combine<T>(params T[] values)
    {
        var data = new TheoryData<TestHostKind, T>();
        foreach (TestHostKind kind in Enum.GetValues<TestHostKind>())
        {
            foreach (T value in values)
            {
                data.Add(kind, value);
            }
        }

        return data;
    }
}
