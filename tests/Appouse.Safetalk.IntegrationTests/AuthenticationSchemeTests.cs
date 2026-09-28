using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The <c>AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac()</c> scheme with
/// <c>[Authorize]</c>/<c>RequireAuthorization()</c>, on its own and together with <c>UseHmacAuthentication()</c>.
/// </summary>
public sealed class AuthenticationSchemeTests
{
    /// <summary>
    /// The scheme alone (the middleware protects nothing here) authenticates signed requests for authorization.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeWithoutMiddleware_SignedRequest_IsAuthenticatedAndAuthorized(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, SchemeOnly(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/partner-a-only", ct);

        WhoAmIResponse whoAmI = await response.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
        Assert.True(whoAmI.IsAuthenticated);
        Assert.Equal(TestCredentials.ClientId, whoAmI.UserName);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientIdClaim);
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeWithoutMiddleware_UnsignedRequestToProtectedEndpoint_IsChallengedWith401(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, SchemeOnly(), ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/authorized/any-client", UriKind.Relative), ct);

        response.AssertUnauthorized();
        Assert.Empty(server.ValidationResults); // No HMAC header: NoResult, nothing validated.
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeWithoutMiddleware_UnsignedRequestToAnonymousEndpoint_IsServed(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, SchemeOnly(), ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);

        WhoAmIResponse whoAmI = await response.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.False(whoAmI.IsAuthenticated);
        Assert.Null(whoAmI.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeWithoutMiddleware_InvalidSignatureToProtectedEndpoint_IsChallengedWith401(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, SchemeOnly(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { Secret = "not-the-shared-secret" });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/any-client", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeWithoutMiddleware_AuthenticatedClientFailingPolicy_IsForbiddenWith403(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, SchemeOnly(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/partner-a-only", ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeWithoutMiddleware_WithReplayProtection_ReplayIsChallengedWith401(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { AddHmacAuthenticationScheme = true, ProtectOnly = _ => false, ConfigureHmac = hmac => hmac.AddReplayProtection() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });

        using HttpResponseMessage original = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/any-client", ct);
        using HttpClient attacker = server.CreateUnsignedClient();
        using HttpRequestMessage replay = Assert.Single(capture.Requests).ToRequestMessage();
        using HttpResponseMessage replayed = await attacker.SendAsync(replay, ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        replayed.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
    }

    /// <summary>
    /// MarkedEndpointsOnly: an endpoint protected by authorization but not marked for the middleware is authenticated
    /// by the scheme, and an unsigned request is challenged by the scheme (401 with the HMAC challenge).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MarkedEndpointsOnlyWithScheme_AuthorizedEndpointNotMarked_IsProtectedByTheScheme(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                AddHmacAuthenticationScheme = true,
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage unsignedResponse = await unsigned.GetAsync(new Uri("/api/authorized/any-client", UriKind.Relative), ct);
        using HttpResponseMessage signedResponse = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/any-client", ct);

        unsignedResponse.AssertUnauthorized();
        WhoAmIResponse whoAmI = await signedResponse.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    /// <summary>
    /// Scheme and middleware together with replay protection: a valid request is verified once and not reported as its
    /// own replay by the second component.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeAndMiddleware_WithReplayProtection_ValidRequestIsVerifiedOnce(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { AddHmacAuthenticationScheme = true, ConfigureHmac = hmac => hmac.AddReplayProtection() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new ByteArrayContent(TestData.CreateBytes(10_000));

        using HttpResponseMessage authorized = await client.GetAsync("/api/authorized/any-client", ct);
        using HttpResponseMessage plain = await client.PostAsync("/api/raw?n=2", content, ct);

        Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);
        RawBodyResponse body = await plain.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(10_000, body.Length);
        Assert.Equal(2, server.ValidationResults.Count);
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    /// <summary>
    /// The README states that when the scheme and the middleware are used together "the same request is not validated
    /// twice", whether it succeeds or fails. The authentication handler (auto-added <c>UseAuthentication</c>, default
    /// scheme) validates first; the middleware then asks the validator again, which answers from the result it
    /// remembered for the request: one secret lookup, one actual verification (one rejection logged).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeAndMiddleware_RejectedRequest_IsValidatedOnlyOnce(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                AddHmacAuthenticationScheme = true,
                Logs = logs,
                ConfigureHmac = hmac => hmac.AddSecretProvider<DatabaseSecretProvider>(),
                ConfigureServices = services =>
                {
                    services.AddScoped<ClientSecretsDbContext>();
                    services.AddSingleton(lookups);
                },
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { Secret = "not-the-shared-secret" });

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();

        // Both components got the same answer (the second call is served from the remembered result)...
        Assert.Equal(2, server.ValidationResults.Count);
        Assert.All(server.ValidationResults, result => Assert.Equal(
            (false, HmacValidationFailure.InvalidSignature, TestCredentials.ClientId),
            (result.Succeeded, result.Failure, result.ClientId)));

        // ...but the request was verified once: (secret lookups, "Rejected" log entries of the validator).
        Assert.Equal((1, 1), (lookups.Lookups.Count, logs.Find<HmacRequestValidator>(eventId: 2).Length));
    }

    /// <summary>
    /// With several schemes (no automatic default), the middleware verifies first and a policy naming the HMAC scheme
    /// invokes the handler afterwards: the handler reuses the middleware's verification instead of validating again,
    /// which with replay protection would otherwise reject the request as its own replay.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PolicyNamingTheHmacScheme_AfterTheMiddleware_ReusesItsVerification_WithReplayProtection(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, PolicyWithExplicitHmacScheme(), ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server);
        await using ServiceProvider partnerB = TestClientFactory.Create(server, new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });

        using HttpResponseMessage allowed = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/scheme/partner-a", ct);
        using HttpResponseMessage forbidden = await partnerB.GetRequiredService<SafetalkApiClient>().GetAsync("/scheme/partner-a", ct);

        Assert.Equal("scheme:partner-a", await allowed.Content.ReadAsStringAsync(ct));
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        Assert.Equal(2, server.ValidationResults.Count); // One per request: the middleware's.
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    private static ServerSetup SchemeOnly() => new() { AddHmacAuthenticationScheme = true, ProtectOnly = _ => false };

    private static ServerSetup PolicyWithExplicitHmacScheme() => new()
    {
        ConfigureHmac = hmac => hmac.AddReplayProtection(),
        ConfigureServices = services =>
        {
            // Two schemes: no automatic default scheme, so only the policy below invokes the HMAC handler.
            services.AddAuthentication().AddHmac().AddHmac("HMAC-Secondary", configureOptions: null);
            services.AddAuthorization(options => options.AddPolicy("PartnerAViaScheme", policy => policy
                .AddAuthenticationSchemes(HmacAuthenticationDefaults.AuthenticationScheme)
                .RequireClaim(HmacAuthenticationDefaults.ClientIdClaimType, TestCredentials.ClientId)));
        },
        ConfigureEndpoints = endpoints => endpoints
            .MapGet("/scheme/partner-a", (HttpContext context) => "scheme:" + context.User.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value)
            .RequireAuthorization("PartnerAViaScheme"),
    };
}
