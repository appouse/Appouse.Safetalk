using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The server sample and the README's authorization section combined: <c>AddHmacServer(IConfiguration)</c> with the
/// sample's <c>Safetalk</c> section (replay protection on), <c>AddProblemDetails()</c>,
/// <c>AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac()</c>, a policy on the <c>client_id</c>
/// claim, and an explicit <c>UseAuthorization()</c> right after <c>UseHmacAuthentication()</c>.
/// </summary>
public sealed class SampleSetupTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PartnerPolicy_RightPartnerGets200_WrongPartnerGets403_UnsignedGets401(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, SampleLikeServer(), ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server);
        await using ServiceProvider partnerB = TestClientFactory.Create(server, new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage right = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/partner-a-only", ct);
        using HttpResponseMessage wrong = await partnerB.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/partner-a-only", ct);
        HmacValidationResult[] signedResults = [.. server.ValidationResults];
        using HttpResponseMessage anonymous = await unsigned.GetAsync(new Uri("/api/authorized/partner-a-only", UriKind.Relative), ct);
        using HttpResponseMessage health = await unsigned.GetAsync(new Uri("/health", UriKind.Relative), ct);

        WhoAmIResponse whoAmI = await right.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal((TestCredentials.ClientId, TestCredentials.ClientId, true), (whoAmI.ClientId, whoAmI.ClientIdClaim, whoAmI.IsAuthenticated));
        Assert.Equal(HttpStatusCode.Forbidden, wrong.StatusCode);
        Assert.Empty(wrong.Headers.WwwAuthenticate);
        anonymous.AssertUnauthorized();
        Assert.Equal("application/problem+json", anonymous.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);

        // With replay protection on, the scheme and the middleware share one verification per signed request: neither
        // the right nor the wrong partner is reported as a replay of itself.
        Assert.Equal(
            new[] { (true, TestCredentials.ClientId), (true, TestCredentials.OtherClientId) },
            signedResults.Select(result => (result.Succeeded, result.ClientId!)));
    }

    /// <summary>
    /// A captured request of the right partner, replayed verbatim, is rejected: replay protection from the sample's
    /// configuration is active behind the authentication scheme.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PartnerPolicy_ReplayOfTheRightPartnersRequest_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, SampleLikeServer(), ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });

        using HttpResponseMessage original = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/partner-a-only", ct);
        using HttpClient attacker = server.CreateUnsignedClient();
        using HttpRequestMessage replay = Assert.Single(capture.Requests).ToRequestMessage();
        using HttpResponseMessage replayed = await attacker.SendAsync(replay, ct);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        replayed.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.ReplayDetected, server.LastFailure);
    }

    /// <summary>
    /// The same sample-like application running exactly what the library registers (the validator by type, no test
    /// wrapper) on a Development host with build and scope validation: every documented outcome is unchanged.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PartnerPolicy_WithTheLibraryRegistrationUnwrapped_BehavesAsDocumented(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, SampleLikeServer(recordValidationResults: false), ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        await using ServiceProvider partnerB = TestClientFactory.Create(server, new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage right = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/partner-a-only", ct);
        using HttpResponseMessage wrong = await partnerB.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/partner-a-only", ct);
        using HttpResponseMessage anonymous = await unsigned.GetAsync(new Uri("/api/authorized/partner-a-only", UriKind.Relative), ct);
        using HttpResponseMessage health = await unsigned.GetAsync(new Uri("/health", UriKind.Relative), ct);
        using HttpRequestMessage replay = Assert.Single(capture.Requests).ToRequestMessage();
        using HttpResponseMessage replayed = await unsigned.SendAsync(replay, ct);

        WhoAmIResponse whoAmI = await right.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal((TestCredentials.ClientId, TestCredentials.ClientId, true), (whoAmI.ClientId, whoAmI.ClientIdClaim, whoAmI.IsAuthenticated));
        Assert.Equal(HttpStatusCode.Forbidden, wrong.StatusCode);
        anonymous.AssertUnauthorized();
        Assert.Equal("application/problem+json", anonymous.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        replayed.AssertUnauthorized();
        Assert.Equal("application/problem+json", replayed.Content.Headers.ContentType?.MediaType);
    }

    private static ServerSetup SampleLikeServer(bool recordValidationResults = true)
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Safetalk:AllowedClockSkew"] = "00:05:00",
                ["Safetalk:MaxBodySize"] = "1048576",
                ["Safetalk:EnableReplayProtection"] = "true",
                ["Safetalk:EnforcementMode"] = "AllRequests",
                ["Safetalk:Clients:partner-a"] = TestCredentials.Secret,
                ["Safetalk:Clients:partner-b"] = TestCredentials.OtherSecret,
            })
            .Build();

        // The harness registers the PartnerAOnly policy and calls UseAuthorization() right after UseHmacAuthentication().
        return new ServerSetup
        {
            Configuration = configuration.GetSection("Safetalk"),
            AddHmacAuthenticationScheme = true,
            UseProblemDetails = true,
            RecordValidationResults = recordValidationResults,
        };
    }
}
