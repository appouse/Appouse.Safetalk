using System.Collections.Concurrent;
using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Round 4: the validator no longer marks a request as verified; only the middleware and the <c>AddHmac()</c> scheme do,
/// after the <em>registered</em> <see cref="IHmacRequestValidator"/> succeeded. An application decorator that rejects a
/// partner whose signature is valid (IP allow-list, suspended partner, ...) must therefore win everywhere: in the
/// scheme, in the middleware that runs after it, and when the pipeline is re-executed for the error page.
/// </summary>
public sealed class DecoratingValidatorTests
{
    private static readonly ClientSetup PartnerB = new() { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret };

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task VerifiedButBlockedPartner_SchemeMiddlewareAndStatusCodeReExecution_IsRejectedWith401(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var decisions = new DecoratorDecisions();
        var servedPages = new ConcurrentQueue<string>();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                AddHmacAuthenticationScheme = true, // Default scheme: WebApplication authenticates before the middleware.
                ConfigureHmac = hmac => hmac.AddReplayProtection(),
                ConfigureServices = services => PartnerBlockingValidator.Decorate(services, TestCredentials.OtherClientId, decisions),
                ConfigurePipeline = app => app.UseStatusCodePagesWithReExecute("/errors/{0}"),
                ConfigureEndpoints = endpoints => MapErrorPage(endpoints, servedPages),
            },
            ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server);
        await using ServiceProvider partnerB = TestClientFactory.Create(server, PartnerB);
        SafetalkApiClient blocked = partnerB.GetRequiredService<SafetalkApiClient>();
        using var content = new ByteArrayContent(TestData.CreateBytes(2_000, seed: 3));

        using HttpResponseMessage whoAmI = await blocked.GetAsync("/api/whoami", ct);
        using HttpResponseMessage authorized = await blocked.GetAsync("/api/authorized/any-client", ct);
        using HttpResponseMessage raw = await blocked.PostAsync("/api/raw", content, ct);
        using HttpResponseMessage missingRoute = await blocked.GetAsync("/does/not/exist", ct);
        HmacValidationResult[] libraryResults = [.. server.ValidationResults];
        DecoratorDecision[] blockedDecisions = [.. decisions.All];
        WhoAmIResponse allowed = await partnerA.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        foreach (HttpResponseMessage response in new[] { whoAmI, authorized, raw, missingRoute })
        {
            response.AssertUnauthorized();
            Assert.DoesNotContain(TestCredentials.OtherClientId, await response.Content.ReadAsStringAsync(ct), StringComparison.Ordinal);
        }

        // No endpoint and no error page ran for the blocked partner (an error page would have revealed an attached client).
        Assert.Empty(servedPages);

        // The library verified every signature of the blocked partner (one verification per request: no replay)...
        Assert.NotEmpty(libraryResults);
        Assert.All(libraryResults, result => Assert.Equal((true, TestCredentials.OtherClientId), (result.Succeeded, result.ClientId)));

        // ...but every component asked the decorator and was refused: the scheme and the middleware for each request,
        // and the middleware again when the 401 was re-executed as an error page.
        Assert.All(blockedDecisions, decision => Assert.Equal(
            (false, HmacValidationFailure.UnknownClient, TestCredentials.OtherClientId),
            (decision.Result.Succeeded, decision.Result.Failure, decision.Result.ClientId)));
        Assert.True(blockedDecisions.Count(decision => decision.Path == "/api/whoami") >= 2, "The scheme and the middleware both asked the decorator.");
        Assert.Contains(blockedDecisions, decision => decision.Path == "/errors/401");

        // Control: the decorator lets other partners through, and the scheme + middleware still authenticate them.
        Assert.Equal((TestCredentials.ClientId, TestCredentials.ClientId), (allowed.ClientId, allowed.ClientIdClaim));
    }

    /// <summary>
    /// The scheme alone (the middleware protects nothing): a blocked partner is challenged on endpoints that require
    /// authorization and stays anonymous on the others, although its signature is valid.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task VerifiedButBlockedPartner_SchemeOnly_IsChallengedOnProtectedEndpoints_AndAnonymousElsewhere(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var decisions = new DecoratorDecisions();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                AddHmacAuthenticationScheme = true,
                ProtectOnly = _ => false,
                ConfigureHmac = hmac => hmac.AddReplayProtection(),
                ConfigureServices = services => PartnerBlockingValidator.Decorate(services, TestCredentials.OtherClientId, decisions),
            },
            ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server);
        await using ServiceProvider partnerB = TestClientFactory.Create(server, PartnerB);
        SafetalkApiClient blocked = partnerB.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage authorized = await blocked.GetAsync("/api/authorized/any-client", ct);
        using HttpResponseMessage anonymousEndpoint = await blocked.GetAsync("/api/whoami", ct);
        using HttpResponseMessage allowed = await partnerA.GetRequiredService<SafetalkApiClient>().GetAsync("/api/authorized/any-client", ct);

        authorized.AssertUnauthorized();
        WhoAmIResponse anonymous = await anonymousEndpoint.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal((null, false, null), (anonymous.ClientId, anonymous.IsAuthenticated, anonymous.ClientIdClaim));
        WhoAmIResponse partner = await allowed.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, partner.ClientId);
        Assert.All(
            decisions.All.Where(decision => decision.Result.ClientId == TestCredentials.OtherClientId),
            decision => Assert.False(decision.Result.Succeeded));
    }

    /// <summary>
    /// <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/> with the middleware and the scheme: the blocked partner is
    /// rejected on a marked endpoint and never attached to the request on an unmarked one.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task VerifiedButBlockedPartner_MarkedEndpointsOnly_IsRejectedOnMarkedEndpoints_AndNeverAttached(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var decisions = new DecoratorDecisions();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                AddHmacAuthenticationScheme = true,
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ConfigureServices = services => PartnerBlockingValidator.Decorate(services, TestCredentials.OtherClientId, decisions),
            },
            ct);
        await using ServiceProvider partnerB = TestClientFactory.Create(server, PartnerB);
        SafetalkApiClient blocked = partnerB.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage marked = await blocked.GetAsync("/api/partner/orders", ct);
        using HttpResponseMessage unmarked = await blocked.GetAsync("/api/whoami", ct);

        Assert.Equal((HttpStatusCode.Unauthorized, string.Empty), (marked.StatusCode, await marked.Content.ReadAsStringAsync(ct)));
        WhoAmIResponse anonymous = await unmarked.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal((null, false), (anonymous.ClientId, anonymous.IsAuthenticated));
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded)); // The signatures were valid.
    }

    private static void MapErrorPage(IEndpointRouteBuilder endpoints, ConcurrentQueue<string> servedPages)
        => endpoints.Map("/errors/{code:int}", (HttpContext context, int code) =>
        {
            string page = $"error-page {code} for {context.GetHmacClientId() ?? "anonymous"}";
            servedPages.Enqueue(page);
            return page;
        });
}
