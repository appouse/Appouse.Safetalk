using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Endpoint metadata is only visible when the HMAC middleware runs after routing. When <c>UseRouting()</c> is
/// registered after <c>UseHmacAuthentication()</c>, the middleware cannot tell public from protected endpoints: it
/// validates every request (fail closed) and logs a warning, instead of letting <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/>
/// open every endpoint.
/// </summary>
public sealed class RoutingOrderTests
{
    private const int RoutingRegisteredAfterMiddlewareEventId = 10;

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseRoutingAfterTheMiddleware_MarkedEndpointsOnly_UnsignedRequestsToPublicEndpointsAreRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                Logs = logs,
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ConfigurePipelineAfterHmac = app => app.UseRouting(),
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage unmarked = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage skippedEndpoint = await unsigned.GetAsync(new Uri("/health", UriKind.Relative), ct);
        using HttpResponseMessage skippedController = await unsigned.GetAsync(new Uri("/api/catalog/items", UriKind.Relative), ct);
        using HttpResponseMessage required = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);

        unmarked.AssertUnauthorized();
        skippedEndpoint.AssertUnauthorized();
        skippedController.AssertUnauthorized();
        required.AssertUnauthorized();
        Assert.All(server.ValidationResults, result => Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure));
        CapturedLog warning = Assert.Single(logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterMiddlewareEventId));
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Warning, warning.Level);
    }

    /// <summary>
    /// Fail closed does not mean fail: signed requests are still verified and authenticated, and the identity reaches
    /// the endpoint.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseRoutingAfterTheMiddleware_SignedRequests_AreAuthenticated(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ConfigurePipelineAfterHmac = app => app.UseRouting(),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse whoAmI = await client.GetWhoAmIAsync(ct);
        using HttpResponseMessage partnerOrders = await client.GetAsync("/api/partner/orders", ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
        Assert.Equal(TestCredentials.ClientId, await partnerOrders.Content.ReadAsStringAsync(ct));
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    /// <summary>
    /// Control: explicit routing registered before the middleware (and WebApplication's implicit routing) keep the
    /// metadata, and no warning is logged.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, true)]
    [InlineData(TestHostKind.TestServer, false)]
    [InlineData(TestHostKind.Kestrel, true)]
    [InlineData(TestHostKind.Kestrel, false)]
    public async Task UseRoutingBeforeTheMiddlewareOrImplicit_MarkedEndpointsOnly_PublicEndpointsStayPublic(TestHostKind kind, bool explicitRouting)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                Logs = logs,
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ConfigurePipeline = explicitRouting ? app => app.UseRouting() : null,
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage unmarked = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage required = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);

        Assert.Equal(HttpStatusCode.OK, unmarked.StatusCode);
        required.AssertUnauthorized();
        Assert.Empty(logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterMiddlewareEventId));
    }

    /// <summary>
    /// The README suggests branching with <c>UseWhen(..., b => b.UseHmacAuthentication())</c>. When routing is
    /// registered on the main pipeline after that branch, the branch runs before routing exactly like the unbranched
    /// middleware above, so it must fail closed as well: an unsigned request to a <c>[RequireHmacValidation]</c>
    /// controller must not be served.
    /// </summary>
    /// <remarks>
    /// Inside a branch the routing order cannot be determined when the pipeline is built (round 4: "Unknown"), so the
    /// misconfiguration is only reported at run time, once, after a request that passed the middleware shows that an
    /// endpoint was selected <em>after</em> it. A rejected request never reaches routing and proves nothing.
    /// </remarks>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseWhenBranchBeforeUseRouting_MarkedEndpointsOnly_UnsignedRequestToRequiredEndpointIsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                Logs = logs,
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ProtectOnly = context => context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase),
                ConfigurePipelineAfterHmac = app => app.UseRouting(),
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient signed = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage required = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);
        CapturedLog[] logsAfterRejection = logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterMiddlewareEventId);
        using HttpResponseMessage firstSigned = await signed.GetAsync("/api/partner/orders", ct);
        using HttpResponseMessage unmarkedUnsigned = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage secondSigned = await signed.GetAsync("/api/partner/orders", ct);

        // (status, served body): "anonymous" would mean the protected controller action ran for an unsigned caller.
        Assert.Equal(
            (HttpStatusCode.Unauthorized, string.Empty),
            (required.StatusCode, await required.Content.ReadAsStringAsync(ct)));
        Assert.Empty(logsAfterRejection);

        // Fail closed also for an unmarked endpoint: its metadata is not visible before routing.
        unmarkedUnsigned.AssertUnauthorized();

        Assert.Equal(TestCredentials.ClientId, await firstSigned.Content.ReadAsStringAsync(ct));
        Assert.Equal(TestCredentials.ClientId, await secondSigned.Content.ReadAsStringAsync(ct));

        // Reported once, at run time, by the first request that reached routing behind the branch.
        CapturedLog warning = Assert.Single(logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterMiddlewareEventId));
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Warning, warning.Level);
    }

    /// <summary>
    /// The README's <c>UseWhen</c> branch on a <c>WebApplication</c> without explicit routing: implicit routing runs in
    /// front of the whole pipeline, so selected endpoints keep their metadata inside the branch. The branch cannot know
    /// that, so a request for which no endpoint was selected is validated in every mode (fail closed): an unmatched
    /// route under the branch gets 401 instead of 404. Nothing is logged, because the endpoint was never selected
    /// after the middleware.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseWhenBranchWithImplicitRouting_MarkedEndpointsOnly_HonoursMetadata_AndUnmatchedRoutesFailClosed(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                Logs = logs,
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ProtectOnly = context => context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase),
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient signed = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage unmarked = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage required = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);
        using HttpResponseMessage unmatchedInBranch = await unsigned.GetAsync(new Uri("/api/does-not-exist", UriKind.Relative), ct);
        using HttpResponseMessage unmatchedOutsideBranch = await unsigned.GetAsync(new Uri("/elsewhere/does-not-exist", UriKind.Relative), ct);
        using HttpResponseMessage signedRequired = await signed.GetAsync("/api/partner/orders", ct);
        using HttpResponseMessage signedUnmatched = await signed.GetAsync("/api/does-not-exist", ct);

        WhoAmIResponse anonymous = await unmarked.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Null(anonymous.ClientId);
        required.AssertUnauthorized();
        unmatchedInBranch.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.NotFound, unmatchedOutsideBranch.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await signedRequired.Content.ReadAsStringAsync(ct));
        Assert.Equal(HttpStatusCode.NotFound, signedUnmatched.StatusCode); // Verified, then no route matched.
        Assert.Empty(logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterMiddlewareEventId));
    }

    /// <summary>
    /// Trying to break the run-time detection: routing does run first here (implicit), but a signed request to an
    /// unmatched route under the branch is re-executed by <c>UseStatusCodePagesWithReExecute</c> placed after the
    /// branch, which re-routes to the error page. The endpoint that exists when the middleware's next delegate returns
    /// was selected by the re-execution, not by a routing middleware registered after the HMAC middleware, so the
    /// "registered before UseRouting()" warning must not be logged.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseWhenBranchWithImplicitRouting_ErrorPageReExecutedAfterTheBranch_DoesNotReportRoutingAfterTheMiddleware(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                Logs = logs,
                ProtectOnly = context => context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase),
                ConfigurePipelineAfterHmac = app => app.UseStatusCodePagesWithReExecute("/errors/{0}"),
                ConfigureEndpoints = endpoints => endpoints.Map("/errors/{code:int}", (int code) => $"error-page {code}"),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage missing = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/does-not-exist", ct);

        Assert.Equal((HttpStatusCode.NotFound, "error-page 404"), (missing.StatusCode, await missing.Content.ReadAsStringAsync(ct)));

        // The logged messages are the evidence on failure.
        Assert.Equal(
            Array.Empty<string>(),
            logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterMiddlewareEventId).Select(entry => $"{entry.Level}: {entry.Message}"));
    }

    /// <summary>
    /// The README's remedy for the 401-instead-of-404 behaviour of a branch: call <c>UseRouting()</c> before it. The
    /// branch then knows routing ran first, and an unmatched route is a plain 404 in
    /// <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/> mode.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseWhenBranchAfterExplicitUseRouting_MarkedEndpointsOnly_UnmatchedRouteIs404(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var logs = new LogCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                Logs = logs,
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ConfigurePipeline = app => app.UseRouting(),
                ProtectOnly = context => context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase),
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage unmarked = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage required = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);
        using HttpResponseMessage unmatched = await unsigned.GetAsync(new Uri("/api/does-not-exist", UriKind.Relative), ct);

        Assert.Equal(HttpStatusCode.OK, unmarked.StatusCode);
        required.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.NotFound, unmatched.StatusCode);
        Assert.Equal(HmacValidationFailure.MissingHeaders, Assert.Single(server.ValidationResults).Failure); // Only the marked endpoint.
        Assert.Empty(logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterMiddlewareEventId));
    }

    /// <summary>
    /// Manual registration (<c>UseMiddleware&lt;HmacAuthenticationMiddleware&gt;()</c>, public constructor) cannot know
    /// the routing order either: selected endpoints keep their metadata, requests without an endpoint are validated.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseMiddlewareRegistration_MarkedEndpointsOnly_HonoursMetadata_AndUnmatchedRoutesFailClosed(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ProtectOnly = _ => false, // The harness's own registration never runs.
                ConfigurePipelineAfterHmac = app => app.UseMiddleware<HmacAuthenticationMiddleware>(),
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage unmarked = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage required = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);
        using HttpResponseMessage unmatched = await unsigned.GetAsync(new Uri("/does-not-exist", UriKind.Relative), ct);
        using HttpResponseMessage signedRequired = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/partner/orders", ct);

        Assert.Equal(HttpStatusCode.OK, unmarked.StatusCode);
        required.AssertUnauthorized();
        unmatched.AssertUnauthorized();
        Assert.Equal(TestCredentials.ClientId, await signedRequired.Content.ReadAsStringAsync(ct));
    }

    /// <summary>
    /// Manual registration in front of an explicit <c>UseRouting()</c>: no request ever has an endpoint at the
    /// middleware, so every request is validated, including endpoints marked <c>SkipHmacValidation()</c> (fail closed).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseMiddlewareBeforeUseRouting_MarkedEndpointsOnly_ValidatesEveryRequest(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ProtectOnly = _ => false,
                ConfigurePipelineAfterHmac = app =>
                {
                    app.UseMiddleware<HmacAuthenticationMiddleware>();
                    app.UseRouting();
                },
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage unmarked = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage skipped = await unsigned.GetAsync(new Uri("/health", UriKind.Relative), ct);
        WhoAmIResponse signed = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        unmarked.AssertUnauthorized();
        skipped.AssertUnauthorized();
        Assert.Equal(TestCredentials.ClientId, signed.ClientId);
    }
}
