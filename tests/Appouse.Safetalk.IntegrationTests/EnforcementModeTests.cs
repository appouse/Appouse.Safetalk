using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// <see cref="HmacServerOptions.EnforcementMode"/> and per-endpoint <see cref="IHmacValidationMetadata"/>: public and
/// partner endpoints in one application.
/// </summary>
public sealed class EnforcementModeTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MarkedEndpointsOnly_GroupWithRequireHmacValidation_RejectsUnsignedAndAcceptsSignedRequests(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, MarkedEndpointsOnly(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage unsignedResponse = await unsigned.GetAsync(new Uri("/b2b/orders", UriKind.Relative), ct);
        using HttpResponseMessage signedResponse = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/b2b/orders", ct);

        unsignedResponse.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.OK, signedResponse.StatusCode);
        Assert.Equal("b2b:partner-a", await signedResponse.Content.ReadAsStringAsync(ct));
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MarkedEndpointsOnly_PublicAndUnmarkedEndpoints_AreServedWithoutValidation(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, MarkedEndpointsOnly(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage ping = await unsigned.GetAsync(new Uri("/public/ping", UriKind.Relative), ct);
        using HttpResponseMessage whoAmIUnsigned = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage whoAmISigned = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);
        using HttpResponseMessage missingRoute = await unsigned.GetAsync(new Uri("/does/not/exist", UriKind.Relative), ct);

        Assert.Equal("pong", await ping.Content.ReadAsStringAsync(ct));
        Assert.Null((await whoAmIUnsigned.ReadOkJsonAsync<WhoAmIResponse>(ct)).ClientId);

        // A signature on an unmarked endpoint is neither required nor evaluated: no identity is attached.
        Assert.Null((await whoAmISigned.ReadOkJsonAsync<WhoAmIResponse>(ct)).ClientId);
        Assert.Equal(HttpStatusCode.NotFound, missingRoute.StatusCode);
        Assert.Empty(server.ValidationResults);
    }

    [Fact]
    public async Task AllRequests_UnsignedRequestToMissingRoute_IsRejected_WhileMarkedEndpointsOnlyReturns404()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer allRequests = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        await using SafetalkServer markedOnly = await SafetalkServer.StartAsync(TestHostKind.Kestrel, MarkedEndpointsOnly(), ct);
        using HttpClient toAllRequests = allRequests.CreateUnsignedClient();
        using HttpClient toMarkedOnly = markedOnly.CreateUnsignedClient();

        using HttpResponseMessage rejected = await toAllRequests.GetAsync(new Uri("/does/not/exist", UriKind.Relative), ct);
        using HttpResponseMessage notFound = await toMarkedOnly.GetAsync(new Uri("/does/not/exist", UriKind.Relative), ct);

        rejected.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.NotFound, notFound.StatusCode);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MarkedEndpointsOnly_EndpointSkipInsideRequiredGroup_WinsOverTheGroup(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, MarkedEndpointsOnly(), ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage status = await unsigned.GetAsync(new Uri("/b2b/status", UriKind.Relative), ct);
        using HttpResponseMessage nested = await unsigned.GetAsync(new Uri("/b2b/v2/open", UriKind.Relative), ct);
        using HttpResponseMessage nestedRequired = await unsigned.GetAsync(new Uri("/b2b/v2/closed", UriKind.Relative), ct);

        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        Assert.Equal(HttpStatusCode.OK, nested.StatusCode);
        nestedRequired.AssertUnauthorized();
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AllRequests_EndpointRequireInsideSkippedGroup_WinsOverTheGroup(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureEndpoints = MapGroups }, ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage open = await unsigned.GetAsync(new Uri("/public/ping", UriKind.Relative), ct);
        using HttpResponseMessage closed = await unsigned.GetAsync(new Uri("/public/partner-report", UriKind.Relative), ct);

        Assert.Equal(HttpStatusCode.OK, open.StatusCode);
        closed.AssertUnauthorized();
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, HmacEnforcementMode.AllRequests, "/api/partner/orders", HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.Kestrel, HmacEnforcementMode.AllRequests, "/api/partner/orders", HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.TestServer, HmacEnforcementMode.MarkedEndpointsOnly, "/api/partner/orders", HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.Kestrel, HmacEnforcementMode.MarkedEndpointsOnly, "/api/partner/orders", HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.TestServer, HmacEnforcementMode.AllRequests, "/api/partner/catalog", HttpStatusCode.OK)]
    [InlineData(TestHostKind.Kestrel, HmacEnforcementMode.AllRequests, "/api/partner/catalog", HttpStatusCode.OK)]
    [InlineData(TestHostKind.TestServer, HmacEnforcementMode.MarkedEndpointsOnly, "/api/partner/catalog", HttpStatusCode.OK)]
    [InlineData(TestHostKind.Kestrel, HmacEnforcementMode.MarkedEndpointsOnly, "/api/partner/catalog", HttpStatusCode.OK)]
    [InlineData(TestHostKind.TestServer, HmacEnforcementMode.AllRequests, "/api/catalog/items", HttpStatusCode.OK)]
    [InlineData(TestHostKind.Kestrel, HmacEnforcementMode.AllRequests, "/api/catalog/items", HttpStatusCode.OK)]
    [InlineData(TestHostKind.TestServer, HmacEnforcementMode.MarkedEndpointsOnly, "/api/catalog/items", HttpStatusCode.OK)]
    [InlineData(TestHostKind.Kestrel, HmacEnforcementMode.MarkedEndpointsOnly, "/api/catalog/items", HttpStatusCode.OK)]
    [InlineData(TestHostKind.TestServer, HmacEnforcementMode.AllRequests, "/api/catalog/prices", HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.Kestrel, HmacEnforcementMode.AllRequests, "/api/catalog/prices", HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.TestServer, HmacEnforcementMode.MarkedEndpointsOnly, "/api/catalog/prices", HttpStatusCode.Unauthorized)]
    [InlineData(TestHostKind.Kestrel, HmacEnforcementMode.MarkedEndpointsOnly, "/api/catalog/prices", HttpStatusCode.Unauthorized)]
    public async Task ControllerAttributes_ActionLevelMetadataWinsOverControllerLevel(TestHostKind kind, HmacEnforcementMode mode, string path, HttpStatusCode expected)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureOptions = options => options.EnforcementMode = mode },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri(path, UriKind.Relative), ct);

        Assert.Equal(expected, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MarkedEndpointsOnly_SignedRequestToRequiredControllerAction_IsAuthenticated(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, MarkedEndpointsOnly(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/catalog/prices", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await response.Content.ReadAsStringAsync(ct));
    }

    /// <summary>
    /// <see cref="RequireHmacValidationAttribute"/> is documented to "re-enable validation below a broader
    /// <see cref="SkipHmacValidationAttribute"/>" and the most specific metadata is documented to win. An action marked
    /// <c>[RequireHmacValidation]</c> must stay protected when all controllers are exempted with the broader
    /// <c>MapControllers().SkipHmacValidation()</c> convention.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AllRequests_MapControllersSkipConvention_ActionWithRequireHmacValidationAttribute_StaysProtected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureControllers = controllers => controllers.SkipHmacValidation() },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage exempt = await unsigned.GetAsync(new Uri("/api/catalog/items", UriKind.Relative), ct);
        using HttpResponseMessage markedAction = await unsigned.GetAsync(new Uri("/api/catalog/prices", UriKind.Relative), ct);
        using HttpResponseMessage markedController = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);

        // (action of a [SkipHmacValidation] controller, [RequireHmacValidation] action, [RequireHmacValidation] controller), UNSIGNED.
        Assert.Equal(
            (HttpStatusCode.OK, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized),
            (exempt.StatusCode, markedAction.StatusCode, markedController.StatusCode));
    }

    /// <summary>
    /// The mirror image: in <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/> mode, an action exempted with
    /// <c>[SkipHmacValidation]</c> stays public below a broader <c>MapControllers().RequireHmacValidation()</c>.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MarkedEndpointsOnly_MapControllersRequireConvention_ActionWithSkipHmacValidationAttribute_StaysPublic(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ConfigureControllers = controllers => controllers.RequireHmacValidation(),
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage marked = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);
        using HttpResponseMessage exemptAction = await unsigned.GetAsync(new Uri("/api/controller/orders/public", UriKind.Relative), ct);
        using HttpResponseMessage exemptController = await unsigned.GetAsync(new Uri("/api/catalog/items", UriKind.Relative), ct);

        // (action of a [RequireHmacValidation] controller, [SkipHmacValidation] action, [SkipHmacValidation] controller), UNSIGNED.
        Assert.Equal(
            (HttpStatusCode.Unauthorized, HttpStatusCode.OK, HttpStatusCode.OK),
            (marked.StatusCode, exemptAction.StatusCode, exemptController.StatusCode));
    }

    /// <summary>
    /// A value outside the enum (for example cast from an integer in code) fails options validation at start-up
    /// instead of silently selecting either mode.
    /// </summary>
    [Theory]
    [InlineData(2)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public async Task UndefinedEnforcementMode_FailsAtStartup(int value)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;

        Microsoft.Extensions.Options.OptionsValidationException exception = await Assert.ThrowsAsync<Microsoft.Extensions.Options.OptionsValidationException>(
            () => SafetalkServer.StartAsync(
                TestHostKind.TestServer,
                new ServerSetup { ConfigureOptions = options => options.EnforcementMode = (HmacEnforcementMode)value },
                ct));

        Assert.Contains("EnforcementMode must be AllRequests or MarkedEndpointsOnly.", exception.Failures);
    }

    private static ServerSetup MarkedEndpointsOnly() => new()
    {
        ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
        ConfigureEndpoints = MapGroups,
    };

    private static void MapGroups(IEndpointRouteBuilder endpoints)
    {
        RouteGroupBuilder b2b = endpoints.MapGroup("/b2b").RequireHmacValidation();
        b2b.MapGet("/orders", (HttpContext context) => "b2b:" + context.GetHmacClientId());
        b2b.MapGet("/status", () => "up").SkipHmacValidation();

        RouteGroupBuilder v2 = b2b.MapGroup("/v2").SkipHmacValidation();
        v2.MapGet("/open", () => "open");
        v2.MapGet("/closed", () => "closed").RequireHmacValidation();

        RouteGroupBuilder publicGroup = endpoints.MapGroup("/public").SkipHmacValidation();
        publicGroup.MapGet("/ping", () => "pong");
        publicGroup.MapGet("/partner-report", (HttpContext context) => "report:" + context.GetHmacClientId()).RequireHmacValidation();
    }
}
