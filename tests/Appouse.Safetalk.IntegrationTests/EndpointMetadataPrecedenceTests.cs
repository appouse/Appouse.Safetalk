using System.Net;
using System.Net.Http.Json;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Attributes (and other metadata) beat the <c>SkipHmacValidation()</c>/<c>RequireHmacValidation()</c> conventions;
/// within each kind the most specific (last) one wins.
/// </summary>
public sealed class EndpointMetadataPrecedenceTests
{
    private static readonly OrderRequest Order = new("SKU-1", 1, null);

    /// <summary>
    /// <c>MapControllers().SkipHmacValidation()</c> exempts every controller, except those that explicitly ask for a
    /// signature with <c>[RequireHmacValidation]</c>: unsigned requests to them get 401, signed ones 200.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MapControllersSkipConvention_RequireHmacValidationController_UnsignedIs401_SignedIs200(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureControllers = controllers => controllers.SkipHmacValidation() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient signed = clientServices.GetRequiredService<SafetalkApiClient>();
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage unsignedRequired = await unsigned.GetAsync(new Uri("/api/partner/orders", UriKind.Relative), ct);
        using HttpResponseMessage signedRequired = await signed.GetAsync("/api/partner/orders", ct);
        using HttpResponseMessage unsignedActionSkip = await unsigned.GetAsync(new Uri("/api/partner/catalog", UriKind.Relative), ct);
        using HttpResponseMessage unsignedUnmarked = await unsigned.PostAsJsonAsync(new Uri("/api/controller/orders", UriKind.Relative), Order, ct);

        unsignedRequired.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.OK, signedRequired.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await signedRequired.Content.ReadAsStringAsync(ct));

        // [SkipHmacValidation] on the action beats [RequireHmacValidation] on its controller.
        Assert.Equal("anonymous", await unsignedActionSkip.Content.ReadAsStringAsync(ct));

        // A controller without attributes follows the convention.
        OrderEchoResponse echo = await unsignedUnmarked.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Null(echo.ClientId);
    }

    /// <summary>
    /// A convention applied to the endpoint itself does not override an attribute on its handler.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task HandlerAttribute_BeatsConventionOnTheSameEndpointAndItsGroup(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigureEndpoints = MapAttributedEndpoints }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage endpointConvention = await unsigned.GetAsync(new Uri("/precedence/required-handler", UriKind.Relative), ct);
        using HttpResponseMessage groupConvention = await unsigned.GetAsync(new Uri("/precedence/open-group/required-handler", UriKind.Relative), ct);
        using HttpResponseMessage signed = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/precedence/open-group/required-handler", ct);

        endpointConvention.AssertUnauthorized();
        groupConvention.AssertUnauthorized();
        Assert.Equal("required:" + TestCredentials.ClientId, await signed.Content.ReadAsStringAsync(ct));
    }

    /// <summary>
    /// In <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/> mode a <c>[SkipHmacValidation]</c> handler stays public
    /// inside a group that requires a signature, and custom <see cref="IHmacValidationMetadata"/> counts like an attribute.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MarkedEndpointsOnly_SkipAttributeAndCustomMetadata_BeatTheRequiredGroupConvention(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly,
                ConfigureEndpoints = MapAttributedEndpoints,
            },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage protectedByGroup = await unsigned.GetAsync(new Uri("/precedence/b2b/orders", UriKind.Relative), ct);
        using HttpResponseMessage skipAttribute = await unsigned.GetAsync(new Uri("/precedence/b2b/skipped-handler", UriKind.Relative), ct);
        using HttpResponseMessage customMetadata = await unsigned.GetAsync(new Uri("/precedence/b2b/custom-opt-out", UriKind.Relative), ct);

        protectedByGroup.AssertUnauthorized();
        Assert.Equal("skipped", await skipAttribute.Content.ReadAsStringAsync(ct));
        Assert.Equal("custom", await customMetadata.Content.ReadAsStringAsync(ct));
    }

    private static void MapAttributedEndpoints(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/precedence/required-handler", [RequireHmacValidation] (HttpContext context) => "required:" + context.GetHmacClientId())
            .SkipHmacValidation();

        RouteGroupBuilder open = endpoints.MapGroup("/precedence/open-group").SkipHmacValidation();
        open.MapGet("/required-handler", [RequireHmacValidation] (HttpContext context) => "required:" + context.GetHmacClientId());

        RouteGroupBuilder b2b = endpoints.MapGroup("/precedence/b2b").RequireHmacValidation();
        b2b.MapGet("/orders", (HttpContext context) => "orders:" + context.GetHmacClientId());
        b2b.MapGet("/skipped-handler", [SkipHmacValidation] () => "skipped");
        b2b.MapGet("/custom-opt-out", () => "custom").WithMetadata(new PublicEndpointMetadata());
    }

    /// <summary>Application-defined metadata that opts an endpoint out of HMAC validation.</summary>
    private sealed class PublicEndpointMetadata : IHmacValidationMetadata
    {
        public bool RequiresValidation => false;
    }
}
