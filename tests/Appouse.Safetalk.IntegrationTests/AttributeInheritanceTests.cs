using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Round 4: <see cref="SkipHmacValidationAttribute"/> is not inherited (fail closed) while
/// <see cref="RequireHmacValidationAttribute"/> is, checked through real MVC controllers and endpoint metadata.
/// </summary>
public sealed class AttributeInheritanceTests
{
    /// <summary>
    /// A skip on a base controller or a base virtual action does not exempt the derived controller or the override;
    /// a base action that is not overridden is still that action and keeps its own skip.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SkipOnBaseControllerAndBaseVirtualAction_IsNotInherited(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient signed = clientServices.GetRequiredService<SafetalkApiClient>();
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage own = await unsigned.GetAsync(new Uri("/api/inheritance/skipped-base/own", UriKind.Relative), ct);
        using HttpResponseMessage overridden = await unsigned.GetAsync(new Uri("/api/inheritance/skipped-base/overridden", UriKind.Relative), ct);
        using HttpResponseMessage baseAction = await unsigned.GetAsync(new Uri("/api/inheritance/skipped-base/base-action", UriKind.Relative), ct);
        using HttpResponseMessage signedOwn = await signed.GetAsync("/api/inheritance/skipped-base/own", ct);
        using HttpResponseMessage signedOverridden = await signed.GetAsync("/api/inheritance/skipped-base/overridden", ct);

        own.AssertUnauthorized();
        overridden.AssertUnauthorized();
        Assert.Equal((HttpStatusCode.OK, "anonymous"), (baseAction.StatusCode, await baseAction.Content.ReadAsStringAsync(ct)));
        Assert.Equal(TestCredentials.ClientId, await signedOwn.Content.ReadAsStringAsync(ct));
        Assert.Equal("derived:" + TestCredentials.ClientId, await signedOverridden.Content.ReadAsStringAsync(ct));
    }

    /// <summary>
    /// <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/>: a require on a base controller protects the derived one;
    /// an explicit skip on a derived action still wins.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequireOnBaseController_IsInherited_InMarkedEndpointsOnlyMode(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureOptions = options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage orders = await unsigned.GetAsync(new Uri("/api/inheritance/required-base/orders", UriKind.Relative), ct);
        using HttpResponseMessage publicAction = await unsigned.GetAsync(new Uri("/api/inheritance/required-base/public", UriKind.Relative), ct);
        using HttpResponseMessage signedOrders = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/inheritance/required-base/orders", ct);

        orders.AssertUnauthorized();
        Assert.Equal((HttpStatusCode.OK, "anonymous"), (publicAction.StatusCode, await publicAction.Content.ReadAsStringAsync(ct)));
        Assert.Equal(TestCredentials.ClientId, await signedOrders.Content.ReadAsStringAsync(ct));
    }

    /// <summary>
    /// An inherited require is an attribute, so it beats a broad <c>MapControllers().SkipHmacValidation()</c>
    /// convention; controllers without attributes follow the convention.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task InheritedRequire_BeatsTheSkipConventionOnMapControllers(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureControllers = controllers => controllers.SkipHmacValidation() },
            ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage inheritedRequire = await unsigned.GetAsync(new Uri("/api/inheritance/required-base/orders", UriKind.Relative), ct);
        using HttpResponseMessage followsConvention = await unsigned.GetAsync(new Uri("/api/inheritance/skipped-base/own", UriKind.Relative), ct);

        inheritedRequire.AssertUnauthorized();
        Assert.Equal((HttpStatusCode.OK, "anonymous"), (followsConvention.StatusCode, await followsConvention.Content.ReadAsStringAsync(ct)));
    }
}
