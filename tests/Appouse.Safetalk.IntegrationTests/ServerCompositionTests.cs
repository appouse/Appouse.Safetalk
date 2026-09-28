using System.Net;
using System.Security.Claims;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The HMAC middleware composed with the rest of an ASP.NET Core pipeline as documented in the README:
/// partial protection with <c>UseWhen</c>, other authentication mechanisms and <c>UseAuthorization()</c>.
/// </summary>
public sealed class ServerCompositionTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseWhen_OnlyMatchingRequestsRequireASignature(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ProtectOnly = context => context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase) },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient signed = clientServices.GetRequiredService<SafetalkApiClient>();
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage unprotected = await unsigned.GetAsync(new Uri("/inspect/public", UriKind.Relative), ct);
        using HttpResponseMessage protectedUnsigned = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        WhoAmIResponse protectedSigned = await signed.GetWhoAmIAsync(ct);

        RequestInfoResponse info = await unprotected.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Null(info.ClientId);
        protectedUnsigned.AssertUnauthorized();
        Assert.Equal(TestCredentials.ClientId, protectedSigned.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UserAuthenticatedByAnotherMechanism_IsKept_AndHmacIdentityIsAdded(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigurePipeline = app => app.Use((HttpContext context, RequestDelegate next) =>
                {
                    context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "alice")], "Cookies"));
                    return next(context);
                }),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse whoAmI = await client.GetWhoAmIAsync(ct);

        Assert.Equal("alice", whoAmI.UserName);
        Assert.Equal("Cookies", whoAmI.AuthenticationType);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientIdClaim);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequireAuthorization_SignedClient_IsAuthorized(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithHmacScheme(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/authorized/any-client", ct);

        WhoAmIResponse whoAmI = await response.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientIdClaim);
        Assert.True(Assert.Single(server.ValidationResults).Succeeded); // Scheme and middleware share one verification.
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequireAuthorization_UnsignedRequest_IsRejectedWith401(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithHmacScheme(), ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/authorized/any-client", UriKind.Relative), ct);

        response.AssertUnauthorized();
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClaimsPolicyOnClientIdClaim_AdmitsTheMatchingClient(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithHmacScheme(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/authorized/partner-a-only", ct);

        WhoAmIResponse whoAmI = await response.ReadOkJsonAsync<WhoAmIResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    /// <summary>
    /// With the README setup (<c>AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac()</c> and an
    /// explicit <c>UseAuthorization()</c> after <c>UseHmacAuthentication()</c>) an authenticated client that fails a
    /// policy on the <c>client_id</c> claim gets <c>403 Forbidden</c> (it was <c>500</c> without a scheme).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClaimsPolicyOnClientIdClaim_ForbidsAnotherAuthenticatedClientWith403(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithHmacScheme(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/authorized/partner-a-only", ct);

        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    private static ServerSetup WithHmacScheme() => new() { AddHmacAuthenticationScheme = true };
}
