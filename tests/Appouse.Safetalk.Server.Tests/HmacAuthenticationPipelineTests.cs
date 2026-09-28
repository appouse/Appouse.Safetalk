using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacAuthenticationPipelineTests
{
    private static readonly byte[] OrderJson = """{"orderId":42,"quantity":3}"""u8.ToArray();

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task SignedPost_ReachesEndpointWithClientIdClaimsAndReadableBody()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo + "?id=5", OrderJson));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        ClientInfoResponse? info = await response.Content.ReadFromJsonAsync<ClientInfoResponse>(CancellationToken);
        Assert.NotNull(info);
        Assert.Equal(TestCredentials.ClientId, info.HmacClientId);
        Assert.Equal(TestCredentials.ClientId, info.PrimaryName);
        Assert.Equal(HmacAuthenticationDefaults.AuthenticationType, info.PrimaryAuthenticationType);
        Assert.True(info.IsAuthenticated);
        Assert.Equal(TestCredentials.ClientId, info.NameIdentifier);
        Assert.Equal(TestCredentials.ClientId, info.ClientIdClaim);
        Assert.Equal([HmacAuthenticationDefaults.AuthenticationType], info.AuthenticationTypes);
        Assert.Equal("""{"orderId":42,"quantity":3}""", info.Body);
        Assert.Equal(1, app.Services.GetRequiredService<RequestCounter>().Count);
    }

    [Fact]
    public async Task SignedGetWithoutBody_Succeeds()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, TestEndpoints.WhoAmI + "?page=2&size=10"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        ClientInfoResponse? info = await response.Content.ReadFromJsonAsync<ClientInfoResponse>(CancellationToken);
        Assert.Equal(TestCredentials.ClientId, info?.HmacClientId);
    }

    [Fact]
    public async Task SignedRequestWithEncodedQuery_Succeeds()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, TestEndpoints.WhoAmI + "?name=J%C3%BCrgen%20M&tags=a%2Cb"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SignedJsonPost_ModelBindingStillReadsVerifiedBody()
    {
        await using TestApplication app = await StartAsync();
        var content = new ByteArrayContent(OrderJson);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Orders, content, OrderJson));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(new OrderRequest(42, 3), await response.Content.ReadFromJsonAsync<OrderRequest>(CancellationToken));
    }

    [Fact]
    public async Task UnsignedRequest_Returns401WithChallengeEmptyBodyAndSkipsEndpoint()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri(TestEndpoints.WhoAmI, UriKind.Relative)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        AuthenticationHeaderValue challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, challenge.Scheme);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync(CancellationToken));
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
    }

    [Fact]
    public async Task UnsignedRequest_WithProblemDetailsRegistered_ReturnsProblemDetails()
    {
        await using TestApplication app = await StartAsync(services => services.AddProblemDetails());

        using HttpResponseMessage response = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri(TestEndpoints.WhoAmI, UriKind.Relative)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal(401, document.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("The request signature could not be verified.", document.RootElement.GetProperty("detail").GetString());
        Assert.Single(response.Headers.WwwAuthenticate);
    }

    [Fact]
    public async Task TamperedBody_Returns401AndSkipsEndpoint()
    {
        await using TestApplication app = await StartAsync();
        byte[] tampered = """{"orderId":42,"quantity":300}"""u8.ToArray();

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, new ByteArrayContent(tampered), OrderJson));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
    }

    [Fact]
    public async Task ExpiredTimestamp_Returns401()
    {
        await using TestApplication app = await StartAsync();
        HttpRequestMessage request = app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, OrderJson);
        app.Time.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        using HttpResponseMessage response = await app.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UnknownClient_Returns401()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, TestEndpoints.WhoAmI, clientId: "partner-unknown", secret: "whatever"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task OversizedBodyWithContentLength_Returns413WithoutChallenge()
    {
        await using TestApplication app = await StartAsync(configureHmac: options => options.MaxBodySize = 16);
        byte[] body = new byte[17];

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, body));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
    }

    [Fact]
    public async Task OversizedChunkedBody_Returns413()
    {
        await using TestApplication app = await StartAsync(configureHmac: options => options.MaxBodySize = 16);
        byte[] body = new byte[4096];

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, new UnknownLengthContent(body), body));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
    }

    [Fact]
    public async Task ChunkedBodyWithinLimit_Succeeds()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, new UnknownLengthContent(OrderJson), OrderJson));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        ClientInfoResponse? info = await response.Content.ReadFromJsonAsync<ClientInfoResponse>(CancellationToken);
        Assert.Equal("""{"orderId":42,"quantity":3}""", info?.Body);
    }

    [Fact]
    public async Task SkipHmacValidationEndpoint_IsReachableWithoutSignature()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri(TestEndpoints.Health, UriKind.Relative)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task SkipHmacValidationEndpoint_WithInvalidSignature_IsStillReachableButUnauthenticated()
    {
        await using TestApplication app = await StartAsync();
        HttpRequestMessage request = app.CreateSignedRequest(HttpMethod.Get, TestEndpoints.Health, secret: "wrong-secret");

        using HttpResponseMessage response = await app.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task AlreadyAuthenticatedUser_KeepsIdentityAndGainsHmacIdentity()
    {
        await using TestApplication app = await StartAsync(beforeHmac: pipeline => pipeline.Use(async (HttpContext context, RequestDelegate next) =>
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "alice")], "Bearer"));
            await next(context);
        }));

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, TestEndpoints.WhoAmI));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        ClientInfoResponse? info = await response.Content.ReadFromJsonAsync<ClientInfoResponse>(CancellationToken);
        Assert.NotNull(info);
        Assert.Equal("alice", info.PrimaryName);
        Assert.Equal("Bearer", info.PrimaryAuthenticationType);
        Assert.Equal(["Bearer", HmacAuthenticationDefaults.AuthenticationType], info.AuthenticationTypes);
        Assert.Equal(TestCredentials.ClientId, info.ClientIdClaim);
        Assert.Equal(TestCredentials.ClientId, info.HmacClientId);
    }

    [Fact]
    public async Task ReplayProtectionEnabled_IdenticalRequestIsRejectedSecondTime()
    {
        await using TestApplication app = await StartAsync(configureServer: hmac => hmac.AddReplayProtection());

        using HttpResponseMessage first = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, OrderJson));
        using HttpResponseMessage replay = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, OrderJson));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal(1, app.Services.GetRequiredService<RequestCounter>().Count);
    }

    [Fact]
    public async Task ReplayProtectionDisabled_IdenticalRequestIsAcceptedTwice()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage first = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, OrderJson));
        using HttpResponseMessage second = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, TestEndpoints.Echo, OrderJson));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
    }

    [Fact]
    public async Task ScopedSecretProvider_IsResolvedPerRequest()
    {
        await using TestApplication app = await StartAsync(
            services => services.AddSingleton<InstanceTracker>(),
            hmac => hmac.AddSecretProvider<ScopedSecretProvider>());

        using HttpResponseMessage first = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, TestEndpoints.WhoAmI));
        using HttpResponseMessage second = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, TestEndpoints.WhoAmI + "?n=2"));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        IReadOnlyList<object> instances = app.Services.GetRequiredService<InstanceTracker>().Instances;
        Assert.Equal(2, instances.Count);
        Assert.NotSame(instances[0], instances[1]);
    }

    [Fact]
    public async Task UnmatchedRoute_IsStillProtected()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri("/does-not-exist", UriKind.Relative)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static Task<TestApplication> StartAsync(
        Action<IServiceCollection>? configureServices = null,
        Action<IHmacServerBuilder>? configureServer = null,
        Action<HmacServerOptions>? configureHmac = null,
        Action<WebApplication>? beforeHmac = null)
    {
        return TestApplication.StartAsync(
            builder =>
            {
                configureServices?.Invoke(builder.Services);
                IHmacServerBuilder server = builder.Services
                    .AddHmacServer(configureHmac)
                    .AddInMemorySecrets(TestCredentials.Secrets);
                configureServer?.Invoke(server);
            },
            app =>
            {
                beforeHmac?.Invoke(app);
                app.UseHmacAuthentication();
                TestEndpoints.Map(app);
            });
    }
}
