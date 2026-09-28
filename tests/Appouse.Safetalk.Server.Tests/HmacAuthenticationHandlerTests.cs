using System.Net;
using System.Net.Http.Headers;
using Appouse.Safetalk.Server.Authentication;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacAuthenticationHandlerTests
{
    private const string PartnerBPolicy = AuthorizedController.PartnerBPolicy;
    private static readonly byte[] OrderJson = """{"orderId":42,"quantity":3}"""u8.ToArray();

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public enum Composition
    {
        HandlerOnly,
        AuthenticationThenMiddleware,
        MiddlewareThenAuthentication,
        ImplicitAuthenticationThenMiddleware,
    }

    [Fact]
    public async Task SignedRequest_RequireAuthorization_SucceedsWithHmacPrincipal()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/protected"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("partner-a|HMAC|True|partner-a|partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task SignedRequest_AuthorizeAttributeOnController_Succeeds()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/mvc/authorized"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task SignedPost_RequireAuthorization_BodyIsStillReadableByEndpoint()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, "/auth/echo", OrderJson));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("""{"orderId":42,"quantity":3}""", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task UnsignedRequest_AnonymousEndpoint_Returns200WithoutValidation()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/auth/anonymous"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Empty(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Theory]
    [InlineData("/auth/protected")]
    [InlineData("/mvc/authorized")]
    [InlineData("/auth/partner-b")]
    public async Task UnsignedRequest_ProtectedEndpoint_Returns401WithHmacChallenge(string path)
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(Unsigned(path));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        AuthenticationHeaderValue challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, challenge.Scheme);
        Assert.Empty(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Fact]
    public async Task UnsignedRequest_AllowAnonymousAction_Returns200()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/mvc/authorized/anonymous"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Theory]
    [InlineData("/auth/partner-b")]
    [InlineData("/mvc/authorized/partner-b")]
    public async Task SignedRequest_PolicyNotSatisfied_Returns403NotChallenge(string path)
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, path));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    [Theory]
    [InlineData("/auth/partner-b")]
    [InlineData("/mvc/authorized/partner-b")]
    public async Task SignedRequest_PolicySatisfied_Returns200(string path)
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, path, clientId: TestCredentials.OtherClientId, secret: TestCredentials.OtherSecret));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("/auth/protected")]
    [InlineData("/mvc/authorized")]
    public async Task InvalidSignature_ProtectedEndpoint_Returns401WithChallenge(string path)
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, path, secret: "wrong-secret"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.Equal(
            HmacValidationFailure.InvalidSignature,
            Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Fact]
    public async Task InvalidSignature_AnonymousEndpoint_IsReachedAsAnonymous()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/anonymous", secret: "wrong-secret"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Theory]
    [InlineData(SafetalkHeaderNames.ClientId)]
    [InlineData(SafetalkHeaderNames.Timestamp)]
    [InlineData(SafetalkHeaderNames.Signature)]
    public async Task SingleHmacHeader_IsValidatedAndRejected(string header)
    {
        await using TestApplication app = await StartAsync();
        HttpRequestMessage request = Unsigned("/auth/protected");
        request.Headers.Add(header, "1");

        using HttpResponseMessage response = await app.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(
            HmacValidationFailure.MissingHeaders,
            Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Fact]
    public async Task ReplayedRequest_ProtectedEndpoint_Returns401()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage first = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/protected"));
        using HttpResponseMessage replay = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/protected"));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task AuthenticateCalledSeveralTimesInOneRequest_ValidatesOnce()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/reauthenticate"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("True|True|partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Theory]
    [InlineData(Composition.AuthenticationThenMiddleware)]
    [InlineData(Composition.MiddlewareThenAuthentication)]
    [InlineData(Composition.ImplicitAuthenticationThenMiddleware)]
    public async Task HandlerAndMiddlewareTogether_WithReplayProtection_ValidateOnce(Composition composition)
    {
        await using TestApplication app = await StartAsync(composition);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/protected"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        HmacValidationResult validation = Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
        Assert.True(validation.Succeeded);
        string[] parts = (await response.Content.ReadAsStringAsync(CancellationToken)).Split('|');
        Assert.Equal(TestCredentials.ClientId, parts[0]);
        Assert.Equal(TestCredentials.ClientId, parts[3]);
    }

    [Theory]
    [InlineData(Composition.AuthenticationThenMiddleware)]
    [InlineData(Composition.MiddlewareThenAuthentication)]
    [InlineData(Composition.ImplicitAuthenticationThenMiddleware)]
    public async Task HandlerAndMiddlewareTogether_SignedPost_ValidateOnceAndBodyReachesEndpoint(Composition composition)
    {
        await using TestApplication app = await StartAsync(composition);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, "/auth/echo", OrderJson));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("""{"orderId":42,"quantity":3}""", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Theory]
    [InlineData(Composition.AuthenticationThenMiddleware)]
    [InlineData(Composition.MiddlewareThenAuthentication)]
    [InlineData(Composition.ImplicitAuthenticationThenMiddleware)]
    public async Task HandlerAndMiddlewareTogether_UnsignedRequest_Returns401(Composition composition)
    {
        await using TestApplication app = await StartAsync(composition);

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/auth/protected"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, Assert.Single(response.Headers.WwwAuthenticate).Scheme);
    }

    [Theory]
    [InlineData(Composition.AuthenticationThenMiddleware)]
    [InlineData(Composition.MiddlewareThenAuthentication)]
    public async Task HandlerAndMiddlewareTogether_PolicyNotSatisfied_Returns403(Composition composition)
    {
        await using TestApplication app = await StartAsync(composition);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/partner-b"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_WithAuthenticationAfterIt_ReusesVerificationAndKeeps404()
    {
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets).AddReplayProtection();
                builder.Services.AddValidationRecorder();
                builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
                builder.Services.AddAuthorization();
            },
            pipeline =>
            {
                pipeline.UseStatusCodePagesWithReExecute("/error/{0}");
                pipeline.UseAuthentication();
                pipeline.UseAuthorization();
                pipeline.MapGet(
                    "/error/{code:int}",
                    (HttpContext context, int code) => context.Response.WriteAsync($"error {code} for {context.User.Identity?.Name}", context.RequestAborted))
                    .RequireAuthorization();
                pipeline.MapGet("/auth/protected", Describe).RequireAuthorization();
            });

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/missing"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("error 404 for partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Fact]
    public async Task MarkedEndpointsOnlyMiddlewareWithAuthorizeOnUnmarkedEndpoint_HandlerValidatesOnce()
    {
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                builder.Services
                    .AddHmacServer(options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly)
                    .AddInMemorySecrets(TestCredentials.Secrets)
                    .AddReplayProtection();
                builder.Services.AddValidationRecorder();
                builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
                builder.Services.AddAuthorization();
            },
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.UseAuthentication();
                pipeline.UseAuthorization();
                pipeline.MapGet("/auth/protected", Describe).RequireAuthorization();
                pipeline.MapGet("/b2b/protected", Describe).RequireAuthorization().RequireHmacValidation();
            });

        using HttpResponseMessage viaHandler = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/auth/protected"));
        using HttpResponseMessage viaMiddleware = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b/protected"));
        using HttpResponseMessage unsigned = await app.SendAsync(Unsigned("/auth/protected"));

        Assert.Equal(HttpStatusCode.OK, viaHandler.StatusCode);
        Assert.Equal(HttpStatusCode.OK, viaMiddleware.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
        Assert.Equal(2, app.Services.GetRequiredService<ValidationRecorder>().Results.Count(result => result.Succeeded));
    }

    [Fact]
    public async Task CustomSchemeName_WorksWithPolicySelectingTheScheme()
    {
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
                builder.Services.AddAuthentication().AddHmac("Partners", configureOptions: null);
                builder.Services.AddAuthorization(options => options.AddPolicy(
                    "PartnersOnly",
                    policy => policy.AddAuthenticationSchemes("Partners").RequireAuthenticatedUser()));
            },
            app =>
            {
                app.UseAuthentication();
                app.UseAuthorization();
                app.MapGet("/partners", (HttpContext context) => context.User.Identity?.Name ?? "anonymous").RequireAuthorization("PartnersOnly");
            });

        using HttpResponseMessage signed = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/partners"));
        using HttpResponseMessage unsigned = await app.SendAsync(Unsigned("/partners"));

        Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await signed.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, Assert.Single(unsigned.Headers.WwwAuthenticate).Scheme);
    }

    [Fact]
    public async Task AddHmac_RegistersSchemeWithHandlerAndHmacServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication().AddHmac();
        await using ServiceProvider provider = services.BuildServiceProvider();

        IAuthenticationSchemeProvider schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();
        AuthenticationScheme? scheme = await schemes.GetSchemeAsync(HmacAuthenticationDefaults.AuthenticationScheme);

        Assert.NotNull(scheme);
        Assert.Equal(typeof(HmacAuthenticationHandler), scheme.HandlerType);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, scheme.DisplayName);
        Assert.Single(services, d => d.ServiceType == typeof(HmacServerMarkerService));
        Assert.Single(services, d => d.ServiceType == typeof(IHmacRequestValidator));
    }

    [Fact]
    public void AddHmac_ConfigureOptions_IsApplied()
    {
        var services = new ServiceCollection();
        services.AddAuthentication().AddHmac("Custom", options => options.ClaimsIssuer = "partners");
        using ServiceProvider provider = services.BuildServiceProvider();

        HmacAuthenticationSchemeOptions options = provider.GetRequiredService<IOptionsMonitor<HmacAuthenticationSchemeOptions>>().Get("Custom");

        Assert.Equal("partners", options.ClaimsIssuer);
    }

    [Fact]
    public void AddHmac_InvalidArguments_Throw()
    {
        AuthenticationBuilder builder = new ServiceCollection().AddAuthentication();

        Assert.Throws<ArgumentNullException>("builder", () => HmacAuthenticationBuilderExtensions.AddHmac(null!));
        Assert.Throws<ArgumentNullException>("builder", () => HmacAuthenticationBuilderExtensions.AddHmac(null!, "HMAC", null));
        Assert.Throws<ArgumentNullException>("authenticationScheme", () => builder.AddHmac(null!, null));
        Assert.Throws<ArgumentException>("authenticationScheme", () => builder.AddHmac(string.Empty, null));
    }

    [Fact]
    public void AuthenticationScheme_IsHmac()
    {
        Assert.Equal("HMAC", HmacAuthenticationDefaults.AuthenticationScheme);
    }

    private static HttpRequestMessage Unsigned(string path) => new(HttpMethod.Get, new Uri(path, UriKind.Relative));

    private static string Describe(HttpContext context) => string.Join(
        '|',
        context.User.Identity?.Name ?? "anonymous",
        context.User.Identity?.AuthenticationType ?? "none",
        context.User.Identity?.IsAuthenticated == true,
        context.GetHmacClientId() ?? "none",
        context.User.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value ?? "none");

    private static Task<TestApplication> StartAsync(Composition composition = Composition.HandlerOnly) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddControllers().AddApplicationPart(typeof(AuthorizedController).Assembly);
                builder.Services
                    .AddHmacServer()
                    .AddInMemorySecrets(TestCredentials.Secrets)
                    .AddReplayProtection();
                builder.Services.AddValidationRecorder();
                builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
                builder.Services.AddAuthorization(options => options.AddPolicy(
                    PartnerBPolicy,
                    policy => policy.RequireClaim(HmacAuthenticationDefaults.ClientIdClaimType, TestCredentials.OtherClientId)));
            },
            app =>
            {
                switch (composition)
                {
                    case Composition.HandlerOnly:
                        app.UseAuthentication();
                        app.UseAuthorization();
                        break;
                    case Composition.AuthenticationThenMiddleware:
                        app.UseAuthentication();
                        app.UseHmacAuthentication();
                        app.UseAuthorization();
                        break;
                    case Composition.MiddlewareThenAuthentication:
                        app.UseHmacAuthentication();
                        app.UseAuthentication();
                        app.UseAuthorization();
                        break;
                    case Composition.ImplicitAuthenticationThenMiddleware:
                        // WebApplication inserts UseAuthentication/UseAuthorization before user middleware.
                        app.UseHmacAuthentication();
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(composition), composition, null);
                }

                app.MapGet("/auth/anonymous", (HttpContext context) => context.User.Identity?.Name ?? "anonymous");
                app.MapGet("/auth/protected", Describe).RequireAuthorization();
                app.MapGet("/auth/partner-b", Describe).RequireAuthorization(PartnerBPolicy);
                app.MapPost("/auth/echo", async (HttpContext context) =>
                {
                    using var reader = new StreamReader(context.Request.Body);
                    return await reader.ReadToEndAsync(context.RequestAborted);
                }).RequireAuthorization();
                app.MapGet("/auth/reauthenticate", async (HttpContext context) =>
                {
                    AuthenticateResult first = await context.AuthenticateAsync(HmacAuthenticationDefaults.AuthenticationScheme);
                    AuthenticateResult second = await context.AuthenticateAsync(HmacAuthenticationDefaults.AuthenticationScheme);
                    return $"{first.Succeeded}|{second.Succeeded}|{second.Principal?.Identity?.Name}";
                });
                app.MapControllers();
            });
}
