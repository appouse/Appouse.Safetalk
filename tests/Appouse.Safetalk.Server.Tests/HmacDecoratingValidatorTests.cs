using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// A decorating <see cref="IHmacRequestValidator"/> that rejects some successes of the default validator (an IP
/// allow-list, a per-client kill switch...) must be honoured everywhere: the default validator only caches its outcome,
/// and only the consumers of the registered validator (middleware, <c>AddHmac()</c> handler) mark a request verified.
/// </summary>
public sealed class HmacDecoratingValidatorTests
{
    private const string Blocked = TestCredentials.OtherClientId;
    private const string BlockedSecret = TestCredentials.OtherSecret;

    private readonly RecordingSecretProvider _secrets = RecordingSecretProvider.ForTestCredentials();
    private readonly ClientBlockList _blockList = new(Blocked);

    public enum Setup
    {
        Middleware,
        Handler,
        HandlerThenMiddleware,
        MiddlewareThenHandler,
    }

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(Setup.Middleware)]
    [InlineData(Setup.Handler)]
    [InlineData(Setup.HandlerThenMiddleware)]
    [InlineData(Setup.MiddlewareThenHandler)]
    public async Task ProtectedEndpoint_DecoratorRejectsAValidSignature_Returns401AndNoHandlerRuns(Setup setup)
    {
        await using TestApplication app = await StartAsync(setup);

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami", clientId: Blocked, secret: BlockedSecret));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);

        // The signature itself was valid and verified exactly once; only the decorator turned it into a failure.
        Assert.All(app.Services.GetRequiredService<ValidationRecorder>().Results, result => Assert.True(result.Succeeded));
        Assert.Equal([Blocked], _secrets.RequestedClientIds);
        Assert.True(_blockList.RejectedSuccesses >= 1);
    }

    [Theory]
    [InlineData(Setup.Middleware)]
    [InlineData(Setup.Handler)]
    [InlineData(Setup.HandlerThenMiddleware)]
    [InlineData(Setup.MiddlewareThenHandler)]
    public async Task ProtectedEndpoint_DecoratorAllowsTheClient_Returns200WithTheClientIdentity(Setup setup)
    {
        await using TestApplication app = await StartAsync(setup);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("partner-a|partner-a|True", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal(0, _blockList.RejectedSuccesses);
    }

    [Theory]
    [InlineData(Setup.Handler)]
    [InlineData(Setup.HandlerThenMiddleware)]
    public async Task AnonymousEndpoint_DecoratorRejectsAValidSignature_IsReachedWithoutAnyIdentity(Setup setup)
    {
        await using TestApplication app = await StartAsync(setup);

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, "/open/whoami", clientId: Blocked, secret: BlockedSecret));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("none|anonymous|False", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task Handler_DecoratorRejects_AuthenticatingAgainStaysFailedAndAttachesNoClient()
    {
        await using TestApplication app = await StartAsync(Setup.Handler);

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, "/open/reauthenticate", clientId: Blocked, secret: BlockedSecret));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("False|False|none", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal([Blocked], _secrets.RequestedClientIds);
    }

    [Fact]
    public async Task CustomCallerOfTheRegisteredValidator_DecoratorRejects_GetsTheFailureAndMiddlewareStillRejects()
    {
        await using TestApplication app = await StartAsync(Setup.Middleware, customCaller: true);

        using HttpResponseMessage blocked = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami", clientId: Blocked, secret: BlockedSecret));
        using HttpResponseMessage allowed = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami"));

        Assert.Equal(HttpStatusCode.Unauthorized, blocked.StatusCode);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal("partner-a|partner-a|True", await allowed.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal([Blocked, TestCredentials.ClientId], _secrets.RequestedClientIds);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_DecoratorRejects_SkippedErrorPageRendersWithoutIdentity()
    {
        await using TestApplication app = await StartAsync(Setup.Middleware, statusCodePages: true, skipErrorEndpoint: true);

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami", clientId: Blocked, secret: BlockedSecret));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error 401 for none|anonymous|False", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal([Blocked], _secrets.RequestedClientIds);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_DecoratorRejects_ProtectedErrorPageIsRejectedAgainWithoutIdentity()
    {
        await using TestApplication app = await StartAsync(Setup.Middleware, statusCodePages: true, skipErrorEndpoint: false);

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami", clientId: Blocked, secret: BlockedSecret));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);

        // Re-execution consulted the registered validator again (the default validator answered from its cache).
        Assert.Equal(2, _blockList.RejectedSuccesses);
        Assert.Equal([Blocked], _secrets.RequestedClientIds);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_AllowedClientToUnknownRoute_ErrorPageSeesTheClientAndKeeps404()
    {
        await using TestApplication app = await StartAsync(Setup.Middleware, statusCodePages: true, skipErrorEndpoint: false);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b/missing"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("error 404 for partner-a|partner-a|True", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal(1, _blockList.Calls);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_HandlerOnlyDecoratorRejects_ErrorPageHasNoIdentity()
    {
        await using TestApplication app = await StartAsync(Setup.Handler, statusCodePages: true, skipErrorEndpoint: true);

        using HttpResponseMessage response = await app.SendAsync(
            app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami", clientId: Blocked, secret: BlockedSecret));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error 401 for none|anonymous|False", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal([Blocked], _secrets.RequestedClientIds);
    }

    [Fact]
    public async Task ReplayProtection_RequestRejectedByTheDecorator_StillConsumesTheSignature()
    {
        // The signature was genuinely verified: replaying it later is still a replay, even if the decorator's decision
        // would change (for example the client is unblocked in between).
        await using TestApplication app = await StartAsync(Setup.Middleware);
        HttpRequestMessage original = app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami", clientId: Blocked, secret: BlockedSecret);
        HttpRequestMessage replay = app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami", clientId: Blocked, secret: BlockedSecret);

        using HttpResponseMessage first = await app.SendAsync(original);
        using HttpResponseMessage second = await app.SendAsync(replay);

        Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
        Assert.Equal(
            [HmacValidationFailure.None, HmacValidationFailure.ReplayDetected],
            app.Services.GetRequiredService<ValidationRecorder>().Results.Select(result => result.Failure));
    }

    private static string Describe(HttpContext context) => string.Join(
        '|',
        context.GetHmacClientId() ?? "none",
        context.User.Identity?.Name ?? "anonymous",
        context.User.Identity?.IsAuthenticated == true);

    private Task<TestApplication> StartAsync(
        Setup setup,
        bool statusCodePages = false,
        bool skipErrorEndpoint = true,
        bool customCaller = false) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services
                    .AddHmacServer()
                    .AddSecretProvider(_ => _secrets, ServiceLifetime.Singleton)
                    .AddReplayProtection();
                builder.Services.AddValidationRecorder();
                builder.Services.AddSingleton(_blockList);
                builder.Services.DecorateRequestValidator(
                    (provider, inner) => new AllowListRequestValidator(inner, provider.GetRequiredService<ClientBlockList>()));
                if (setup != Setup.Middleware)
                {
                    builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
                    builder.Services.AddAuthorization();
                }
            },
            app =>
            {
                if (statusCodePages)
                {
                    app.UseStatusCodePagesWithReExecute("/error/{0}");
                }

                if (customCaller)
                {
                    // Audit logging that inspects the result of the registered validator but never short-circuits.
                    app.Use(async (HttpContext context, RequestDelegate next) =>
                    {
                        HmacValidationResult result = await context.RequestServices
                            .GetRequiredService<IHmacRequestValidator>()
                            .ValidateAsync(context, context.RequestAborted);
                        Assert.Equal(result.ClientId != Blocked, result.Succeeded);
                        Assert.Null(context.GetHmacClientId());
                        await next(context);
                    });
                }

                switch (setup)
                {
                    case Setup.Middleware:
                        app.UseHmacAuthentication();
                        break;
                    case Setup.Handler:
                        app.UseAuthentication();
                        app.UseAuthorization();
                        break;
                    case Setup.HandlerThenMiddleware:
                        app.UseAuthentication();
                        app.UseHmacAuthentication();
                        app.UseAuthorization();
                        break;
                    case Setup.MiddlewareThenHandler:
                        app.UseHmacAuthentication();
                        app.UseAuthentication();
                        app.UseAuthorization();
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(setup), setup, null);
                }

                RequestCounter counter = app.Services.GetRequiredService<RequestCounter>();
                RouteHandlerBuilder protectedEndpoint = app.MapGet("/b2b/whoami", (HttpContext context) =>
                {
                    counter.Increment();
                    return Describe(context);
                });
                RouteHandlerBuilder error = app.MapGet(
                    "/error/{code:int}",
                    (HttpContext context, int code) => $"error {code} for {Describe(context)}");
                app.MapGet("/open/whoami", Describe).SkipHmacValidation();
                app.MapGet("/open/reauthenticate", async (HttpContext context) =>
                {
                    AuthenticateResult first = await context.AuthenticateAsync(HmacAuthenticationDefaults.AuthenticationScheme);
                    AuthenticateResult second = await context.AuthenticateAsync(HmacAuthenticationDefaults.AuthenticationScheme);
                    return $"{first.Succeeded}|{second.Succeeded}|{context.GetHmacClientId() ?? "none"}";
                }).SkipHmacValidation();

                if (skipErrorEndpoint)
                {
                    error.SkipHmacValidation();
                }

                if (setup != Setup.Middleware)
                {
                    protectedEndpoint.RequireAuthorization();
                    if (!skipErrorEndpoint)
                    {
                        error.RequireAuthorization();
                    }
                }
            });
}
