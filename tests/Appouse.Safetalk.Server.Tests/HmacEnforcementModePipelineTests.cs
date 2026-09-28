using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacEnforcementModePipelineTests
{
    public static TheoryData<string, bool> MarkedEndpointsOnlyCases { get; } = new()
    {
        { "/plain", false },
        { "/marked", true },
        { "/skipped", false },
        { "/b2b/orders", true },
        { "/b2b/ping", false },
        { "/b2b/handler-skip", false },
        { "/public/info", false },
        { "/public/secure", true },
        { "/public/handler-require", true },
        { "/outer/inner/x", true },
        { "/outer/inner/y", false },
        { "/attributed", true },
        { "/attributed-skip", false },
        { "/mvc/probe/protected", false },
        { "/mvc/probe/public", false },
        { "/mvc/open", false },
        { "/mvc/required/default", true },
        { "/mvc/required/skipped", false },
        { "/mvc/skipped/default", false },
        { "/mvc/skipped/required", true },
        { "/mvc/inherited", true },
        { "/mvc/inherited/skipped", false },
    };

    public static TheoryData<string, bool> AllRequestsCases { get; } = new()
    {
        { "/plain", true },
        { "/marked", true },
        { "/skipped", false },
        { "/b2b/orders", true },
        { "/b2b/ping", false },
        { "/b2b/handler-skip", false },
        { "/public/info", false },
        { "/public/secure", true },
        { "/public/handler-require", true },
        { "/outer/inner/x", true },
        { "/outer/inner/y", false },
        { "/attributed", true },
        { "/attributed-skip", false },
        { "/mvc/probe/protected", true },
        { "/mvc/probe/public", false },
        { "/mvc/open", false },
        { "/mvc/required/default", true },
        { "/mvc/required/skipped", false },
        { "/mvc/skipped/default", false },
        { "/mvc/skipped/required", true },
        { "/mvc/inherited", true },
        { "/mvc/inherited/skipped", false },
    };

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Theory]
    [MemberData(nameof(MarkedEndpointsOnlyCases))]
    public async Task MarkedEndpointsOnly_ValidatesExactlyTheMarkedEndpoints(string path, bool expectValidation)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly);

        await AssertEnforcementAsync(app, path, expectValidation);
    }

    [Theory]
    [MemberData(nameof(AllRequestsCases))]
    public async Task AllRequests_ValidatesEverythingExceptSkippedEndpoints(string path, bool expectValidation)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests);

        await AssertEnforcementAsync(app, path, expectValidation);
    }

    [Fact]
    public async Task MarkedEndpointsOnly_UnmatchedRoute_Returns404InsteadOf401()
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly);

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/does-not-exist"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task AllRequests_UnmatchedRoute_Returns401()
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests);

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/does-not-exist"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task MarkedEndpointsOnly_SignedRequestToUnmarkedEndpoint_IsNotAuthenticated()
    {
        // Unmarked endpoints are not validated, so a signature there does not authenticate the caller either.
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/plain"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task MarkedEndpointsOnly_InvalidSignatureOnMarkedEndpoint_Returns401()
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b/orders", secret: "wrong-secret"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/mvc/required/default")]
    [InlineData("/mvc/skipped/required")]
    [InlineData("/mvc/inherited")]
    public async Task MapControllersSkipConvention_DoesNotOverrideRequireAttributeOnControllerOrAction(string path)
    {
        // The documented rule is that the most specific metadata wins. An application-wide convention on
        // MapControllers() is less specific than an attribute on a controller or action, so an explicitly required
        // controller must stay protected.
        await using TestApplication app = await StartAsync(
            HmacEnforcementMode.AllRequests,
            mapControllers: endpoints => endpoints.MapControllers().SkipHmacValidation());

        using HttpResponseMessage response = await app.SendAsync(Unsigned(path));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/mvc/required/skipped")]
    [InlineData("/mvc/probe/public")]
    public async Task MapControllersRequireConvention_DoesNotOverrideSkipAttributeOnAction(string path)
    {
        await using TestApplication app = await StartAsync(
            HmacEnforcementMode.MarkedEndpointsOnly,
            mapControllers: endpoints => endpoints.MapControllers().RequireHmacValidation());

        using HttpResponseMessage response = await app.SendAsync(Unsigned(path));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task MapControllersRequireConvention_ProtectsUnmarkedControllersInMarkedEndpointsOnlyMode()
    {
        await using TestApplication app = await StartAsync(
            HmacEnforcementMode.MarkedEndpointsOnly,
            mapControllers: endpoints => endpoints.MapControllers().RequireHmacValidation());

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/mvc/probe/protected"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task UndefinedEnforcementMode_ApplicationDoesNotStart(int mode)
    {
        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(
            () => StartAsync((HmacEnforcementMode)mode));

        Assert.Contains(exception.Failures, failure => failure.Contains(nameof(HmacServerOptions.EnforcementMode), StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(int.MaxValue)]
    public async Task UndefinedEnforcementModeForcedPastValidation_FailsClosedButHonoursExplicitMetadata(int mode)
    {
        var options = new HmacServerOptions { EnforcementMode = (HmacEnforcementMode)mode };
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
                builder.Services.AddSingleton<IOptionsMonitor<HmacServerOptions>>(new StaticOptionsMonitor<HmacServerOptions>(options));
            },
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.MapGet("/plain", Who);
                pipeline.MapGet("/skipped", Who).SkipHmacValidation();
            });

        using HttpResponseMessage plain = await app.SendAsync(Unsigned("/plain"));
        using HttpResponseMessage missing = await app.SendAsync(Unsigned("/missing"));
        using HttpResponseMessage skipped = await app.SendAsync(Unsigned("/skipped"));

        Assert.Equal(HttpStatusCode.Unauthorized, plain.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal(HttpStatusCode.OK, skipped.StatusCode);
    }

    private static async Task AssertEnforcementAsync(TestApplication app, string path, bool expectValidation)
    {
        using HttpResponseMessage unsigned = await app.SendAsync(Unsigned(path));
        using HttpResponseMessage signed = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, path));

        if (expectValidation)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
            Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
            Assert.Equal(TestCredentials.ClientId, await signed.Content.ReadAsStringAsync(CancellationToken));
        }
        else
        {
            Assert.Equal(HttpStatusCode.OK, unsigned.StatusCode);
            Assert.Equal("anonymous", await unsigned.Content.ReadAsStringAsync(CancellationToken));
            Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
            Assert.Equal("anonymous", await signed.Content.ReadAsStringAsync(CancellationToken));
        }
    }

    private static HttpRequestMessage Unsigned(string path) => new(HttpMethod.Get, new Uri(path, UriKind.Relative));

    private static string Who(HttpContext context) => context.GetHmacClientId() ?? "anonymous";

    private static Task<TestApplication> StartAsync(HmacEnforcementMode mode, Action<IEndpointRouteBuilder>? mapControllers = null) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddControllers().AddApplicationPart(typeof(ProbeController).Assembly);
                builder.Services
                    .AddHmacServer(options => options.EnforcementMode = mode)
                    .AddInMemorySecrets(TestCredentials.Secrets);
            },
            app =>
            {
                app.UseHmacAuthentication();

                app.MapGet("/plain", Who);
                app.MapGet("/marked", Who).RequireHmacValidation();
                app.MapGet("/skipped", Who).SkipHmacValidation();

                RouteGroupBuilder b2b = app.MapGroup("/b2b").RequireHmacValidation();
                b2b.MapGet("/orders", Who);
                b2b.MapGet("/ping", Who).SkipHmacValidation();
                b2b.MapGet("/handler-skip", [SkipHmacValidation] (HttpContext context) => Who(context));

                RouteGroupBuilder open = app.MapGroup("/public").SkipHmacValidation();
                open.MapGet("/info", Who);
                open.MapGet("/secure", Who).RequireHmacValidation();
                open.MapGet("/handler-require", [RequireHmacValidation] (HttpContext context) => Who(context));

                RouteGroupBuilder inner = app.MapGroup("/outer").SkipHmacValidation().MapGroup("/inner").RequireHmacValidation();
                inner.MapGet("/x", Who);
                inner.MapGet("/y", Who).SkipHmacValidation();

                app.MapGet("/attributed", [RequireHmacValidation] (HttpContext context) => Who(context));
                app.MapGet("/attributed-skip", [SkipHmacValidation] (HttpContext context) => Who(context));

                if (mapControllers is null)
                {
                    app.MapControllers();
                }
                else
                {
                    mapControllers(app);
                }
            });
}
