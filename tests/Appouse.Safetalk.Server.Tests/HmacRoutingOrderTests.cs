using System.Diagnostics;
using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRoutingOrderTests : IDisposable
{
    private const int RoutingRegisteredAfterEventId = 10;

    private static readonly string[] Paths = ["/public", "/health", "/attr-skip", "/b2b", "/attr-require", "/b2b-group/orders", "/missing"];

    private readonly LogCollector _logs = new();

    public enum Order
    {
        ImplicitRouting,
        RoutingBefore,
        RoutingAfter,
    }

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public void Dispose() => _logs.Dispose();

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly)]
    public async Task RoutingAfterMiddleware_EveryUnsignedRequestIsRejectedIncludingSkippedAndPublicEndpoints(HmacEnforcementMode mode)
    {
        await using TestApplication app = await StartAsync(mode, Order.RoutingAfter);

        foreach (string path in Paths)
        {
            using HttpResponseMessage response = await app.SendAsync(Unsigned(path));
            Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{path}: expected 401 but got {(int)response.StatusCode}.");
        }

        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
    }

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly)]
    public async Task RoutingAfterMiddleware_SignedRequestsAreAcceptedAndAuthenticatedEverywhere(HmacEnforcementMode mode)
    {
        await using TestApplication app = await StartAsync(mode, Order.RoutingAfter);

        foreach (string path in Paths.Where(path => path != "/missing"))
        {
            using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, path));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(TestCredentials.ClientId, await response.Content.ReadAsStringAsync(CancellationToken));
        }
    }

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly)]
    public async Task RoutingAfterMiddleware_LogsOneWarningAtStartUpRegardlessOfTraffic(HmacEnforcementMode mode)
    {
        await using TestApplication app = await StartAsync(mode, Order.RoutingAfter);
        LogRecord startUpWarning = Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));

        for (int i = 0; i < 3; i++)
        {
            using HttpResponseMessage unsigned = await app.SendAsync(Unsigned("/health"));
            using HttpResponseMessage signed = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/public?n=" + i));
        }

        Assert.Equal(LogLevel.Warning, startUpWarning.Level);
        Assert.Contains("UseRouting()", startUpWarning.Message, StringComparison.Ordinal);
        Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Theory]
    [InlineData(Order.ImplicitRouting, HmacEnforcementMode.AllRequests)]
    [InlineData(Order.ImplicitRouting, HmacEnforcementMode.MarkedEndpointsOnly)]
    [InlineData(Order.RoutingBefore, HmacEnforcementMode.AllRequests)]
    [InlineData(Order.RoutingBefore, HmacEnforcementMode.MarkedEndpointsOnly)]
    public async Task RoutingBeforeMiddleware_MetadataIsHonouredAndNoWarningIsLogged(Order order, HmacEnforcementMode mode)
    {
        await using TestApplication app = await StartAsync(mode, order);

        using HttpResponseMessage health = await app.SendAsync(Unsigned("/health"));
        using HttpResponseMessage attributeSkip = await app.SendAsync(Unsigned("/attr-skip"));
        using HttpResponseMessage publicEndpoint = await app.SendAsync(Unsigned("/public"));
        using HttpResponseMessage required = await app.SendAsync(Unsigned("/b2b"));
        using HttpResponseMessage attributeRequired = await app.SendAsync(Unsigned("/attr-require"));
        using HttpResponseMessage groupRequired = await app.SendAsync(Unsigned("/b2b-group/orders"));

        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.Equal(HttpStatusCode.OK, attributeSkip.StatusCode);
        Assert.Equal(mode == HmacEnforcementMode.AllRequests ? HttpStatusCode.Unauthorized : HttpStatusCode.OK, publicEndpoint.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, required.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, attributeRequired.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, groupRequired.StatusCode);
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ApplicationBuilder_RoutingRegisteredAfter_ValidatesSkippedEndpointAndWarnsOnce(bool buildTwice)
    {
        await using ServiceProvider services = BuildServices(HmacEnforcementMode.MarkedEndpointsOnly);
        var app = new ApplicationBuilder(services);
        app.UseHmacAuthentication();
        app.UseRouting();
        app.UseEndpoints(endpoints => endpoints.MapGet("/health", context => context.Response.WriteAsync("ok", context.RequestAborted)).SkipHmacValidation());

        RequestDelegate pipeline = app.Build();
        int status = await InvokeAsync(services, pipeline, "/health");

        Assert.Equal(StatusCodes.Status401Unauthorized, status);
        Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
        if (buildTwice)
        {
            // Every pipeline build reports the misconfiguration of that pipeline.
            RequestDelegate second = app.Build();
            Assert.Equal(StatusCodes.Status401Unauthorized, await InvokeAsync(services, second, "/health"));
            Assert.Equal(2, _logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId).Count);
        }
    }

    [Fact]
    public async Task ApplicationBuilder_RoutingRegisteredBefore_HonoursSkipAndDoesNotWarn()
    {
        await using ServiceProvider services = BuildServices(HmacEnforcementMode.MarkedEndpointsOnly);
        var app = new ApplicationBuilder(services);
        app.UseRouting();
        app.UseHmacAuthentication();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet("/health", context => context.Response.WriteAsync("ok", context.RequestAborted)).SkipHmacValidation();
            endpoints.MapGet("/b2b", context => context.Response.WriteAsync("b2b", context.RequestAborted)).RequireHmacValidation();
            endpoints.MapGet("/public", context => context.Response.WriteAsync("public", context.RequestAborted));
        });

        RequestDelegate pipeline = app.Build();

        Assert.Equal(StatusCodes.Status200OK, await InvokeAsync(services, pipeline, "/health"));
        Assert.Equal(StatusCodes.Status401Unauthorized, await InvokeAsync(services, pipeline, "/b2b"));
        Assert.Equal(StatusCodes.Status200OK, await InvokeAsync(services, pipeline, "/public"));
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task ApplicationBuilder_NoRoutingAtAll_KeepsModeBasedBehaviourWithoutWarning()
    {
        await using ServiceProvider services = BuildServices(HmacEnforcementMode.AllRequests);
        var app = new ApplicationBuilder(services);
        app.UseHmacAuthentication();
        app.Run(context => context.Response.WriteAsync("terminal", context.RequestAborted));

        RequestDelegate pipeline = app.Build();

        Assert.Equal(StatusCodes.Status401Unauthorized, await InvokeAsync(services, pipeline, "/anything"));
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task UseWhenBranchBeforeUseRouting_MarkedEndpointsOnly_RequiredEndpointIsStillProtected()
    {
        // The README suggests app.UseWhen(..., b => b.UseHmacAuthentication()) as an alternative placement. A branch is
        // built immediately, so when UseRouting() is registered after it the endpoint is not selected yet when the
        // middleware runs. Marked endpoints must not become reachable without a signature (fail closed).
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                builder.Logging.AddProvider(_logs);
                builder.Services
                    .AddHmacServer(options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly)
                    .AddInMemorySecrets(TestCredentials.Secrets);
            },
            pipeline =>
            {
                pipeline.UseWhen(
                    context => context.Request.Path.StartsWithSegments("/api/b2b", StringComparison.Ordinal),
                    branch => branch.UseHmacAuthentication());
                pipeline.UseRouting();
                pipeline.MapGet("/api/b2b/orders", Who).RequireHmacValidation();
            });

        using HttpResponseMessage unsigned = await app.SendAsync(Unsigned("/api/b2b/orders"));

        Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
    }

    [Fact]
    public async Task UseWhenBranchBeforeUseRouting_AllRequests_ValidatesEveryRequestOfTheBranch()
    {
        await using TestApplication app = await TestApplication.StartAsync(
            builder => builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets),
            pipeline =>
            {
                pipeline.UseWhen(
                    context => context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal),
                    branch => branch.UseHmacAuthentication());
                pipeline.UseRouting();
                pipeline.MapGet("/api/health", Who).SkipHmacValidation();
                pipeline.MapGet("/api/orders", Who);
                pipeline.MapGet("/outside", Who);
            });

        using HttpResponseMessage skipped = await app.SendAsync(Unsigned("/api/health"));
        using HttpResponseMessage orders = await app.SendAsync(Unsigned("/api/orders"));
        using HttpResponseMessage outside = await app.SendAsync(Unsigned("/outside"));
        using HttpResponseMessage signed = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/orders"));

        Assert.Equal(HttpStatusCode.Unauthorized, skipped.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, orders.StatusCode);
        Assert.Equal(HttpStatusCode.OK, outside.StatusCode);
        Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
    }

    [Fact]
    public async Task UseMiddlewareDirectlyBeforeUseRouting_MarkedEndpointsOnly_RequiredEndpointIsStillProtected()
    {
        // HmacAuthenticationMiddleware is public and follows the UseMiddleware<T>() convention. Its documentation says
        // that registering it before UseRouting() validates every request (fail closed).
        await using TestApplication app = await TestApplication.StartAsync(
            builder => builder.Services
                .AddHmacServer(options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly)
                .AddInMemorySecrets(TestCredentials.Secrets),
            pipeline =>
            {
                pipeline.UseMiddleware<HmacAuthenticationMiddleware>();
                pipeline.UseRouting();
                pipeline.MapGet("/b2b", Who).RequireHmacValidation();
            });

        using HttpResponseMessage unsigned = await app.SendAsync(Unsigned("/b2b"));

        Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
    }

    [Fact]
    public async Task UseMiddlewareDirectlyAfterRouting_MetadataIsHonoured()
    {
        await using TestApplication app = await TestApplication.StartAsync(
            builder => builder.Services
                .AddHmacServer(options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly)
                .AddInMemorySecrets(TestCredentials.Secrets),
            pipeline =>
            {
                pipeline.UseMiddleware<HmacAuthenticationMiddleware>();
                pipeline.MapGet("/b2b", Who).RequireHmacValidation();
                pipeline.MapGet("/public", Who);
            });

        using HttpResponseMessage required = await app.SendAsync(Unsigned("/b2b"));
        using HttpResponseMessage publicEndpoint = await app.SendAsync(Unsigned("/public"));

        Assert.Equal(HttpStatusCode.Unauthorized, required.StatusCode);
        Assert.Equal(HttpStatusCode.OK, publicEndpoint.StatusCode);
    }

    [Fact]
    public async Task UseWhenBranchAfterImplicitRouting_MarkedEndpointsOnly_MetadataIsHonoured()
    {
        await using TestApplication app = await TestApplication.StartAsync(
            builder => builder.Services
                .AddHmacServer(options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly)
                .AddInMemorySecrets(TestCredentials.Secrets),
            pipeline =>
            {
                pipeline.UseWhen(
                    context => context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal),
                    branch => branch.UseHmacAuthentication());
                pipeline.MapGet("/api/b2b/orders", Who).RequireHmacValidation();
                pipeline.MapGet("/api/public", Who);
            });

        using HttpResponseMessage required = await app.SendAsync(Unsigned("/api/b2b/orders"));
        using HttpResponseMessage publicEndpoint = await app.SendAsync(Unsigned("/api/public"));
        using HttpResponseMessage signed = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/b2b/orders"));

        Assert.Equal(HttpStatusCode.Unauthorized, required.StatusCode);
        Assert.Equal(HttpStatusCode.OK, publicEndpoint.StatusCode);
        Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await signed.Content.ReadAsStringAsync(CancellationToken));
    }

    private static HttpRequestMessage Unsigned(string path) => new(HttpMethod.Get, new Uri(path, UriKind.Relative));

    private static string Who(HttpContext context) => context.GetHmacClientId() ?? "anonymous";

    private static async Task<int> InvokeAsync(IServiceProvider services, RequestDelegate pipeline, string path)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        await pipeline(context);
        return context.Response.StatusCode;
    }

    private ServiceProvider BuildServices(HmacEnforcementMode mode)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(_logs));
        services.AddRouting();
        services.AddSingleton(new DiagnosticListener("Appouse.Safetalk.Server.Tests"));
        services.AddHmacServer(options => options.EnforcementMode = mode).AddInMemorySecrets(TestCredentials.Secrets);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private Task<TestApplication> StartAsync(HmacEnforcementMode mode, Order order) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Logging.AddProvider(_logs);
                builder.Services
                    .AddHmacServer(options => options.EnforcementMode = mode)
                    .AddInMemorySecrets(TestCredentials.Secrets);
            },
            app =>
            {
                switch (order)
                {
                    case Order.ImplicitRouting:
                        app.UseHmacAuthentication();
                        break;
                    case Order.RoutingBefore:
                        app.UseRouting();
                        app.UseHmacAuthentication();
                        break;
                    case Order.RoutingAfter:
                        app.UseHmacAuthentication();
                        app.UseRouting();
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(order), order, null);
                }

                RequestCounter counter = app.Services.GetRequiredService<RequestCounter>();
                app.Use(async (HttpContext context, RequestDelegate next) =>
                {
                    counter.Increment();
                    await next(context);
                });

                app.MapGet("/public", Who);
                app.MapGet("/health", Who).SkipHmacValidation();
                app.MapGet("/attr-skip", [SkipHmacValidation] (HttpContext context) => Who(context));
                app.MapGet("/b2b", Who).RequireHmacValidation();
                app.MapGet("/attr-require", [RequireHmacValidation] (HttpContext context) => Who(context));
                app.MapGroup("/b2b-group").RequireHmacValidation().MapGet("/orders", Who);
            });
}
