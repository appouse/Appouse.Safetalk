using System.Diagnostics;
using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// Where routing runs relative to the middleware decides how a missing endpoint is interpreted:
/// <list type="bullet">
///   <item><description>Before (explicit <c>UseRouting()</c> first, or the <c>WebApplication</c> root with implicit routing, or a branch created after <c>UseRouting()</c>): no endpoint means no route matched.</description></item>
///   <item><description>Unknown (<c>UseWhen</c> branches, <c>UseMiddleware</c>, plain builders): requests without an endpoint are validated in every mode (fail closed).</description></item>
///   <item><description>After (<c>UseRouting()</c> registered later): every request is validated and EventId 10 is logged at build.</description></item>
/// </list>
/// </summary>
public sealed class HmacRoutingOrderMatrixTests : IDisposable
{
    private const int RoutingRegisteredAfterEventId = 10;

    private readonly LogCollector _logs = new();
    private readonly ServiceProvider _requestServices = new ServiceCollection().AddLogging().BuildServiceProvider();

    public enum Placement
    {
        RootImplicitRouting,
        RootAfterExplicitRouting,
        RootBeforeExplicitRouting,
        BranchWithImplicitRouting,
        BranchAfterExplicitRouting,
        BranchBeforeExplicitRouting,
        UseMiddlewareWithImplicitRouting,
        UseMiddlewareBeforeExplicitRouting,
    }

    /// <summary>
    /// Unsigned requests in <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/> mode: (unmarked, required, skipped, unmatched).
    /// </summary>
    public static TheoryData<Placement, int, int, int, int> MarkedEndpointsOnlyMatrix { get; } = new()
    {
        { Placement.RootImplicitRouting, 200, 401, 200, 404 },
        { Placement.RootAfterExplicitRouting, 200, 401, 200, 404 },
        { Placement.RootBeforeExplicitRouting, 401, 401, 401, 401 },
        { Placement.BranchWithImplicitRouting, 200, 401, 200, 401 },
        { Placement.BranchAfterExplicitRouting, 200, 401, 200, 404 },
        { Placement.BranchBeforeExplicitRouting, 401, 401, 401, 401 },
        { Placement.UseMiddlewareWithImplicitRouting, 200, 401, 200, 401 },
        { Placement.UseMiddlewareBeforeExplicitRouting, 401, 401, 401, 401 },
    };

    /// <summary>
    /// Unsigned requests in <see cref="HmacEnforcementMode.AllRequests"/> mode: (unmarked, required, skipped, unmatched).
    /// </summary>
    public static TheoryData<Placement, int, int, int, int> AllRequestsMatrix { get; } = new()
    {
        { Placement.RootImplicitRouting, 401, 401, 200, 401 },
        { Placement.RootAfterExplicitRouting, 401, 401, 200, 401 },
        { Placement.RootBeforeExplicitRouting, 401, 401, 401, 401 },
        { Placement.BranchWithImplicitRouting, 401, 401, 200, 401 },
        { Placement.BranchAfterExplicitRouting, 401, 401, 200, 401 },
        { Placement.BranchBeforeExplicitRouting, 401, 401, 401, 401 },
        { Placement.UseMiddlewareWithImplicitRouting, 401, 401, 200, 401 },
        { Placement.UseMiddlewareBeforeExplicitRouting, 401, 401, 401, 401 },
    };

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _logs.Dispose();
        _requestServices.Dispose();
    }

    [Theory]
    [MemberData(nameof(MarkedEndpointsOnlyMatrix))]
    public async Task MarkedEndpointsOnly_UnsignedRequests_FollowTheRoutingOrder(Placement placement, int unmarked, int required, int skipped, int unmatched)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly, placement);

        await AssertStatusAsync(app, "/api/public", unmarked);
        await AssertStatusAsync(app, "/api/b2b", required);
        await AssertStatusAsync(app, "/api/health", skipped);
        await AssertStatusAsync(app, "/api/missing", unmatched);
    }

    [Theory]
    [MemberData(nameof(AllRequestsMatrix))]
    public async Task AllRequests_UnsignedRequests_FollowTheRoutingOrder(Placement placement, int unmarked, int required, int skipped, int unmatched)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests, placement);

        await AssertStatusAsync(app, "/api/public", unmarked);
        await AssertStatusAsync(app, "/api/b2b", required);
        await AssertStatusAsync(app, "/api/health", skipped);
        await AssertStatusAsync(app, "/api/missing", unmatched);
    }

    [Theory]
    [InlineData(Placement.RootImplicitRouting)]
    [InlineData(Placement.RootAfterExplicitRouting)]
    [InlineData(Placement.RootBeforeExplicitRouting)]
    [InlineData(Placement.BranchWithImplicitRouting)]
    [InlineData(Placement.BranchAfterExplicitRouting)]
    [InlineData(Placement.BranchBeforeExplicitRouting)]
    [InlineData(Placement.UseMiddlewareWithImplicitRouting)]
    [InlineData(Placement.UseMiddlewareBeforeExplicitRouting)]
    public async Task SignedRequests_AreAuthenticatedOnRequiredEndpointsAndUnmatchedRoutesReturn404(Placement placement)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly, placement);

        using HttpResponseMessage required = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/b2b"));
        using HttpResponseMessage unmatched = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/missing"));

        Assert.Equal(HttpStatusCode.OK, required.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await required.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal(HttpStatusCode.NotFound, unmatched.StatusCode);
    }

    [Theory]
    [InlineData(Placement.BranchWithImplicitRouting)]
    [InlineData(Placement.BranchAfterExplicitRouting)]
    [InlineData(Placement.BranchBeforeExplicitRouting)]
    public async Task Branches_RequestsOutsideTheBranch_AreNeverValidated(Placement placement)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests, placement);

        await AssertStatusAsync(app, "/outside", 200);
        await AssertStatusAsync(app, "/outside-missing", 404);
    }

    [Theory]
    [InlineData(Placement.RootImplicitRouting)]
    [InlineData(Placement.RootAfterExplicitRouting)]
    [InlineData(Placement.BranchWithImplicitRouting)]
    [InlineData(Placement.BranchAfterExplicitRouting)]
    [InlineData(Placement.UseMiddlewareWithImplicitRouting)]
    public async Task RoutingKnownOrFoundBeforeTheMiddleware_NoWarningIsLoggedEvenAfterSignedTraffic(Placement placement)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly, placement);

        await SendMixedTrafficAsync(app);

        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task RootBeforeExplicitRouting_WarnsOnceAtBuildAndNeverAtRuntime()
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly, Placement.RootBeforeExplicitRouting);
        Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));

        await SendMixedTrafficAsync(app);

        LogRecord warning = Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
        Assert.Equal(LogLevel.Warning, warning.Level);
    }

    [Fact]
    public async Task BranchBeforeExplicitRouting_WarnsOnceAtRuntimeAfterTheFirstRequestThatPassesTheMiddleware()
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly, Placement.BranchBeforeExplicitRouting);
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));

        // Rejected requests never reach routing: the order cannot be observed yet.
        await AssertStatusAsync(app, "/api/b2b", 401);
        await AssertStatusAsync(app, "/api/health", 401);
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));

        using HttpResponseMessage first = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/b2b"));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        LogRecord warning = Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));

        using HttpResponseMessage second = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/public"));
        using HttpResponseMessage third = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/health"));
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.OK, third.StatusCode);
        Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Contains("UseRouting()", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BranchBeforeExplicitRouting_SignedRequestToUnmatchedRouteDoesNotWarn()
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly, Placement.BranchBeforeExplicitRouting);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/missing"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BranchWithImplicitRouting_ErrorHandlingRegisteredAfterTheBranch_DoesNotReportRoutingAfterMiddleware(bool exceptionHandler)
    {
        // Routing ran before the branch (implicit routing). A re-executing error handler registered after the branch
        // re-routes the request and leaves the error endpoint selected: that is not evidence of UseRouting() running
        // after the middleware, so no misconfiguration warning may be logged.
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
                    context => context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal),
                    branch => branch.UseHmacAuthentication());
                if (exceptionHandler)
                {
                    pipeline.UseExceptionHandler("/error/500");
                }
                else
                {
                    pipeline.UseStatusCodePagesWithReExecute("/error/{0}");
                }

                pipeline.MapGet("/error/{code:int}", (int code) => $"error {code}");
                pipeline.MapGet("/api/throws", string () => throw new InvalidOperationException("Endpoint failure."));
            });

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, exceptionHandler ? "/api/throws" : "/api/missing"));

        Assert.Equal(exceptionHandler ? HttpStatusCode.InternalServerError : HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(exceptionHandler ? "error 500" : "error 404", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly)]
    public async Task ApplicationBuilder_NoRoutingAtAll_RequestWithoutEndpointIsValidatedInEveryMode(HmacEnforcementMode mode)
    {
        await using ServiceProvider services = BuildServices(mode);
        var app = new ApplicationBuilder(services);
        app.UseHmacAuthentication();
        app.Run(context => context.Response.WriteAsync("terminal", context.RequestAborted));

        RequestDelegate pipeline = app.Build();

        Assert.Equal(StatusCodes.Status401Unauthorized, await InvokeAsync(services, pipeline, "/anything"));
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task ApplicationBuilder_RoutingRegisteredBefore_UnmatchedRouteIsNotValidatedInMarkedEndpointsOnlyMode()
    {
        await using ServiceProvider services = BuildServices(HmacEnforcementMode.MarkedEndpointsOnly);
        var app = new ApplicationBuilder(services);
        app.UseRouting();
        app.UseHmacAuthentication();
        app.UseEndpoints(endpoints => endpoints.MapGet("/b2b", context => context.Response.WriteAsync("b2b", context.RequestAborted)).RequireHmacValidation());

        RequestDelegate pipeline = app.Build();

        Assert.Equal(StatusCodes.Status404NotFound, await InvokeAsync(services, pipeline, "/missing"));
        Assert.Equal(StatusCodes.Status401Unauthorized, await InvokeAsync(services, pipeline, "/b2b"));
    }

    [Fact]
    public async Task ApplicationBuilder_BranchCreatedAfterUseRouting_InheritsTheKnownOrder()
    {
        await using ServiceProvider services = BuildServices(HmacEnforcementMode.MarkedEndpointsOnly);
        var app = new ApplicationBuilder(services);
        app.UseRouting();
        app.UseWhen(_ => true, branch => branch.UseHmacAuthentication());
        app.UseEndpoints(endpoints => endpoints.MapGet("/b2b", context => context.Response.WriteAsync("b2b", context.RequestAborted)).RequireHmacValidation());

        RequestDelegate pipeline = app.Build();

        Assert.Equal(StatusCodes.Status404NotFound, await InvokeAsync(services, pipeline, "/missing"));
        Assert.Equal(StatusCodes.Status401Unauthorized, await InvokeAsync(services, pipeline, "/b2b"));
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly)]
    public async Task Unknown_EndpointSelectedOnlyAfterTheMiddleware_LogsOnceAcrossRequests(HmacEnforcementMode mode)
    {
        var (middleware, nextCalls) = CreateMiddleware(HmacAuthenticationMiddleware.RoutingOrder.Unknown, mode, selectEndpointInNext: true);
        var validator = new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId));

        await middleware.InvokeAsync(CreateContext(), validator);
        await middleware.InvokeAsync(CreateContext(), validator);
        await middleware.InvokeAsync(CreateContext(), validator);

        Assert.Equal(3, validator.CallCount); // Fail closed: no endpoint when the middleware ran.
        Assert.Equal(3, nextCalls());
        LogRecord warning = Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
        Assert.Equal(LogLevel.Warning, warning.Level);
    }

    [Fact]
    public async Task Unknown_RejectedRequest_DoesNotLog()
    {
        var (middleware, nextCalls) = CreateMiddleware(HmacAuthenticationMiddleware.RoutingOrder.Unknown, HmacEnforcementMode.MarkedEndpointsOnly, selectEndpointInNext: true);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        DefaultHttpContext context = CreateContext();
        await middleware.InvokeAsync(context, validator);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(0, nextCalls());
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task Unknown_EndpointAlreadySelected_HonoursMetadataAndDoesNotLog()
    {
        var (middleware, nextCalls) = CreateMiddleware(HmacAuthenticationMiddleware.RoutingOrder.Unknown, HmacEnforcementMode.MarkedEndpointsOnly, selectEndpointInNext: true);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));
        DefaultHttpContext unmarked = CreateContext(new object());
        DefaultHttpContext skipped = CreateContext(new SkipHmacValidationAttribute());
        DefaultHttpContext required = CreateContext(new RequireHmacValidationAttribute());

        await middleware.InvokeAsync(unmarked, validator);
        await middleware.InvokeAsync(skipped, validator);
        await middleware.InvokeAsync(required, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(2, nextCalls());
        Assert.Equal(StatusCodes.Status401Unauthorized, required.Response.StatusCode);
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task Unknown_ReExecutionOfAVerifiedRequest_ReportsTheLateEndpointToo()
    {
        var (middleware, _) = CreateMiddleware(HmacAuthenticationMiddleware.RoutingOrder.Unknown, HmacEnforcementMode.AllRequests, selectEndpointInNext: true);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));
        DefaultHttpContext context = CreateContext();
        HmacClientIdentity.SetFeature(context, TestCredentials.ClientId);

        await middleware.InvokeAsync(context, validator);

        Assert.Equal(0, validator.CallCount);
        Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task After_EndpointSelectedAfterTheMiddleware_DoesNotLogAtRuntime()
    {
        // The After order is already reported (and enforced) when the pipeline is built.
        var (middleware, nextCalls) = CreateMiddleware(HmacAuthenticationMiddleware.RoutingOrder.After, HmacEnforcementMode.AllRequests, selectEndpointInNext: true);
        var validator = new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId));

        await middleware.InvokeAsync(CreateContext(), validator);

        Assert.Equal(1, nextCalls());
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task Before_EndpointSelectedAfterTheMiddlewareOnSuccess_IsReportedOnceAndLaterRequestsAreValidated()
    {
        // Safety net for a misclassified pipeline (for example endpoints mapped only inside Map branches): an endpoint
        // that appears only after the middleware on a successful response proves routing runs later.
        var (middleware, nextCalls) = CreateMiddleware(HmacAuthenticationMiddleware.RoutingOrder.Before, HmacEnforcementMode.MarkedEndpointsOnly, selectEndpointInNext: true);
        var validator = new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId));

        await middleware.InvokeAsync(CreateContext(), validator);
        await middleware.InvokeAsync(CreateContext(), validator);
        await middleware.InvokeAsync(CreateContext(), validator);

        Assert.Equal(3, nextCalls());
        Assert.Equal(2, validator.CallCount); // The first request passed through; later ones fail closed and are validated.
        Assert.Single(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task Before_EndpointSelectedAfterTheMiddlewareOnErrorResponse_IsNotReported()
    {
        // Error responses may be re-executed through an error endpoint (UseStatusCodePagesWithReExecute): not evidence.
        int nextCalls = 0;
        var middleware = new HmacAuthenticationMiddleware(
            context =>
            {
                nextCalls++;
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(), "error page"));
                return Task.CompletedTask;
            },
            new StaticOptionsMonitor<HmacServerOptions>(new HmacServerOptions { EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly }),
            HmacAuthenticationMiddleware.RoutingOrder.Before,
            _logs.CreateLogger<HmacAuthenticationMiddleware>());
        var validator = new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId));

        await middleware.InvokeAsync(CreateContext(), validator);
        await middleware.InvokeAsync(CreateContext(), validator);

        Assert.Equal(2, nextCalls);
        Assert.Equal(0, validator.CallCount);
        Assert.Empty(_logs.Find<HmacAuthenticationMiddleware>(RoutingRegisteredAfterEventId));
    }

    [Fact]
    public async Task Before_NoEndpointInMarkedEndpointsOnlyMode_PassesThroughWithoutValidating()
    {
        var (middleware, nextCalls) = CreateMiddleware(HmacAuthenticationMiddleware.RoutingOrder.Before, HmacEnforcementMode.MarkedEndpointsOnly, selectEndpointInNext: false);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await middleware.InvokeAsync(CreateContext(), validator);

        Assert.Equal(0, validator.CallCount);
        Assert.Equal(1, nextCalls());
    }

    [Fact]
    public async Task After_EndpointWithSkipMetadata_IsStillValidated()
    {
        var (middleware, nextCalls) = CreateMiddleware(HmacAuthenticationMiddleware.RoutingOrder.After, HmacEnforcementMode.MarkedEndpointsOnly, selectEndpointInNext: false);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));
        DefaultHttpContext context = CreateContext(new SkipHmacValidationAttribute());

        await middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(0, nextCalls());
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public void RoutingOrder_HasExactlyTheThreeDocumentedValues()
    {
        Assert.Equal(
            [HmacAuthenticationMiddleware.RoutingOrder.Before, HmacAuthenticationMiddleware.RoutingOrder.Unknown, HmacAuthenticationMiddleware.RoutingOrder.After],
            Enum.GetValues<HmacAuthenticationMiddleware.RoutingOrder>());
    }

    private static async Task AssertStatusAsync(TestApplication app, string path, int expected)
    {
        using HttpResponseMessage response = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri(path, UriKind.Relative)));
        Assert.True((int)response.StatusCode == expected, $"{path}: expected {expected} but got {(int)response.StatusCode}.");
    }

    private static async Task SendMixedTrafficAsync(TestApplication app)
    {
        foreach (string path in (string[])["/api/public", "/api/b2b", "/api/health", "/api/missing"])
        {
            using HttpResponseMessage unsigned = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri(path, UriKind.Relative)));
            using HttpResponseMessage signed = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, path));
        }
    }

    private static string Who(HttpContext context) => context.GetHmacClientId() ?? "anonymous";

    private DefaultHttpContext CreateContext(params object[] endpointMetadata)
    {
        var context = new DefaultHttpContext { RequestServices = _requestServices };
        context.Response.Body = new MemoryStream();
        if (endpointMetadata.Length > 0)
        {
            context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(endpointMetadata), "selected"));
        }

        return context;
    }

    private (HmacAuthenticationMiddleware Middleware, Func<int> NextCalls) CreateMiddleware(
        HmacAuthenticationMiddleware.RoutingOrder order,
        HmacEnforcementMode mode,
        bool selectEndpointInNext)
    {
        int nextCalls = 0;
        var middleware = new HmacAuthenticationMiddleware(
            context =>
            {
                nextCalls++;
                if (selectEndpointInNext && context.GetEndpoint() is null)
                {
                    // What a UseRouting() registered after the middleware does.
                    context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(new SkipHmacValidationAttribute()), "late"));
                }

                return Task.CompletedTask;
            },
            new StaticOptionsMonitor<HmacServerOptions>(new HmacServerOptions { EnforcementMode = mode }),
            order,
            _logs.CreateLogger<HmacAuthenticationMiddleware>());
        return (middleware, () => nextCalls);
    }

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

    private Task<TestApplication> StartAsync(HmacEnforcementMode mode, Placement placement) =>
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
                static bool InApi(HttpContext context) => context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal);

                switch (placement)
                {
                    case Placement.RootImplicitRouting:
                        app.UseHmacAuthentication();
                        break;
                    case Placement.RootAfterExplicitRouting:
                        app.UseRouting();
                        app.UseHmacAuthentication();
                        break;
                    case Placement.RootBeforeExplicitRouting:
                        app.UseHmacAuthentication();
                        app.UseRouting();
                        break;
                    case Placement.BranchWithImplicitRouting:
                        app.UseWhen(InApi, branch => branch.UseHmacAuthentication());
                        break;
                    case Placement.BranchAfterExplicitRouting:
                        app.UseRouting();
                        app.UseWhen(InApi, branch => branch.UseHmacAuthentication());
                        break;
                    case Placement.BranchBeforeExplicitRouting:
                        app.UseWhen(InApi, branch => branch.UseHmacAuthentication());
                        app.UseRouting();
                        break;
                    case Placement.UseMiddlewareWithImplicitRouting:
                        app.UseMiddleware<HmacAuthenticationMiddleware>();
                        break;
                    case Placement.UseMiddlewareBeforeExplicitRouting:
                        app.UseMiddleware<HmacAuthenticationMiddleware>();
                        app.UseRouting();
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(placement), placement, null);
                }

                app.MapGet("/api/public", Who);
                app.MapGet("/api/b2b", Who).RequireHmacValidation();
                app.MapGet("/api/health", Who).SkipHmacValidation();
                app.MapGet("/outside", Who);
            });
}
