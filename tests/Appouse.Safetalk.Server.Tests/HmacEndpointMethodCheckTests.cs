using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// The verified method must be one the selected endpoint accepts: a method rewritten after routing (for example
/// <c>UseHttpMethodOverride()</c> running after <c>WebApplication</c>'s implicit routing) would otherwise run the handler
/// selected for the wire method with a signature made for another method.
/// </summary>
public sealed class HmacEndpointMethodCheckTests : IDisposable
{
    private const string OverrideHeader = "X-HTTP-Method-Override";
    private const string PartnerOrigin = "https://partner.example";

    private readonly RecordingSecretProvider _secretProvider = RecordingSecretProvider.ForTestCredentials();
    private readonly LogCollector _logs = new();
    private readonly ValidatorHarness _harness;

    public HmacEndpointMethodCheckTests()
    {
        _harness = new ValidatorHarness(_secretProvider, logger: _logs.CreateLogger<HmacRequestValidator>());
    }

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public void Dispose() => _logs.Dispose();

    [Theory]
    [InlineData("POST", "DELETE")]
    [InlineData("POST", "PUT")]
    [InlineData("GET", "POST")]
    [InlineData("GET", "HEAD")]
    [InlineData("GET,POST", "PATCH")]
    [InlineData("PUT", "OPTIONS")]
    public async Task ValidateAsync_MethodNotAcceptedBySelectedEndpoint_ReturnsUnsignedMethodOverrideBeforeSecretLookupOrBodyRead(
        string endpointMethods,
        string requestMethod)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = requestMethod;
        DefaultHttpContext context = request.Build();
        context.Request.Body = new ThrowingReadStream();
        SelectEndpoint(context, new HttpMethodMetadata(endpointMethods.Split(',')));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Empty(_secretProvider.RequestedClientIds);
        Assert.Null(context.GetHmacClientId());
    }

    [Theory]
    [InlineData("POST", "POST")]
    [InlineData("post", "POST")]
    [InlineData("POST", "post")]
    [InlineData("GET,POST,DELETE", "DELETE")]
    [InlineData("Patch", "PATCH")]
    public async Task ValidateAsync_MethodAcceptedBySelectedEndpointIgnoringCase_Succeeds(string endpointMethods, string requestMethod)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = requestMethod;
        DefaultHttpContext context = request.Build();
        SelectEndpoint(context, new HttpMethodMetadata(endpointMethods.Split(',')));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
    }

    [Theory]
    [InlineData("OPTIONS")]
    [InlineData("options")]
    public async Task ValidateAsync_GenuinePreflightOnEndpointAcceptingCorsPreflight_Succeeds(string requestMethod)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = requestMethod;
        request.Body = [];
        DefaultHttpContext context = request.Build();
        context.Request.Headers.Origin = "https://partner.example.com";
        context.Request.Headers.AccessControlRequestMethod = HttpMethods.Put;
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Put], acceptCorsPreflight: true));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
    }

    [Fact]
    public async Task ValidateAsync_OptionsWithoutPreflightShapeOnEndpointAcceptingCorsPreflight_IsRejected()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Options;
        request.Body = [];
        DefaultHttpContext context = request.Build();
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Put], acceptCorsPreflight: true));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_OverriddenToOptionsOnEndpointAcceptingCorsPreflight_IsRejectedEvenWithPreflightHeaders()
    {
        // A request re-sent as POST with "X-HTTP-Method-Override: OPTIONS" after routing selected the POST endpoint.
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Options;
        request.Body = [];
        DefaultHttpContext context = request.Build();
        context.Request.Headers["X-HTTP-Method-Override"] = HttpMethods.Options;
        context.Request.Headers.Origin = "https://partner.example.com";
        context.Request.Headers.AccessControlRequestMethod = HttpMethods.Post;
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Post], acceptCorsPreflight: true));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("DELETE")]
    [InlineData("HEAD")]
    public async Task ValidateAsync_CorsPreflightAcceptance_DoesNotAcceptOtherMethods(string requestMethod)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = requestMethod;
        DefaultHttpContext context = request.Build();
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Put], acceptCorsPreflight: true));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_OptionsOnEndpointNotAcceptingCorsPreflight_ReturnsUnsignedMethodOverride()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Options;
        DefaultHttpContext context = request.Build();
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Put], acceptCorsPreflight: false));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    [InlineData("OPTIONS")]
    public async Task ValidateAsync_EndpointWithoutMethodMetadata_IsUnaffected(string requestMethod)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = requestMethod;
        DefaultHttpContext context = request.Build();
        SelectEndpoint(context, new object(), new SkipHmacValidationAttribute());

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
    }

    [Fact]
    public async Task ValidateAsync_EndpointWithEmptyMethodList_AcceptsAnyMethod()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Delete;
        DefaultHttpContext context = request.Build();
        SelectEndpoint(context, new HttpMethodMetadata([]));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("DELETE")]
    public async Task ValidateAsync_NoEndpointSelected_IsUnaffected(string requestMethod)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = requestMethod;
        DefaultHttpContext context = request.Build();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
    }

    [Fact]
    public async Task ValidateAsync_SeveralMethodMetadata_TheLastOneDecidesLikeRouting()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Delete;
        DefaultHttpContext rejected = request.Build();
        SelectEndpoint(rejected, new HttpMethodMetadata([HttpMethods.Delete]), new HttpMethodMetadata([HttpMethods.Post]));
        DefaultHttpContext accepted = request.Build();
        SelectEndpoint(accepted, new HttpMethodMetadata([HttpMethods.Post]), new HttpMethodMetadata([HttpMethods.Delete]));

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, (await _harness.ValidateAsync(rejected)).Failure);
        Assert.True((await _harness.ValidateAsync(accepted)).Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_OverrideHeaderMatchesAndEndpointAcceptsTheMethod_Succeeds()
    {
        // UseHttpMethodOverride() → UseRouting() → UseHmacAuthentication(): the endpoint was selected for the overriding method.
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Delete;
        DefaultHttpContext context = request.Build();
        context.Request.Headers[OverrideHeader] = HttpMethods.Delete;
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Delete]));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
    }

    [Fact]
    public async Task ValidateAsync_MethodNotAcceptedByEndpoint_IsLoggedWithTheClaimedClient()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Delete;
        DefaultHttpContext context = request.Build();
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Post]));

        await _harness.ValidateAsync(context);

        LogRecord log = Assert.Single(_logs.Find<HmacRequestValidator>(2));
        Assert.Equal(LogLevel.Warning, log.Level);
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, log.Properties["Failure"]);
        Assert.Equal(TestCredentials.ClientId, log.Properties["ClientId"]);
    }

    [Fact]
    public async Task ValidateAsync_MethodNotAcceptedByEndpoint_ResultIsCachedForTheRequest()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Delete;
        DefaultHttpContext context = request.Build();
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Post]));

        HmacValidationResult first = await _harness.ValidateAsync(context);
        SelectEndpoint(context, new HttpMethodMetadata([HttpMethods.Delete]));
        HmacValidationResult second = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, first.Failure);
        Assert.Equal(first, second);
    }

    [Fact]
    public async Task Pipeline_OverrideAfterImplicitRouting_SignedDeleteIsRejectedWithUnsignedMethodOverride()
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride();
            pipeline.UseHmacAuthentication();
            MapItems(pipeline);
        });

        using HttpResponseMessage response = await app.SendAsync(CreateOverriddenRequest(app, signedMethod: "DELETE", overrideMethod: "DELETE"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
        Assert.Equal(
            HmacValidationFailure.UnsignedMethodOverride,
            Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Fact]
    public async Task Pipeline_OverrideAfterImplicitRouting_SignatureOverTheWireMethodIsAlsoRejected()
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride();
            pipeline.UseHmacAuthentication();
            MapItems(pipeline);
        });

        using HttpResponseMessage response = await app.SendAsync(CreateOverriddenRequest(app, signedMethod: "POST", overrideMethod: "DELETE"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
    }

    [Fact]
    public async Task Pipeline_OverrideAfterImplicitRouting_RequestWithoutOverrideStillReachesItsHandler()
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride();
            pipeline.UseHmacAuthentication();
            MapItems(pipeline);
        });

        using HttpResponseMessage post = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, "/items/5", []));
        using HttpResponseMessage delete = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Delete, "/items/6"));

        Assert.Equal(HttpStatusCode.OK, post.StatusCode);
        Assert.Equal("POST 5 partner-a", await post.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal(HttpStatusCode.OK, delete.StatusCode);
        Assert.Equal("DELETE 6 partner-a", await delete.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task Pipeline_OverrideBeforeExplicitRouting_OverridingMethodIsVerifiedAndReachesItsHandler()
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride();
            pipeline.UseRouting();
            pipeline.UseHmacAuthentication();
            MapItems(pipeline);
        });

        using HttpResponseMessage response = await app.SendAsync(CreateOverriddenRequest(app, signedMethod: "DELETE", overrideMethod: "DELETE"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("DELETE 5 partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task Pipeline_HmacDefaultSchemeWithAuthenticationAfterOverride_OverridingMethodIsVerified()
    {
        // The documented order when HMAC is also the default authentication scheme.
        await using TestApplication app = await StartAsync(
            pipeline =>
            {
                pipeline.UseHttpMethodOverride();
                pipeline.UseRouting();
                pipeline.UseAuthentication();
                pipeline.UseHmacAuthentication();
                pipeline.UseAuthorization();
                MapItems(pipeline);
            },
            AddHmacDefaultScheme);

        using HttpResponseMessage response = await app.SendAsync(CreateOverriddenRequest(app, signedMethod: "DELETE", overrideMethod: "DELETE"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("DELETE 5 partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.True(Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Succeeded);
    }

    [Fact]
    public async Task Pipeline_HmacDefaultSchemeWithImplicitAuthenticationBeforeOverride_FailsClosed()
    {
        // WebApplication runs the implicit UseAuthentication() before user middleware, i.e. before the override: the
        // handler verifies the wire method, finds an override naming another method and rejects; the middleware reuses
        // that result. Legitimate overrides fail (hence the documented explicit UseAuthentication()), nothing is let through.
        await using TestApplication app = await StartAsync(
            pipeline =>
            {
                pipeline.UseHttpMethodOverride();
                pipeline.UseRouting();
                pipeline.UseHmacAuthentication();
                MapItems(pipeline);
            },
            AddHmacDefaultScheme);

        using HttpResponseMessage response = await app.SendAsync(CreateOverriddenRequest(app, signedMethod: "DELETE", overrideMethod: "DELETE"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
        Assert.All(
            app.Services.GetRequiredService<ValidationRecorder>().Results,
            result => Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure));
    }

    [Fact]
    public async Task Pipeline_OverrideAfterImplicitRouting_EndpointAcceptingBothMethodsRunsWithTheVerifiedMethod()
    {
        // One handler for POST and DELETE: the handler selected for the wire method also accepts the verified method.
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride();
            pipeline.UseHmacAuthentication();
            pipeline.MapMethods("/items/{id:int}", [HttpMethods.Post, HttpMethods.Delete], (HttpContext context, int id) =>
                $"{context.Request.Method} {id} {context.GetHmacClientId()}");
        });

        using HttpResponseMessage response = await app.SendAsync(CreateOverriddenRequest(app, signedMethod: "DELETE", overrideMethod: "DELETE"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("DELETE 5 partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task Pipeline_OverrideAfterImplicitRouting_EndpointWithoutMethodMetadataIsRejected()
    {
        // With an override header, the selected endpoint must list the method explicitly: an any-method endpoint could
        // otherwise run a handler that routing would never select for the signed method.
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride();
            pipeline.UseHmacAuthentication();
            pipeline.Map("/items/{id:int}", (HttpContext context, int id) => $"{context.Request.Method} {id} {context.GetHmacClientId()}");
        });

        using HttpResponseMessage response = await app.SendAsync(CreateOverriddenRequest(app, signedMethod: "DELETE", overrideMethod: "DELETE"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Pipeline_OverrideAfterImplicitRouting_UnmatchedRouteIsUnaffectedAndReturns404()
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride();
            pipeline.UseHmacAuthentication();
            MapItems(pipeline);
        });

        using HttpResponseMessage response = await app.SendAsync(CreateOverriddenRequest(app, signedMethod: "DELETE", overrideMethod: "DELETE", path: "/missing/5"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.True(Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Succeeded);
    }

    [Fact]
    public async Task Pipeline_SignedCorsPreflightToEndpointRequiringCors_IsAcceptedAndAnsweredByCors()
    {
        await using TestApplication app = await StartAsync(
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.UseCors();
                pipeline.MapPut("/cors/items", (HttpContext context) => context.GetHmacClientId() ?? "anonymous").RequireCors("partners");
            },
            AddPartnerCors);
        HttpRequestMessage preflight = app.CreateSignedRequest(HttpMethod.Options, "/cors/items");
        preflight.Headers.Add("Origin", PartnerOrigin);
        preflight.Headers.Add("Access-Control-Request-Method", "PUT");

        using HttpResponseMessage response = await app.SendAsync(preflight);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(PartnerOrigin, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.True(Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Succeeded);
    }

    [Fact]
    public async Task Pipeline_OverrideToOptionsAfterImplicitRouting_SignedOptionsCannotRunThePostHandler()
    {
        // The CORS preflight allowance must not reopen the hole the endpoint check closes: a (captured) request signed
        // for OPTIONS, re-sent as POST with an override header, is routed to the POST handler before the override is
        // applied. The verified method (OPTIONS) is not a method that handler serves.
        await using TestApplication app = await StartAsync(
            pipeline =>
            {
                pipeline.UseHttpMethodOverride();
                pipeline.UseHmacAuthentication();
                pipeline.UseCors();
                RequestCounter counter = pipeline.Services.GetRequiredService<RequestCounter>();
                pipeline.MapPost("/cors/items/{id:int}", (HttpContext context, int id) =>
                {
                    counter.Increment();
                    return $"POST handler ran as {context.Request.Method} for {context.GetHmacClientId()}";
                }).RequireCors("partners");
            },
            AddPartnerCors);

        using HttpResponseMessage response = await app.SendAsync(
            CreateOverriddenRequest(app, signedMethod: "OPTIONS", overrideMethod: "OPTIONS", path: "/cors/items/5"));

        string body = await response.Content.ReadAsStringAsync(CancellationToken);
        Assert.True(
            app.Services.GetRequiredService<RequestCounter>().Count == 0,
            $"A request signed for OPTIONS executed the POST handler: {(int)response.StatusCode} '{body}'.");
    }

    private static void AddHmacDefaultScheme(IServiceCollection services)
    {
        services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
        services.AddAuthorization();
    }

    private static void AddPartnerCors(IServiceCollection services) =>
        services.AddCors(options => options.AddPolicy(
            "partners",
            policy => policy.WithOrigins(PartnerOrigin).AllowAnyMethod().AllowAnyHeader()));

    private static void SelectEndpoint(HttpContext context, params object[] metadata) =>
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(metadata), "selected"));

    private static void MapItems(WebApplication app)
    {
        RequestCounter counter = app.Services.GetRequiredService<RequestCounter>();
        app.MapPost("/items/{id:int}", (HttpContext context, int id) =>
        {
            counter.Increment();
            return $"POST {id} {context.GetHmacClientId()}";
        });
        app.MapDelete("/items/{id:int}", (HttpContext context, int id) =>
        {
            counter.Increment();
            return $"DELETE {id} {context.GetHmacClientId()}";
        });
    }

    private static HttpRequestMessage CreateOverriddenRequest(TestApplication app, string signedMethod, string overrideMethod, string path = "/items/5")
    {
        string timestamp = TestCredentials.FormatTimestamp(app.Time.GetUtcNow().ToUnixTimeSeconds());
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(path, UriKind.Relative)) { Content = new ByteArrayContent([]) };
        request.Headers.Add(SafetalkHeaderNames.ClientId, TestCredentials.ClientId);
        request.Headers.Add(SafetalkHeaderNames.Timestamp, timestamp);
        request.Headers.Add(SafetalkHeaderNames.Signature, TestCredentials.Sign(signedMethod, path, timestamp, []));
        request.Headers.Add(OverrideHeader, overrideMethod);
        return request;
    }

    private static Task<TestApplication> StartAsync(Action<WebApplication> configurePipeline, Action<IServiceCollection>? configureServices = null) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
                builder.Services.AddValidationRecorder();
                configureServices?.Invoke(builder.Services);
            },
            configurePipeline);
}
