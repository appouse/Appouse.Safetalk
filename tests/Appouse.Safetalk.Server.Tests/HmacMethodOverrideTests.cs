using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacMethodOverrideTests : IDisposable
{
    private const string OverrideHeader = "X-HTTP-Method-Override";

    private readonly RecordingSecretProvider _secretProvider = RecordingSecretProvider.ForTestCredentials();
    private readonly LogCollector _logs = new();
    private readonly ValidatorHarness _harness;

    public HmacMethodOverrideTests()
    {
        _harness = new ValidatorHarness(_secretProvider, logger: _logs.CreateLogger<HmacRequestValidator>());
    }

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public void Dispose() => _logs.Dispose();

    [Theory]
    [InlineData("POST", "DELETE")]
    [InlineData("POST", "PUT")]
    [InlineData("POST", "GET")]
    [InlineData("POST", "PATCH")]
    [InlineData("GET", "DELETE")]
    [InlineData("PUT", "POST")]
    [InlineData("POST", "POST ")]
    [InlineData("POST", " POST")]
    [InlineData("POST", "POSTX")]
    [InlineData("POST", "")]
    public async Task ValidateAsync_OverrideNamingAnotherMethod_ReturnsUnsignedMethodOverrideBeforeSecretLookup(string method, string overrideValue)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = method;
        DefaultHttpContext context = request.Build();
        context.Request.Headers[OverrideHeader] = overrideValue;
        context.Request.Body = new ThrowingReadStream();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Empty(_secretProvider.RequestedClientIds);
        Assert.Null(context.GetHmacClientId());
    }

    [Theory]
    [InlineData("POST", "POST")]
    [InlineData("POST", "post")]
    [InlineData("POST", "Post")]
    [InlineData("DELETE", "delete")]
    [InlineData("PUT", "PUT")]
    public async Task ValidateAsync_OverrideEqualToVerifiedMethodIgnoringCase_IsAccepted(string method, string overrideValue)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = method;
        DefaultHttpContext context = request.Build();
        context.Request.Headers[OverrideHeader] = overrideValue;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData("x-http-method-override")]
    [InlineData("X-HTTP-METHOD-OVERRIDE")]
    [InlineData("x-Http-Method-Override")]
    public async Task ValidateAsync_OverrideHeaderNameInAnyCase_IsDetected(string headerName)
    {
        DefaultHttpContext context = _harness.NewRequest().Build();
        context.Request.Headers[headerName] = "DELETE";

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure);
    }

    [Theory]
    [InlineData("DELETE", "POST")]
    [InlineData("POST", "DELETE")]
    [InlineData("POST", "POST")]
    public async Task ValidateAsync_RepeatedOverrideHeader_IsRejected(string first, string second)
    {
        DefaultHttpContext context = _harness.NewRequest().Build();
        context.Request.Headers[OverrideHeader] = new StringValues([first, second]);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_OverrideAppliedToTheRequestMethod_VerifiesTheOverridingMethod()
    {
        // What UseHttpMethodOverride() does before this validator runs: the partner signs the overriding method.
        SignedRequestBuilder signedAsDelete = _harness.NewRequest();
        signedAsDelete.Method = HttpMethods.Delete;
        DefaultHttpContext accepted = signedAsDelete.Build();
        accepted.Request.Headers[OverrideHeader] = "DELETE";

        SignedRequestBuilder signedAsPost = _harness.NewRequest();
        DefaultHttpContext rejected = signedAsPost.Build();
        rejected.Request.Method = HttpMethods.Delete;
        rejected.Request.Headers[OverrideHeader] = "DELETE";

        Assert.True((await _harness.ValidateAsync(accepted)).Succeeded);
        Assert.Equal(HmacValidationFailure.InvalidSignature, (await _harness.ValidateAsync(rejected)).Failure);
    }

    [Fact]
    public async Task ValidateAsync_UnsignedMethodOverride_IsLoggedWithTheClaimedClient()
    {
        DefaultHttpContext context = _harness.NewRequest().Build();
        context.Request.Headers[OverrideHeader] = "DELETE";

        await _harness.ValidateAsync(context);

        LogRecord log = Assert.Single(_logs.Find<HmacRequestValidator>(2));
        Assert.Equal(LogLevel.Warning, log.Level);
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, log.Properties["Failure"]);
        Assert.Equal(TestCredentials.ClientId, log.Properties["ClientId"]);
    }

    [Fact]
    public async Task ValidateAsync_ExpiredTimestampAndOverride_ReportsTheCheaperTimestampFailure()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow - 3600);
        DefaultHttpContext context = request.Build();
        context.Request.Headers[OverrideHeader] = "DELETE";

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
    }

    [Fact]
    public async Task Pipeline_WithoutMethodOverrideMiddleware_OverrideHeaderIsRejectedAndNoHandlerRuns()
    {
        await using TestApplication app = await StartAsync(OverrideOrder.None);
        HttpRequestMessage request = app.CreateSignedRequest(HttpMethod.Post, "/items/5");
        request.Headers.Add(OverrideHeader, "DELETE");

        using HttpResponseMessage response = await app.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Fact]
    public async Task Pipeline_WithoutOverrideHeader_SignedPostStillReachesThePostHandler()
    {
        await using TestApplication app = await StartAsync(OverrideOrder.None);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, "/items/5"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("POST 5 partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task Pipeline_OverrideBeforeRoutingAndHmac_PartnerSigningTheOverridingMethodReachesThatHandler()
    {
        await using TestApplication app = await StartAsync(OverrideOrder.OverrideRoutingHmac);
        HttpRequestMessage request = CreateOverriddenRequest(app, signedMethod: "DELETE");

        using HttpResponseMessage response = await app.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("DELETE 5 partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task Pipeline_OverrideBeforeRoutingAndHmac_SignatureOverTheWireMethodIsRejected()
    {
        await using TestApplication app = await StartAsync(OverrideOrder.OverrideRoutingHmac);
        HttpRequestMessage request = CreateOverriddenRequest(app, signedMethod: "POST");

        using HttpResponseMessage response = await app.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HmacValidationFailure.InvalidSignature, Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Fact]
    public async Task Pipeline_OverrideAfterHmac_SignedPostCannotBeTurnedIntoADelete()
    {
        // The attack the check prevents: the signature covers POST, but a later UseHttpMethodOverride() would turn the
        // request into a DELETE and route it to another handler.
        await using TestApplication app = await StartAsync(OverrideOrder.HmacOverrideRouting);
        HttpRequestMessage request = CreateOverriddenRequest(app, signedMethod: "POST");

        using HttpResponseMessage response = await app.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Fact]
    public async Task Pipeline_OverrideAfterImplicitRouting_SignedDeleteCannotRunThePostHandler()
    {
        // With WebApplication's implicit routing, app.UseHttpMethodOverride() runs AFTER the endpoint was selected
        // with the wire method (POST). A captured request signed for DELETE, re-sent as POST with the override
        // header, must not execute the POST handler: the verified method differs from the selected endpoint's method.
        await using TestApplication app = await StartAsync(OverrideOrder.ImplicitRoutingOverrideHmac);
        HttpRequestMessage request = CreateOverriddenRequest(app, signedMethod: "DELETE");

        using HttpResponseMessage response = await app.SendAsync(request);

        string body = await response.Content.ReadAsStringAsync(CancellationToken);
        Assert.False(
            response.StatusCode == HttpStatusCode.OK,
            $"A request signed for DELETE executed another handler: {(int)response.StatusCode} '{body}'.");
    }

    private static HttpRequestMessage CreateOverriddenRequest(TestApplication app, string signedMethod)
    {
        string timestamp = TestCredentials.FormatTimestamp(app.Time.GetUtcNow().ToUnixTimeSeconds());
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/items/5", UriKind.Relative)) { Content = new ByteArrayContent([]) };
        request.Headers.Add(SafetalkHeaderNames.ClientId, TestCredentials.ClientId);
        request.Headers.Add(SafetalkHeaderNames.Timestamp, timestamp);
        request.Headers.Add(SafetalkHeaderNames.Signature, TestCredentials.Sign(signedMethod, "/items/5", timestamp, []));
        request.Headers.Add(OverrideHeader, "DELETE");
        return request;
    }

    private static Task<TestApplication> StartAsync(OverrideOrder order) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
                builder.Services.AddValidationRecorder();
            },
            app =>
            {
                RequestCounter counter = app.Services.GetRequiredService<RequestCounter>();
                switch (order)
                {
                    case OverrideOrder.None:
                        app.UseHmacAuthentication();
                        break;
                    case OverrideOrder.OverrideRoutingHmac:
                        app.UseHttpMethodOverride();
                        app.UseRouting();
                        app.UseHmacAuthentication();
                        break;
                    case OverrideOrder.HmacOverrideRouting:
                        app.UseHmacAuthentication();
                        app.UseHttpMethodOverride();
                        app.UseRouting();
                        break;
                    case OverrideOrder.ImplicitRoutingOverrideHmac:
                        app.UseHttpMethodOverride();
                        app.UseHmacAuthentication();
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(order), order, null);
                }

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
            });

    private enum OverrideOrder
    {
        None,
        OverrideRoutingHmac,
        HmacOverrideRouting,
        ImplicitRoutingOverrideHmac,
    }
}
