using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacReExecutionPipelineTests
{
    private static readonly byte[] OrderJson = """{"orderId":42,"quantity":3}"""u8.ToArray();

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task StatusCodePagesReExecute_SignedRequestToUnknownRoute_ReturnsOriginal404AndValidatesOnce()
    {
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseStatusCodePagesWithReExecute("/error/{0}"));

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/missing"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("error 404 for partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Empty(response.Headers.WwwAuthenticate);
        HmacValidationResult validation = Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
        Assert.True(validation.Succeeded);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_SignedPostWithBodyToUnknownRoute_ReturnsOriginal404()
    {
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseStatusCodePagesWithReExecute("/error/{0}"));

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, "/api/missing", OrderJson));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_EndpointReturning400_KeepsStatusAndValidatesOnce()
    {
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseStatusCodePagesWithReExecute("/error/{0}"));

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/bad-request"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("error 400 for partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_UnsignedRequest_StillReturns401WithChallenge()
    {
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseStatusCodePagesWithReExecute("/error/{0}"));

        using HttpResponseMessage response = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri("/api/ok", UriKind.Relative)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(response.Headers.WwwAuthenticate);
        Assert.DoesNotContain(app.Services.GetRequiredService<ValidationRecorder>().Results, result => result.Succeeded);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_UnsignedRequestWithSkippedErrorEndpoint_RendersErrorPageWith401()
    {
        await using TestApplication app = await StartAsync(
            pipeline => pipeline.UseStatusCodePagesWithReExecute("/error/{0}"),
            skipErrorEndpoint: true);

        using HttpResponseMessage response = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri("/api/ok", UriKind.Relative)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error 401 for anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task ExceptionHandler_SignedRequestToThrowingEndpoint_ReturnsOriginal500AndValidatesOnce()
    {
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseExceptionHandler("/error/500"));

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/throws"));

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("error 500 for partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Empty(response.Headers.WwwAuthenticate);
        HmacValidationResult validation = Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
        Assert.True(validation.Succeeded);
    }

    [Fact]
    public async Task ExceptionHandler_SignedPostToEndpointThatThrowsAfterReadingBody_ReturnsOriginal500()
    {
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseExceptionHandler("/error/500"));

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, "/api/throws-after-body", OrderJson));

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("error 500 for partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
    }

    [Fact]
    public async Task ExceptionHandlerAndStatusCodePages_Combined_ValidateOnce()
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseExceptionHandler("/error/500");
            pipeline.UseStatusCodePagesWithReExecute("/error/{0}");
        });

        using HttpResponseMessage thrown = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/throws"));
        using HttpResponseMessage missing = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/missing"));

        Assert.Equal(HttpStatusCode.InternalServerError, thrown.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal(2, app.Services.GetRequiredService<ValidationRecorder>().Results.Count);
    }

    [Fact]
    public async Task ReExecution_DoesNotLetAReplayThrough()
    {
        // The re-execution guard is per HttpContext: an identical second request is still a replay.
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseStatusCodePagesWithReExecute("/error/{0}"));

        using HttpResponseMessage first = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/missing"));
        using HttpResponseMessage replay = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/api/missing"));

        Assert.Equal(HttpStatusCode.NotFound, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task StatusCodePagesReExecute_InvalidSignature_ReExecutionReusesTheFailureWithoutVerifyingAgain()
    {
        var secrets = RecordingSecretProvider.ForTestCredentials();
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseStatusCodePagesWithReExecute("/error/{0}"), secrets: secrets);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(
            HttpMethod.Get, "/api/ok", clientId: TestCredentials.ClientId, secret: "wrong-secret"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal([TestCredentials.ClientId], secrets.RequestedClientIds);
        Assert.All(
            app.Services.GetRequiredService<ValidationRecorder>().Results,
            result => Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure));
    }

    [Fact]
    public async Task ExceptionHandler_SignedRequest_ReExecutionDoesNotLookUpTheSecretAgain()
    {
        var secrets = RecordingSecretProvider.ForTestCredentials();
        await using TestApplication app = await StartAsync(pipeline => pipeline.UseExceptionHandler("/error/500"), secrets: secrets);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, "/api/throws-after-body", OrderJson));

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("error 500 for partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal([TestCredentials.ClientId], secrets.RequestedClientIds);
    }

    private static Task<TestApplication> StartAsync(
        Action<WebApplication> errorHandling,
        bool skipErrorEndpoint = false,
        IHmacSecretProvider? secrets = null) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services
                    .AddHmacServer()
                    .AddSecretProvider(_ => secrets ?? TestCredentials.CreateSecretProvider(), ServiceLifetime.Singleton)
                    .AddReplayProtection();
                builder.Services.AddValidationRecorder();
            },
            app =>
            {
                errorHandling(app);
                app.UseHmacAuthentication();

                RouteHandlerBuilder error = app.MapMethods(
                    "/error/{code:int}",
                    [HttpMethods.Get, HttpMethods.Post],
                    (HttpContext context, int code) => context.Response.WriteAsync($"error {code} for {context.GetHmacClientId() ?? "anonymous"}", context.RequestAborted));
                if (skipErrorEndpoint)
                {
                    error.SkipHmacValidation();
                }

                app.MapGet("/api/ok", (HttpContext context) => context.GetHmacClientId() ?? "anonymous");
                app.MapGet("/api/bad-request", () => Results.StatusCode(StatusCodes.Status400BadRequest));
                app.MapGet("/api/throws", string () => throw new InvalidOperationException("Endpoint failure."));
                app.MapPost("/api/throws-after-body", async (HttpContext context) =>
                {
                    using var reader = new StreamReader(context.Request.Body);
                    await reader.ReadToEndAsync(context.RequestAborted);
                    throw new InvalidOperationException("Endpoint failure after reading the body.");
                });
            });
}
