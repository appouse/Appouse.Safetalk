using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRequestValidatorCachingTests
{
    private static readonly byte[] OrderJson = """{"orderId":42,"quantity":3}"""u8.ToArray();

    private readonly RecordingSecretProvider _secretProvider = RecordingSecretProvider.ForTestCredentials();

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ValidateAsync_CalledAgainAfterSuccess_ReturnsFirstResultWithoutLookupBodyReadOrReplayEntry()
    {
        var replayCache = new RecordingReplayCache();
        var harness = new ValidatorHarness(_secretProvider, replayCache);
        harness.Options.EnableReplayProtection = true;
        DefaultHttpContext context = harness.NewRequest().Build();

        HmacValidationResult first = await harness.ValidateAsync(context);
        context.Request.Body = new ThrowingReadStream();
        HmacValidationResult second = await harness.ValidateAsync(context);
        HmacValidationResult third = await harness.ValidateAsync(context);

        Assert.True(first.Succeeded);
        Assert.Equal(first, second);
        Assert.Equal(first, third);
        Assert.Equal([TestCredentials.ClientId], _secretProvider.RequestedClientIds);
        Assert.Single(replayCache.Calls);
    }

    [Fact]
    public async Task ValidateAsync_CalledAgainWithRealReplayCache_IsNotReportedAsItsOwnReplay()
    {
        var harness = new ValidatorHarness(_secretProvider);
        harness.Options.EnableReplayProtection = true;
        DefaultHttpContext context = harness.NewRequest().Build();

        HmacValidationResult first = await harness.ValidateAsync(context);
        HmacValidationResult second = await harness.ValidateAsync(context);

        Assert.True(first.Succeeded);
        Assert.True(second.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_CalledAgainAfterFailure_ReturnsFirstFailureEvenWhenTheRequestIsFixedInBetween()
    {
        var harness = new ValidatorHarness(_secretProvider);
        SignedRequestBuilder request = harness.NewRequest();
        DefaultHttpContext context = request.Build(new string('0', HmacSha256SignatureService.SignatureHexLength));

        HmacValidationResult first = await harness.ValidateAsync(context);
        context.Request.Headers[SafetalkHeaderNames.Signature] = request.Signature;
        context.Request.Body = new ThrowingReadStream();
        HmacValidationResult second = await harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.InvalidSignature, first.Failure);
        Assert.Equal(first, second);
        Assert.Equal([TestCredentials.ClientId], _secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_CalledAgainAfterEarlyFailure_DoesNotLookUpSecretsLater()
    {
        var harness = new ValidatorHarness(_secretProvider);
        SignedRequestBuilder request = harness.NewRequest();
        DefaultHttpContext context = request.Build();
        context.Request.Headers.Remove(SafetalkHeaderNames.Signature);

        HmacValidationResult first = await harness.ValidateAsync(context);
        context.Request.Headers[SafetalkHeaderNames.Signature] = request.Signature;
        HmacValidationResult second = await harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.MissingHeaders, first.Failure);
        Assert.Equal(first, second);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_CalledAgainAfterReplayDetected_StaysRejected()
    {
        var harness = new ValidatorHarness(_secretProvider);
        harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = harness.NewRequest();
        string signature = request.Signature;
        Assert.True((await harness.ValidateAsync(request.Build(signature))).Succeeded);
        DefaultHttpContext replay = request.Build(signature);

        HmacValidationResult first = await harness.ValidateAsync(replay);
        HmacValidationResult second = await harness.ValidateAsync(replay);

        Assert.Equal(HmacValidationFailure.ReplayDetected, first.Failure);
        Assert.Equal(first, second);
        Assert.Null(replay.GetHmacClientId());
    }

    [Fact]
    public async Task ValidateAsync_Success_CachesTheResultButDoesNotMarkTheRequestVerified()
    {
        // Only the consumers of the registered validator (middleware, authentication handler) mark a request as
        // verified, so that a decorating validator can still reject a success. Custom callers use the returned result.
        var harness = new ValidatorHarness(_secretProvider);
        DefaultHttpContext context = harness.NewRequest().Build();

        HmacValidationResult result = await harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Equal(result, Assert.IsType<HmacValidationResultFeature>(context.Features.Get<HmacValidationResultFeature>()).Result);
        Assert.Null(context.Features.Get<IHmacClientFeature>());
        Assert.Null(context.GetHmacClientId());
        Assert.Null(HmacClientIdentity.GetVerifiedClientId(context));
        Assert.False(context.User.Identity?.IsAuthenticated ?? false);
    }

    [Theory]
    [InlineData(HmacValidationFailure.MissingHeaders)]
    [InlineData(HmacValidationFailure.UnknownClient)]
    [InlineData(HmacValidationFailure.InvalidSignature)]
    public async Task ValidateAsync_Failure_DoesNotRecordAClient(HmacValidationFailure expected)
    {
        var harness = new ValidatorHarness(_secretProvider);
        SignedRequestBuilder request = harness.NewRequest();
        DefaultHttpContext context = expected switch
        {
            HmacValidationFailure.MissingHeaders => new DefaultHttpContext(),
            HmacValidationFailure.UnknownClient => BuildForClient(request, "partner-z"),
            _ => request.Build(new string('0', HmacSha256SignatureService.SignatureHexLength)),
        };

        HmacValidationResult result = await harness.ValidateAsync(context);

        Assert.Equal(expected, result.Failure);
        Assert.Null(context.Features.Get<IHmacClientFeature>());
        Assert.Null(HmacClientIdentity.GetVerifiedClientId(context));
    }

    [Fact]
    public async Task ValidateAsync_ResultIsPerRequest_AnotherValidatorInstanceGetsTheSameAnswer()
    {
        // The cache lives on the request, not on the validator: a second (scoped) validator instance, for example one
        // resolved by the authentication handler, does not verify again.
        var first = new ValidatorHarness(_secretProvider);
        var otherProvider = RecordingSecretProvider.ForTestCredentials();
        var second = new ValidatorHarness(otherProvider);
        DefaultHttpContext context = first.NewRequest().Build();

        HmacValidationResult firstResult = await first.ValidateAsync(context);
        HmacValidationResult secondResult = await second.ValidateAsync(context);

        Assert.True(firstResult.Succeeded);
        Assert.Equal(firstResult, secondResult);
        Assert.Empty(otherProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_DifferentRequests_AreValidatedIndependently()
    {
        var harness = new ValidatorHarness(_secretProvider);
        DefaultHttpContext valid = harness.NewRequest().Build();
        DefaultHttpContext invalid = harness.NewRequest().Build(new string('0', HmacSha256SignatureService.SignatureHexLength));

        HmacValidationResult validResult = await harness.ValidateAsync(valid);
        HmacValidationResult invalidResult = await harness.ValidateAsync(invalid);

        Assert.True(validResult.Succeeded);
        Assert.Equal(HmacValidationFailure.InvalidSignature, invalidResult.Failure);
        Assert.Equal(2, _secretProvider.RequestedClientIds.Count);
    }

    [Fact]
    public async Task ValidateAsync_SecretProviderThrows_IsNotCachedAndTheNextCallValidates()
    {
        int calls = 0;
        var flakyProvider = new RecordingSecretProvider(clientId => ++calls == 1
            ? throw new TimeoutException("The secret store is unavailable.")
            : TestCredentials.Secrets.GetValueOrDefault(clientId));
        var harness = new ValidatorHarness(flakyProvider);
        DefaultHttpContext context = harness.NewRequest().Build();

        await Assert.ThrowsAsync<TimeoutException>(() => harness.ValidateAsync(context).AsTask());
        HmacValidationResult retry = await harness.ValidateAsync(context);

        Assert.True(retry.Succeeded);
        Assert.Equal(2, flakyProvider.RequestedClientIds.Count);
    }

    [Fact]
    public async Task ValidateAsync_CancelledWhileReadingBody_IsNotCachedAndTheBodyIsStillComplete()
    {
        var harness = new ValidatorHarness(_secretProvider);
        SignedRequestBuilder request = harness.NewRequest();
        DefaultHttpContext context = request.Build();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => harness.Validator.ValidateAsync(context, cancelled.Token).AsTask());
        HmacValidationResult retry = await harness.ValidateAsync(context);

        Assert.True(retry.Succeeded);
        using var reader = new StreamReader(context.Request.Body);
        Assert.Equal(request.Body, System.Text.Encoding.UTF8.GetBytes(await reader.ReadToEndAsync(CancellationToken)));
    }

    [Fact]
    public async Task Pipeline_CustomCallerMiddlewareAndAuthenticationHandler_ValidateOnceWithReplayProtection()
    {
        await using TestApplication app = await StartAsync(_secretProvider);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Post, "/b2b/echo", OrderJson));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("partner-a|True|partner-a|{\"orderId\":42,\"quantity\":3}", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal([TestCredentials.ClientId], _secretProvider.RequestedClientIds);
        Assert.Equal(1, ((InMemoryHmacReplayCache)app.Services.GetRequiredService<IHmacReplayCache>()).Count);
    }

    [Fact]
    public async Task Pipeline_CustomCallerMiddlewareAndAuthenticationHandler_InvalidSignatureIsVerifiedOnceAndRejected()
    {
        await using TestApplication app = await StartAsync(_secretProvider);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(
            HttpMethod.Get, "/b2b/whoami", clientId: TestCredentials.ClientId, secret: "wrong-secret"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.Equal([TestCredentials.ClientId], _secretProvider.RequestedClientIds);
        Assert.Equal(0, ((InMemoryHmacReplayCache)app.Services.GetRequiredService<IHmacReplayCache>()).Count);
    }

    [Fact]
    public async Task Pipeline_CustomCallerMiddlewareAndAuthenticationHandler_ReplayIsRejectedAfterASingleVerification()
    {
        await using TestApplication app = await StartAsync(_secretProvider);
        HttpRequestMessage original = app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami");
        HttpRequestMessage replay = app.CreateSignedRequest(HttpMethod.Get, "/b2b/whoami");

        using HttpResponseMessage accepted = await app.SendAsync(original);
        using HttpResponseMessage rejected = await app.SendAsync(replay);

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        Assert.Equal([TestCredentials.ClientId, TestCredentials.ClientId], _secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task Pipeline_ReauthenticatingAfterAFailedVerification_DoesNotVerifyAgain()
    {
        await using TestApplication app = await StartAsync(_secretProvider);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(
            HttpMethod.Get, "/open/reauthenticate", clientId: TestCredentials.ClientId, secret: "wrong-secret"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("False|False|False", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal([TestCredentials.ClientId], _secretProvider.RequestedClientIds);
    }

    private static DefaultHttpContext BuildForClient(SignedRequestBuilder request, string clientId)
    {
        request.ClientId = clientId;
        return request.Build();
    }

    private static Task<TestApplication> StartAsync(RecordingSecretProvider secretProvider) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services
                    .AddHmacServer()
                    .AddSecretProvider(_ => secretProvider, ServiceLifetime.Singleton)
                    .AddReplayProtection();
                builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
                builder.Services.AddAuthorization();
            },
            app =>
            {
                // A custom caller that inspects the result but never short-circuits (for example audit logging).
                app.Use(async (HttpContext context, RequestDelegate next) =>
                {
                    HmacValidationResult result = await context.RequestServices
                        .GetRequiredService<IHmacRequestValidator>()
                        .ValidateAsync(context, context.RequestAborted);
                    context.Items["custom-caller"] = result.Succeeded;
                    await next(context);
                });
                app.UseAuthentication();
                app.UseHmacAuthentication();
                app.UseAuthorization();

                app.MapPost("/b2b/echo", async (HttpContext context) =>
                {
                    using var reader = new StreamReader(context.Request.Body);
                    string body = await reader.ReadToEndAsync(context.RequestAborted);
                    return $"{context.User.Identity?.Name}|{context.Items["custom-caller"]}|{context.GetHmacClientId()}|{body}";
                }).RequireAuthorization();
                app.MapGet("/b2b/whoami", (HttpContext context) => context.User.Identity?.Name ?? "anonymous").RequireAuthorization();
                app.MapGet("/open/reauthenticate", async (HttpContext context) =>
                {
                    AuthenticateResult first = await context.AuthenticateAsync(HmacAuthenticationDefaults.AuthenticationScheme);
                    AuthenticateResult second = await context.AuthenticateAsync(HmacAuthenticationDefaults.AuthenticationScheme);
                    return $"{context.Items["custom-caller"]}|{first.Succeeded}|{second.Succeeded}";
                }).SkipHmacValidation();
            });
}
