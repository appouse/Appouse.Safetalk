using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacKestrelRequestTargetTests
{
    [Fact]
    public async Task OriginFormTarget_WithEncodedReservedCharacters_IsVerifiedAgainstRawTarget()
    {
        await using KestrelApplication app = await StartAsync();
        const string Target = "/api/users/%40me?filter=a%3Ab";
        string timestamp = app.Timestamp;

        int status = await app.SendRawAsync($"GET {Target} HTTP/1.1", timestamp, TestCredentials.Sign("GET", Target, timestamp, []));

        Assert.Equal(StatusCodes.Status200OK, status);
    }

    [Theory]
    [InlineData("/api/users/%40me", "/api/users/@me")]
    [InlineData("/api/users/a%3ab", "/api/users/a%3Ab")]
    [InlineData("/api/users/a%3ab", "/api/users/a:b")]
    [InlineData("/api/users/a%2Bb", "/api/users/a+b")]
    public async Task OriginFormTarget_SignedOverDecodedOrReEncodedForm_IsRejected(string sentTarget, string signedTarget)
    {
        await using KestrelApplication app = await StartAsync();
        string timestamp = app.Timestamp;

        int status = await app.SendRawAsync($"GET {sentTarget} HTTP/1.1", timestamp, TestCredentials.Sign("GET", signedTarget, timestamp, []));

        Assert.Equal(StatusCodes.Status401Unauthorized, status);
        Assert.Equal(
            HmacValidationFailure.InvalidSignature,
            Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Theory]
    [InlineData("/api/users/a%3ab")]
    [InlineData("/api/users/a%2Bb")]
    [InlineData("/api/users/%E2%82%AC")]
    public async Task OriginFormTarget_SignedVerbatim_IsAccepted(string target)
    {
        await using KestrelApplication app = await StartAsync();
        string timestamp = app.Timestamp;

        int status = await app.SendRawAsync($"GET {target} HTTP/1.1", timestamp, TestCredentials.Sign("GET", target, timestamp, []));

        Assert.Equal(StatusCodes.Status200OK, status);
    }

    [Theory]
    [InlineData("/api/users/me")]
    [InlineData("{0}/api/users/me")]
    public async Task AbsoluteFormTarget_IsRejectedWithInvalidRequestTarget(string signedTargetFormat)
    {
        await using KestrelApplication app = await StartAsync();
        string absolute = $"http://127.0.0.1:{app.Port}";
        string signedTarget = string.Format(System.Globalization.CultureInfo.InvariantCulture, signedTargetFormat, absolute);
        string timestamp = app.Timestamp;

        int status = await app.SendRawAsync($"GET {absolute}/api/users/me HTTP/1.1", timestamp, TestCredentials.Sign("GET", signedTarget, timestamp, []));

        Assert.Equal(StatusCodes.Status401Unauthorized, status);
        HmacValidationResult validation = Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, validation.Failure);
    }

    [Fact]
    public async Task AsteriskFormOptionsRequest_IsRejectedWithInvalidRequestTarget()
    {
        await using KestrelApplication app = await StartAsync();
        string timestamp = app.Timestamp;

        int status = await app.SendRawAsync("OPTIONS * HTTP/1.1", timestamp, TestCredentials.Sign("OPTIONS", "*", timestamp, []));

        Assert.Equal(StatusCodes.Status401Unauthorized, status);
        HmacValidationResult validation = Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results);
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, validation.Failure);
    }

    private static Task<KestrelApplication> StartAsync() =>
        KestrelApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
                builder.Services.AddValidationRecorder();
            },
            app =>
            {
                app.UseHmacAuthentication();
                app.MapGet("/api/users/{name}", (HttpContext context, string name) => $"{name}:{context.GetHmacClientId()}");
            });
}
