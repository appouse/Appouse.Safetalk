using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRequestValidatorClientIdTests : IDisposable
{
    private const int RequestRejectedEventId = 2;

    private readonly LogCollector _logs = new();
    private readonly RecordingSecretProvider _secretProvider = new(_ => TestCredentials.Secret);
    private readonly ValidatorHarness _harness;

    public HmacRequestValidatorClientIdTests()
    {
        _harness = new ValidatorHarness(_secretProvider, logger: _logs.CreateLogger<HmacRequestValidator>());
    }

    public static TheoryData<string> MalformedClientIds { get; } = new()
    {
        new string('a', SafetalkHeaderNames.MaxClientIdLength + 1),
        new string('a', 64 * 1024),
        "partner-ä",
        "partnér",
        "partner-€",
        "partner-😀",
        "İstanbul",
        "partner\u0000a",
        "partner\u0001a",
        "partner\ta",
        "partner\u001f",
        "partner\u007f",
        "partner\u0085",
        "partner a",
        "partner​a",
        "﻿partner-a",
    };

    public static TheoryData<string> WellFormedClientIds { get; } = new()
    {
        "a",
        " ",
        "~",
        "partner a",
        " partner-a ",
        "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        new string('z', SafetalkHeaderNames.MaxClientIdLength),
    };

    public void Dispose() => _logs.Dispose();

    [Fact]
    public void MaxClientIdLength_Is256()
    {
        Assert.Equal(256, SafetalkHeaderNames.MaxClientIdLength);
    }

    [Theory]
    [MemberData(nameof(MalformedClientIds))]
    public async Task ValidateAsync_MalformedClientId_ReturnsUnknownClientWithoutQueryingTheSecretProvider(string clientId)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = clientId;
        DefaultHttpContext context = request.Build();
        context.Request.Body = new ThrowingReadStream();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
        Assert.Null(result.ClientId);
        Assert.Empty(_secretProvider.RequestedClientIds);
        Assert.Null(context.GetHmacClientId());
    }

    [Theory]
    [MemberData(nameof(MalformedClientIds))]
    public async Task ValidateAsync_MalformedClientId_IsLoggedWithoutTheClaimedValue(string clientId)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = clientId;

        await _harness.ValidateAsync(request.Build());

        LogRecord log = Assert.Single(_logs.Find<HmacRequestValidator>(RequestRejectedEventId));
        Assert.Equal(LogLevel.Warning, log.Level);
        Assert.Equal(HmacValidationFailure.UnknownClient, log.Properties["Failure"]);
        Assert.Null(log.Properties["ClientId"]);
        Assert.DoesNotContain(clientId, log.Message, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(WellFormedClientIds))]
    public async Task ValidateAsync_WellFormedClientId_IsLookedUpVerbatimAndCanSucceed(string clientId)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = clientId;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
        Assert.Equal(clientId, result.ClientId);
        Assert.Equal([clientId], _secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_ClientIdAtMaximumLengthUnknownToProvider_ReportsItAsClaimed()
    {
        var harness = new ValidatorHarness(RecordingSecretProvider.ForTestCredentials());
        SignedRequestBuilder request = harness.NewRequest();
        string clientId = new('x', SafetalkHeaderNames.MaxClientIdLength);
        request.ClientId = clientId;

        HmacValidationResult result = await harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
        Assert.Equal(clientId, result.ClientId);
    }

    [Theory]
    [InlineData(SafetalkHeaderNames.Timestamp)]
    [InlineData(SafetalkHeaderNames.Signature)]
    public async Task ValidateAsync_MissingHeaderAndMalformedClientId_DoesNotReportTheClaimedValue(string missingHeader)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = "partner\u0001a";
        DefaultHttpContext context = request.Build();
        context.Request.Headers.Remove(missingHeader);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure);
        Assert.Null(result.ClientId);
        Assert.Null(Assert.Single(_logs.Find<HmacRequestValidator>(RequestRejectedEventId)).Properties["ClientId"]);
    }

    [Fact]
    public async Task ValidateAsync_MalformedClientId_IsRejectedBeforeTimestampAndBodyChecks()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = new string('a', SafetalkHeaderNames.MaxClientIdLength + 1);
        request.Timestamp = "not-a-number";
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = long.MaxValue;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
    }

    [Fact]
    public async Task Pipeline_OverlongClientId_Returns401WithoutQueryingTheSecretProvider()
    {
        var secretProvider = RecordingSecretProvider.ForTestCredentials();
        await using TestApplication app = await TestApplication.StartAsync(
            builder => builder.Services.AddHmacServer().AddSecretProvider(_ => secretProvider, ServiceLifetime.Singleton),
            pipeline =>
            {
                pipeline.UseHmacAuthentication();
                pipeline.MapGet("/b2b", (HttpContext context) => context.GetHmacClientId() ?? "anonymous");
            });
        string clientId = new('a', SafetalkHeaderNames.MaxClientIdLength + 1);

        using HttpResponseMessage overlong = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b", clientId: clientId));
        using HttpResponseMessage valid = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/b2b"));

        Assert.Equal(HttpStatusCode.Unauthorized, overlong.StatusCode);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        Assert.Equal([TestCredentials.ClientId], secretProvider.RequestedClientIds);
    }
}
