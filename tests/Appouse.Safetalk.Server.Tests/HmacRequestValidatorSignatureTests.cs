using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRequestValidatorSignatureTests
{
    private readonly ValidatorHarness _harness = new();

    [Fact]
    public async Task ValidateAsync_UpperCaseHexSignature_Succeeds()
    {
        SignedRequestBuilder request = _harness.NewRequest();

        HmacValidationResult result = await _harness.ValidateAsync(request.Build(request.Signature.ToUpperInvariant()));

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_ClientSignedLowerCaseMethod_SucceedsBecauseMethodIsNormalized()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = "post";
        string signature = request.Signature;
        request.Method = HttpMethods.Post;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build(signature));

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public async Task ValidateAsync_OtherHttpMethods_Succeed(string method)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = method;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData("method")]
    [InlineData("path")]
    [InlineData("query")]
    [InlineData("query-removed")]
    [InlineData("timestamp")]
    [InlineData("body")]
    [InlineData("body-truncated")]
    public async Task ValidateAsync_RequestAlteredAfterSigning_ReturnsInvalidSignature(string alteredPart)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        switch (alteredPart)
        {
            case "method":
                request.Method = HttpMethods.Put;
                break;
            case "path":
                request.Path = "/api/orders/6";
                break;
            case "query":
                request.Query = "?id=6";
                break;
            case "query-removed":
                request.Query = string.Empty;
                break;
            case "timestamp":
                request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow - 1);
                break;
            case "body":
                request.Body = """{"orderId":5,"amount":4250}"""u8.ToArray();
                break;
            case "body-truncated":
                request.Body = request.Body[..^1];
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(alteredPart), alteredPart, "Unknown part.");
        }

        HmacValidationResult result = await _harness.ValidateAsync(request.Build(signature));

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
    }

    [Theory]
    [InlineData("truncated")]
    [InlineData("extended")]
    [InlineData("non-hex")]
    [InlineData("whitespace-padded")]
    [InlineData("base64")]
    [InlineData("last-nibble-flipped")]
    [InlineData("short-garbage")]
    public async Task ValidateAsync_MalformedOrWrongSignature_ReturnsInvalidSignature(string kind)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        string valid = request.Signature;
        string signature = kind switch
        {
            "truncated" => valid[..^1],
            "extended" => valid + "0",
            "non-hex" => "g" + valid[1..],
            "whitespace-padded" => " " + valid,
            "base64" => Convert.ToBase64String(Convert.FromHexString(valid)),
            "last-nibble-flipped" => valid[..^1] + (valid[^1] == '0' ? '1' : '0'),
            "short-garbage" => "abc",
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown kind."),
        };

        HmacValidationResult result = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_SignedWithAnotherClientsSecret_ReturnsInvalidSignature()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Secret = TestCredentials.OtherSecret;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_ClientImpersonatesAnotherClientWithOwnSecret_ReturnsInvalidSignature()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = TestCredentials.OtherClientId;
        request.Secret = TestCredentials.Secret;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
        Assert.Equal(TestCredentials.OtherClientId, result.ClientId);
    }

    [Fact]
    public async Task ValidateAsync_SecondClientWithOwnSecret_SucceedsWithItsClientId()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = TestCredentials.OtherClientId;
        request.Secret = TestCredentials.OtherSecret;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
        Assert.Equal(TestCredentials.OtherClientId, result.ClientId);
    }

    [Fact]
    public async Task ValidateAsync_UnknownClient_ReturnsUnknownClientWithClaimedId()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = "partner-unknown";

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
        Assert.Equal("partner-unknown", result.ClientId);
    }

    [Fact]
    public async Task ValidateAsync_ClientIdDiffersOnlyByCase_ReturnsUnknownClient()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = TestCredentials.ClientId.ToUpperInvariant();

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ValidateAsync_ProviderReturnsNoSecret_ReturnsUnknownClient(string? secret)
    {
        var harness = new ValidatorHarness(new RecordingSecretProvider(_ => secret));

        HmacValidationResult result = await harness.ValidateAsync(harness.NewRequest().Build());

        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_SecretProvider_ReceivesClientIdAndCancellationToken()
    {
        var secretProvider = RecordingSecretProvider.ForTestCredentials();
        var harness = new ValidatorHarness(secretProvider);
        using var cancellation = new CancellationTokenSource();

        HmacValidationResult result = await harness.Validator.ValidateAsync(harness.NewRequest().Build(), cancellation.Token);

        Assert.True(result.Succeeded);
        Assert.Equal([TestCredentials.ClientId], secretProvider.RequestedClientIds);
        Assert.Equal(cancellation.Token, secretProvider.LastCancellationToken);
    }

    [Fact]
    public async Task ValidateAsync_NullContext_ThrowsArgumentNullException()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _harness.Validator.ValidateAsync(null!, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void Constructor_NullDependency_ThrowsArgumentNullException()
    {
        IHmacSecretProvider secrets = TestCredentials.CreateSecretProvider();
        IHmacSignatureService signatures = HmacSha256SignatureService.Instance;
        IHmacReplayCache cache = new RecordingReplayCache();
        var options = new StaticOptionsMonitor<HmacServerOptions>(new HmacServerOptions());
        TimeProvider time = TimeProvider.System;
        NullLogger<HmacRequestValidator> logger = NullLogger<HmacRequestValidator>.Instance;

        Assert.Throws<ArgumentNullException>("secretProvider", () => new HmacRequestValidator(null!, signatures, cache, options, time, logger));
        Assert.Throws<ArgumentNullException>("signatureService", () => new HmacRequestValidator(secrets, null!, cache, options, time, logger));
        Assert.Throws<ArgumentNullException>("replayCache", () => new HmacRequestValidator(secrets, signatures, null!, options, time, logger));
        Assert.Throws<ArgumentNullException>("options", () => new HmacRequestValidator(secrets, signatures, cache, null!, time, logger));
        Assert.Throws<ArgumentNullException>("timeProvider", () => new HmacRequestValidator(secrets, signatures, cache, options, null!, logger));
        Assert.Throws<ArgumentNullException>("logger", () => new HmacRequestValidator(secrets, signatures, cache, options, time, null!));
    }
}
