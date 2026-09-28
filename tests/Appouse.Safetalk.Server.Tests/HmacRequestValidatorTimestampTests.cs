using System.Globalization;
using Appouse.Safetalk.Server.Tests.Infrastructure;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRequestValidatorTimestampTests
{
    private readonly RecordingSecretProvider _secretProvider = RecordingSecretProvider.ForTestCredentials();
    private readonly ValidatorHarness _harness;

    public HmacRequestValidatorTimestampTests()
    {
        _harness = new ValidatorHarness(_secretProvider);
    }

    [Theory]
    [InlineData("+{0}")]
    [InlineData(" {0}")]
    [InlineData("{0} ")]
    [InlineData("-{0}")]
    [InlineData("{0}.0")]
    [InlineData("{0}.5")]
    [InlineData("{0}e0")]
    [InlineData("0x{0}")]
    [InlineData("{0},0")]
    [InlineData("+123")]
    [InlineData(" 123")]
    [InlineData("-1")]
    [InlineData("abc")]
    [InlineData("1.5")]
    [InlineData("99999999999999999999")]
    [InlineData("9223372036854775808")]
    [InlineData("١٧٠٠")]
    [InlineData("１７００")]
    public async Task ValidateAsync_MalformedTimestamp_ReturnsInvalidTimestamp(string timestampFormat)
    {
        // The request is signed over the malformed value, so only the timestamp format can cause the rejection.
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = string.Format(CultureInfo.InvariantCulture, timestampFormat, _harness.UnixNow);

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.InvalidTimestamp, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1)]
    [InlineData(-299)]
    [InlineData(299)]
    [InlineData(-300)]
    [InlineData(300)]
    public async Task ValidateAsync_TimestampWithinDefaultClockSkew_Succeeds(int offsetSeconds)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow + offsetSeconds);

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(-301)]
    [InlineData(301)]
    [InlineData(-86_400)]
    [InlineData(86_400)]
    public async Task ValidateAsync_TimestampOutsideDefaultClockSkew_ReturnsTimestampOutOfRange(int offsetSeconds)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow + offsetSeconds);

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_RequestAgesPastClockSkew_ReturnsTimestampOutOfRange()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;

        _harness.Time.Advance(TimeSpan.FromSeconds(301));
        HmacValidationResult result = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("9223372036854775807")]
    public async Task ValidateAsync_ExtremeButWellFormedTimestamp_ReturnsTimestampOutOfRange(string timestamp)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = timestamp;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
    }

    [Theory]
    [InlineData(30, true)]
    [InlineData(-30, true)]
    [InlineData(31, false)]
    [InlineData(-31, false)]
    public async Task ValidateAsync_CustomAllowedClockSkew_IsHonoured(int offsetSeconds, bool expectedSuccess)
    {
        _harness.Options.AllowedClockSkew = TimeSpan.FromSeconds(30);
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow + offsetSeconds);

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(expectedSuccess, result.Succeeded);
        Assert.Equal(expectedSuccess ? HmacValidationFailure.None : HmacValidationFailure.TimestampOutOfRange, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_TimestampWithLeadingZeros_IsSignedVerbatimAndAccepted()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Timestamp = "00" + TestCredentials.FormatTimestamp(_harness.UnixNow);

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_SignatureComputedOverNormalizedTimestamp_ReturnsInvalidSignature()
    {
        // The canonical request uses the header value verbatim, so re-formatting it breaks the signature.
        SignedRequestBuilder request = _harness.NewRequest();
        string signature = request.Signature;
        request.Timestamp = "0" + request.Timestamp;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
    }
}
