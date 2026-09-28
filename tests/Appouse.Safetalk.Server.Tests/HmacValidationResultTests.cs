namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacValidationResultTests
{
    [Fact]
    public void Default_IsNotSucceeded()
    {
        HmacValidationResult result = default;

        Assert.False(result.Succeeded);
        Assert.Null(result.ClientId);
        Assert.Equal(HmacValidationFailure.None, result.Failure);
    }

    [Fact]
    public void Success_SetsClientIdAndNoFailure()
    {
        HmacValidationResult result = HmacValidationResult.Success("partner-a");

        Assert.True(result.Succeeded);
        Assert.Equal("partner-a", result.ClientId);
        Assert.Equal(HmacValidationFailure.None, result.Failure);
    }

    [Fact]
    public void Success_NullClientId_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("clientId", () => HmacValidationResult.Success(null!));
    }

    [Fact]
    public void Success_EmptyClientId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>("clientId", () => HmacValidationResult.Success(string.Empty));
    }

    [Theory]
    [InlineData(HmacValidationFailure.MissingHeaders)]
    [InlineData(HmacValidationFailure.InvalidTimestamp)]
    [InlineData(HmacValidationFailure.TimestampOutOfRange)]
    [InlineData(HmacValidationFailure.UnknownClient)]
    [InlineData(HmacValidationFailure.PayloadTooLarge)]
    [InlineData(HmacValidationFailure.InvalidRequestTarget)]
    [InlineData(HmacValidationFailure.ContentLengthMismatch)]
    [InlineData(HmacValidationFailure.InvalidSignature)]
    [InlineData(HmacValidationFailure.ReplayDetected)]
    [InlineData(HmacValidationFailure.UnsignedMethodOverride)]
    [InlineData(HmacValidationFailure.BodyAlreadyConsumed)]
    public void Fail_SetsFailureAndClaimedClientId(HmacValidationFailure failure)
    {
        HmacValidationResult result = HmacValidationResult.Fail(failure, "partner-a");

        Assert.False(result.Succeeded);
        Assert.Equal(failure, result.Failure);
        Assert.Equal("partner-a", result.ClientId);
    }

    [Fact]
    public void Fail_WithoutClientId_HasNullClientId()
    {
        HmacValidationResult result = HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders);

        Assert.Null(result.ClientId);
    }

    [Fact]
    public void Fail_None_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>("failure", () => HmacValidationResult.Fail(HmacValidationFailure.None));
    }

    [Fact]
    public void FailureValues_HaveStableNumbers()
    {
        // Values may be persisted or logged as numbers; new members are appended without renumbering existing ones.
        Assert.Equal(0, (int)HmacValidationFailure.None);
        Assert.Equal(1, (int)HmacValidationFailure.MissingHeaders);
        Assert.Equal(2, (int)HmacValidationFailure.InvalidTimestamp);
        Assert.Equal(3, (int)HmacValidationFailure.TimestampOutOfRange);
        Assert.Equal(4, (int)HmacValidationFailure.UnknownClient);
        Assert.Equal(5, (int)HmacValidationFailure.PayloadTooLarge);
        Assert.Equal(6, (int)HmacValidationFailure.InvalidRequestTarget);
        Assert.Equal(7, (int)HmacValidationFailure.ContentLengthMismatch);
        Assert.Equal(8, (int)HmacValidationFailure.InvalidSignature);
        Assert.Equal(9, (int)HmacValidationFailure.ReplayDetected);
        Assert.Equal(10, (int)HmacValidationFailure.UnsignedMethodOverride);
        Assert.Equal(11, (int)HmacValidationFailure.BodyAlreadyConsumed);
        Assert.Equal(12, Enum.GetValues<HmacValidationFailure>().Length);
    }

    [Fact]
    public void FailureValues_BodyAlreadyConsumedIsAppendedLast()
    {
        HmacValidationFailure[] values = Enum.GetValues<HmacValidationFailure>();

        Assert.Equal(HmacValidationFailure.BodyAlreadyConsumed, values.Max());
        Assert.Equal(Enumerable.Range(0, values.Length), values.Select(value => (int)value).Order());
    }

    [Fact]
    public void Equality_IsStructural()
    {
        Assert.Equal(HmacValidationResult.Success("partner-a"), HmacValidationResult.Success("partner-a"));
        Assert.NotEqual(HmacValidationResult.Success("partner-a"), HmacValidationResult.Success("partner-b"));
        Assert.NotEqual(
            HmacValidationResult.Fail(HmacValidationFailure.InvalidSignature, "partner-a"),
            HmacValidationResult.Fail(HmacValidationFailure.ReplayDetected, "partner-a"));
    }
}
