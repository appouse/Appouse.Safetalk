using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacServerOptionsValidatorTests
{
    private readonly HmacServerOptionsValidator _validator = HmacServerOptionsValidator.Instance;

    public static TheoryData<TimeSpan> InvalidClockSkews { get; } = new(
        TimeSpan.Zero,
        TimeSpan.FromMilliseconds(999),
        TimeSpan.FromSeconds(-1),
        TimeSpan.MinValue,
        HmacServerOptions.MaxAllowedClockSkew + TimeSpan.FromTicks(1),
        TimeSpan.MaxValue);

    public static TheoryData<TimeSpan> ValidClockSkews { get; } = new(
        TimeSpan.FromSeconds(1),
        TimeSpan.FromMinutes(5),
        HmacServerOptions.MaxAllowedClockSkew);

    [Fact]
    public void NewOptions_HaveDocumentedDefaults()
    {
        var options = new HmacServerOptions();

        Assert.Equal(TimeSpan.FromMinutes(5), options.AllowedClockSkew);
        Assert.Equal(HmacServerOptions.DefaultAllowedClockSkew, options.AllowedClockSkew);
        Assert.Equal(4 * 1024 * 1024, options.MaxBodySize);
        Assert.Equal(HmacServerOptions.DefaultMaxBodySize, options.MaxBodySize);
        Assert.False(options.EnableReplayProtection);
        Assert.Equal(HmacEnforcementMode.AllRequests, options.EnforcementMode);
        Assert.Null(options.RequestTargetResolver);
        Assert.Equal(TimeSpan.FromDays(1), HmacServerOptions.MaxAllowedClockSkew);
    }

    [Fact]
    public void Validate_DefaultOptions_Succeeds()
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacServerOptions());

        Assert.True(result.Succeeded);
    }

    [Theory]
    [MemberData(nameof(InvalidClockSkews))]
    public void Validate_ClockSkewOutOfRange_Fails(TimeSpan clockSkew)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacServerOptions { AllowedClockSkew = clockSkew });

        Assert.True(result.Failed);
        string failure = Assert.Single(result.Failures!);
        Assert.Contains(nameof(HmacServerOptions.AllowedClockSkew), failure, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(ValidClockSkews))]
    public void Validate_ClockSkewWithinRange_Succeeds(TimeSpan clockSkew)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacServerOptions { AllowedClockSkew = clockSkew });

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Validate_NegativeMaxBodySize_Fails(int maxBodySize)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacServerOptions { MaxBodySize = maxBodySize });

        Assert.True(result.Failed);
        string failure = Assert.Single(result.Failures!);
        Assert.Contains(nameof(HmacServerOptions.MaxBodySize), failure, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(int.MaxValue)]
    public void Validate_NonNegativeMaxBodySize_Succeeds(int maxBodySize)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacServerOptions { MaxBodySize = maxBodySize });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_SeveralInvalidValues_ReportsEveryFailure()
    {
        var options = new HmacServerOptions { AllowedClockSkew = TimeSpan.Zero, MaxBodySize = -1 };

        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, options);

        Assert.True(result.Failed);
        Assert.Equal(2, result.Failures!.Count());
    }

    [Fact]
    public void Validate_NamedOptions_AreValidatedToo()
    {
        ValidateOptionsResult result = _validator.Validate("partner-api", new HmacServerOptions { MaxBodySize = -1 });

        Assert.True(result.Failed);
    }

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly)]
    public void Validate_DefinedEnforcementMode_Succeeds(HmacEnforcementMode mode)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacServerOptions { EnforcementMode = mode });

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(42)]
    public void Validate_UndefinedEnforcementMode_Fails(int mode)
    {
        // An undefined value would otherwise be treated as MarkedEndpointsOnly by the middleware (fail-open).
        ValidateOptionsResult result = _validator.Validate(
            Options.DefaultName,
            new HmacServerOptions { EnforcementMode = (HmacEnforcementMode)mode });

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, failure => failure.Contains(nameof(HmacServerOptions.EnforcementMode), StringComparison.Ordinal));
    }

    [Fact]
    public void EnforcementMode_HasDocumentedValues()
    {
        Assert.Equal(0, (int)HmacEnforcementMode.AllRequests);
        Assert.Equal(1, (int)HmacEnforcementMode.MarkedEndpointsOnly);
        Assert.Equal(default, HmacEnforcementMode.AllRequests);
    }

    [Fact]
    public void Validate_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("options", () => _validator.Validate(Options.DefaultName, null!));
    }
}
