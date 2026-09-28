using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests;

public sealed class HmacSigningHandlerConstructorTests
{
    private static readonly ILogger<HmacSigningHandler> Logger = NullLogger<HmacSigningHandler>.Instance;

    [Fact]
    public void Constructor_ValidOptions_CreatesHandler()
    {
        using var handler = new HmacSigningHandler(new HmacClientOptions { ClientId = "partner-a", Secret = "secret" });

        Assert.Null(handler.InnerHandler);
    }

    [Theory]
    [InlineData("", "secret", "ClientId must be provided.")]
    [InlineData("   ", "secret", "ClientId must be provided.")]
    [InlineData(" partner", "secret", "ClientId must consist of at most 256 printable ASCII characters without leading or trailing whitespace.")]
    [InlineData("part\nner", "secret", "ClientId must consist of at most 256 printable ASCII characters without leading or trailing whitespace.")]
    [InlineData("partnerç", "secret", "ClientId must consist of at most 256 printable ASCII characters without leading or trailing whitespace.")]
    [InlineData("partner-a", "", "Secret must be provided.")]
    public void Constructor_InvalidOptions_ThrowsOptionsValidationException(string clientId, string secret, string expectedFailure)
    {
        var options = new HmacClientOptions { ClientId = clientId, Secret = secret };

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(() => new HmacSigningHandler(options));

        Assert.Equal(typeof(HmacClientOptions), exception.OptionsType);
        Assert.Equal(Options.DefaultName, exception.OptionsName);
        Assert.Equal(expectedFailure, Assert.Single(exception.Failures));
    }

    [Fact]
    public void Constructor_ClientIdOfMaxLength_CreatesHandler()
    {
        var options = new HmacClientOptions { ClientId = HmacClientOptionsValidatorTests.CreateClientId(256), Secret = "secret" };

        using var handler = new HmacSigningHandler(options);

        Assert.Null(handler.InnerHandler);
    }

    [Fact]
    public void Constructor_ClientIdLongerThanMaxLength_ThrowsOptionsValidationException()
    {
        var options = new HmacClientOptions { ClientId = HmacClientOptionsValidatorTests.CreateClientId(257), Secret = "secret" };

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(
            () => new HmacSigningHandler(options, HmacSha256SignatureService.Instance, TimeProvider.System, Logger));

        Assert.Equal(
            "ClientId must consist of at most 256 printable ASCII characters without leading or trailing whitespace.",
            Assert.Single(exception.Failures));
    }

    [Theory]
    [InlineData("localhost:5080")]
    [InlineData("ftp://x/")]
    [InlineData("file:///api/")]
    public void Constructor_NonHttpBaseAddress_ThrowsOptionsValidationException(string baseAddress)
    {
        var options = new HmacClientOptions
        {
            ClientId = "partner-a",
            Secret = "secret",
            BaseAddress = new Uri(baseAddress, UriKind.RelativeOrAbsolute),
        };

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(() => new HmacSigningHandler(options));

        Assert.Equal(
            "BaseAddress must be an absolute http or https URI, for example https://api.example.com/.",
            Assert.Single(exception.Failures));
    }

    [Fact]
    public void Constructor_InvalidOptionsWithDependencies_ThrowsOptionsValidationExceptionWithAllFailures()
    {
        var options = new HmacClientOptions { ClientId = string.Empty, Secret = string.Empty };

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(
            () => new HmacSigningHandler(options, HmacSha256SignatureService.Instance, TimeProvider.System, Logger));

        Assert.Equal(2, exception.Failures.Count());
    }

    [Fact]
    public void Constructor_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("options", () => new HmacSigningHandler(null!));
        Assert.Throws<ArgumentNullException>("options", () => new HmacSigningHandler(null!, HmacSha256SignatureService.Instance, TimeProvider.System, Logger));
    }

    [Fact]
    public void Constructor_NullDependencies_ThrowArgumentNullException()
    {
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret" };

        Assert.Throws<ArgumentNullException>("signatureService", () => new HmacSigningHandler(options, null!, TimeProvider.System, Logger));
        Assert.Throws<ArgumentNullException>("timeProvider", () => new HmacSigningHandler(options, HmacSha256SignatureService.Instance, null!, Logger));
        Assert.Throws<ArgumentNullException>("logger", () => new HmacSigningHandler(options, HmacSha256SignatureService.Instance, TimeProvider.System, null!));
    }

    [Fact]
    public async Task Constructor_OptionsOnly_UsesSystemClockAndHmacSha256()
    {
        var transport = new CapturingHandler();
        using var handler = new HmacSigningHandler(new HmacClientOptions { ClientId = "partner-a", Secret = "secret" }) { InnerHandler = transport };
        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        long before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using HttpResponseMessage response = await invoker.SendAsync(request, TestContext.Current.CancellationToken);
        long after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        CapturedRequest sent = transport.SingleRequest;
        long timestamp = long.Parse(sent.Timestamp, System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(timestamp, before, after);
        Assert.Equal(ReferenceSigner.Sign("secret", sent), sent.Signature);
    }

    [Fact]
    public async Task Constructor_FixedOptions_UsesInjectedTimeProvider()
    {
        var time = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_000_000_000));
        var transport = new CapturingHandler();
        using var handler = new HmacSigningHandler(new HmacClientOptions { ClientId = "partner-a", Secret = "secret" }, HmacSha256SignatureService.Instance, time, Logger)
        {
            InnerHandler = transport,
        };
        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");

        using HttpResponseMessage response = await invoker.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal("1000000000", transport.SingleRequest.Timestamp);
    }
}
