using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Client.Tests;

public sealed class HmacClientOptionsValidatorTests
{
    private const string MissingClientId = "ClientId must be provided.";
    private const string InvalidClientId = "ClientId must consist of at most 256 printable ASCII characters without leading or trailing whitespace.";
    private const string MissingSecret = "Secret must be provided.";
    private const string InvalidBaseAddress = "BaseAddress must be an absolute http or https URI, for example https://api.example.com/.";

    private readonly HmacClientOptionsValidator _validator = HmacClientOptionsValidator.Instance;

    [Fact]
    public void Options_Defaults_AreEmptyStrings()
    {
        var options = new HmacClientOptions();

        Assert.Equal(string.Empty, options.ClientId);
        Assert.Equal(string.Empty, options.Secret);
    }

    [Fact]
    public void Validate_DefaultOptions_FailsForClientIdAndSecret()
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions());

        Assert.True(result.Failed);
        Assert.Equal([MissingClientId, MissingSecret], result.Failures);
    }

    [Theory]
    [InlineData("partner-a")]
    [InlineData("a")]
    [InlineData("partner a")]
    [InlineData("PARTNER_01.eu-west")]
    [InlineData("!#$%&'*+-.^_`|~")]
    [InlineData("urn:client:42/v1?x=y")]
    public void Validate_PrintableAsciiClientId_Succeeds(string clientId)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = clientId, Secret = "secret" });

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData("secret")]
    [InlineData(" ")]
    [InlineData("şifre-€-🔐")]
    [InlineData("line\nbreak")]
    public void Validate_AnyNonEmptySecret_Succeeds(string secret)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = "partner-a", Secret = secret });

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData(" \r\n ")]
    public void Validate_EmptyOrWhitespaceClientId_FailsAsMissing(string clientId)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = clientId, Secret = "secret" });

        Assert.True(result.Failed);
        Assert.Equal(MissingClientId, SingleFailure(result));
    }

    [Fact]
    public void Validate_NullClientId_FailsAsMissing()
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = null!, Secret = "secret" });

        Assert.Equal(MissingClientId, SingleFailure(result));
    }

    [Theory]
    [InlineData(" partner")]
    [InlineData("partner ")]
    [InlineData("\tpartner")]
    [InlineData("partner\n")]
    [InlineData("partner ")]
    public void Validate_ClientIdWithLeadingOrTrailingWhitespace_Fails(string clientId)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = clientId, Secret = "secret" });

        Assert.Equal(InvalidClientId, SingleFailure(result));
    }

    [Theory]
    [InlineData("part\nner")]
    [InlineData("part\r\nX-Injected: 1")]
    [InlineData("part\tner")]
    [InlineData("part\u0000ner")]
    [InlineData("part\u001Fner")]
    [InlineData("part\u007Fner")]
    public void Validate_ClientIdWithControlCharacters_Fails(string clientId)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = clientId, Secret = "secret" });

        Assert.Equal(InvalidClientId, SingleFailure(result));
    }

    [Theory]
    [InlineData("partnerç")]
    [InlineData("İstanbul-client")]
    [InlineData("part ner")]
    [InlineData("client-🔐")]
    [InlineData("ｐａｒｔｎｅｒ")]
    public void Validate_ClientIdWithNonAsciiCharacters_Fails(string clientId)
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = clientId, Secret = "secret" });

        Assert.Equal(InvalidClientId, SingleFailure(result));
    }

    [Fact]
    public void Validate_EmptySecret_Fails()
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = "partner-a", Secret = string.Empty });

        Assert.Equal(MissingSecret, SingleFailure(result));
    }

    [Fact]
    public void Validate_NullSecret_Fails()
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = "partner-a", Secret = null! });

        Assert.Equal(MissingSecret, SingleFailure(result));
    }

    [Fact]
    public void Validate_InvalidClientIdAndMissingSecret_ReportsBothFailures()
    {
        ValidateOptionsResult result = _validator.Validate(Options.DefaultName, new HmacClientOptions { ClientId = "bad id ", Secret = string.Empty });

        Assert.Equal([InvalidClientId, MissingSecret], result.Failures);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("OrdersApiClient")]
    public void Validate_AnyOptionsName_AppliesSameRules(string? name)
    {
        Assert.True(_validator.Validate(name, new HmacClientOptions { ClientId = "partner-a", Secret = "secret" }).Succeeded);
        Assert.True(_validator.Validate(name, new HmacClientOptions { ClientId = "partner-a", Secret = string.Empty }).Failed);
    }

    [Fact]
    public void Validate_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("options", () => _validator.Validate(Options.DefaultName, null!));
    }

    [Fact]
    public void Options_DefaultBaseAddress_IsNull()
    {
        Assert.Null(new HmacClientOptions().BaseAddress);
    }

    [Theory]
    [InlineData("https://api.example.com/")]
    [InlineData("https://api.example.com/v1/")]
    [InlineData("http://localhost:5000")]
    [InlineData("https://[::1]:8443/api/")]
    public void Validate_AbsoluteBaseAddress_Succeeds(string baseAddress)
    {
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret", BaseAddress = new Uri(baseAddress) };

        Assert.True(_validator.Validate(Options.DefaultName, options).Succeeded);
    }

    [Theory]
    [InlineData("api/v1/")]
    [InlineData("/api/v1/")]
    [InlineData("api.example.com")]
    [InlineData("")]
    public void Validate_RelativeBaseAddress_Fails(string baseAddress)
    {
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret", BaseAddress = new Uri(baseAddress, UriKind.Relative) };

        Assert.Equal(InvalidBaseAddress, SingleFailure(_validator.Validate(Options.DefaultName, options)));
    }

    [Fact]
    public void Validate_EverythingInvalid_ReportsFailuresInPropertyOrder()
    {
        var options = new HmacClientOptions { ClientId = string.Empty, Secret = string.Empty, BaseAddress = new Uri("relative", UriKind.Relative) };

        Assert.Equal([MissingClientId, MissingSecret, InvalidBaseAddress], _validator.Validate(Options.DefaultName, options).Failures);
    }

    [Fact]
    public void MaxClientIdLength_Is256()
    {
        Assert.Equal(256, SafetalkHeaderNames.MaxClientIdLength);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(255)]
    [InlineData(256)]
    public void Validate_ClientIdUpToMaxLength_Succeeds(int length)
    {
        var options = new HmacClientOptions { ClientId = CreateClientId(length), Secret = "secret" };

        Assert.True(_validator.Validate(Options.DefaultName, options).Succeeded);
    }

    [Theory]
    [InlineData(257)]
    [InlineData(1_000)]
    [InlineData(64 * 1024)]
    public void Validate_ClientIdLongerThanMaxLength_Fails(int length)
    {
        var options = new HmacClientOptions { ClientId = CreateClientId(length), Secret = "secret" };

        Assert.Equal(InvalidClientId, SingleFailure(_validator.Validate(Options.DefaultName, options)));
    }

    [Fact]
    public void Validate_ClientIdTooLongAndWithControlCharacters_ReportsASingleClientIdFailure()
    {
        var options = new HmacClientOptions { ClientId = CreateClientId(300) + "\r\nX-Injected: 1", Secret = "secret" };

        Assert.Equal(InvalidClientId, SingleFailure(_validator.Validate(Options.DefaultName, options)));
    }

    [Fact]
    public void Validate_ClientIdOf256CharactersWithTrailingWhitespace_Fails()
    {
        var options = new HmacClientOptions { ClientId = CreateClientId(255) + " ", Secret = "secret" };

        Assert.Equal(InvalidClientId, SingleFailure(_validator.Validate(Options.DefaultName, options)));
    }

    [Fact]
    public void Validate_WhitespaceOnlyClientIdLongerThanMaxLength_FailsAsMissing()
    {
        var options = new HmacClientOptions { ClientId = new string(' ', 300), Secret = "secret" };

        Assert.Equal(MissingClientId, SingleFailure(_validator.Validate(Options.DefaultName, options)));
    }

    [Theory]
    [InlineData("http://api.example.com/")]
    [InlineData("HTTPS://API.EXAMPLE.COM/v1/")]
    [InlineData("https://api.example.com:8443")]
    [InlineData("http://127.0.0.1:5080/")]
    public void Validate_HttpOrHttpsBaseAddress_Succeeds(string baseAddress)
    {
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret", BaseAddress = new Uri(baseAddress) };

        Assert.True(_validator.Validate(Options.DefaultName, options).Succeeded);
    }

    /// <summary>
    /// Scheme-less values such as <c>localhost:5080</c> parse as absolute URIs whose scheme is the host name; they, and
    /// absolute URIs with any scheme other than http(s), must fail validation instead of the first request.
    /// </summary>
    [Theory]
    [InlineData("localhost:5080")]
    [InlineData("api.example.com:443")]
    [InlineData("ftp://x/")]
    [InlineData("file:///api/")]
    [InlineData("ws://api.example.com/")]
    [InlineData("wss://api.example.com/")]
    [InlineData("mailto:partner@example.com")]
    [InlineData("urn:partner:a")]
    public void Validate_AbsoluteNonHttpBaseAddress_Fails(string baseAddress)
    {
        var uri = new Uri(baseAddress, UriKind.RelativeOrAbsolute);
        Assert.True(uri.IsAbsoluteUri);
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret", BaseAddress = uri };

        Assert.Equal(InvalidBaseAddress, SingleFailure(_validator.Validate(Options.DefaultName, options)));
    }

    [Fact]
    public void Validate_EverythingInvalidWithNonHttpBaseAddress_ReportsFailuresInPropertyOrder()
    {
        var options = new HmacClientOptions { ClientId = CreateClientId(257), Secret = string.Empty, BaseAddress = new Uri("ftp://x/") };

        Assert.Equal([InvalidClientId, MissingSecret, InvalidBaseAddress], _validator.Validate(Options.DefaultName, options).Failures);
    }

    [Fact]
    public void Instance_IsSingleton()
    {
        Assert.Same(HmacClientOptionsValidator.Instance, HmacClientOptionsValidator.Instance);
    }

    /// <summary>
    /// Creates a client id of printable ASCII characters (every character of the range, repeated).
    /// </summary>
    internal static string CreateClientId(int length) =>
        string.Create(length, 0, static (span, _) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = (char)('!' + (i % ('~' - '!' + 1)));
            }
        });

    private static string SingleFailure(ValidateOptionsResult result)
    {
        Assert.True(result.Failed);
        Assert.NotNull(result.Failures);
        return Assert.Single(result.Failures);
    }
}
