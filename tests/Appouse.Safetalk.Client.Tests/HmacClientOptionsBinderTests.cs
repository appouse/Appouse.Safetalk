using Microsoft.Extensions.Configuration;

namespace Appouse.Safetalk.Client.Tests;

public sealed class HmacClientOptionsBinderTests
{
    private const string InvalidBaseAddress = "BaseAddress must be an absolute http or https URI, for example https://api.example.com/.";

    [Fact]
    public void Bind_AllKeysPresent_SetsEveryProperty()
    {
        var options = new HmacClientOptions();

        HmacClientOptionsBinder.Bind(Build(("ClientId", "partner-a"), ("Secret", "s3cr3t"), ("BaseAddress", "https://api.example.com/v1/")), options);

        Assert.Equal("partner-a", options.ClientId);
        Assert.Equal("s3cr3t", options.Secret);
        Assert.Equal(new Uri("https://api.example.com/v1/"), options.BaseAddress);
        Assert.True(options.BaseAddress!.IsAbsoluteUri);
    }

    [Fact]
    public void Bind_MissingKeys_KeepExistingValues()
    {
        var baseAddress = new Uri("https://existing.example.com/");
        var options = new HmacClientOptions { ClientId = "existing-client", Secret = "existing-secret", BaseAddress = baseAddress };

        HmacClientOptionsBinder.Bind(Build(("Unrelated", "value")), options);

        Assert.Equal("existing-client", options.ClientId);
        Assert.Equal("existing-secret", options.Secret);
        Assert.Same(baseAddress, options.BaseAddress);
    }

    [Fact]
    public void Bind_EmptyValues_OverwriteCredentialsButAnEmptyBaseAddressIsIgnored()
    {
        var baseAddress = new Uri("https://existing.example.com/");
        var options = new HmacClientOptions { ClientId = "existing-client", Secret = "existing-secret", BaseAddress = baseAddress };

        HmacClientOptionsBinder.Bind(Build(("ClientId", string.Empty), ("Secret", string.Empty), ("BaseAddress", string.Empty)), options);

        Assert.Equal(string.Empty, options.ClientId);
        Assert.Equal(string.Empty, options.Secret);
        Assert.Same(baseAddress, options.BaseAddress);
    }

    [Fact]
    public void Bind_KeysAreCaseInsensitive()
    {
        var options = new HmacClientOptions();

        HmacClientOptionsBinder.Bind(Build(("clientid", "lower"), ("SECRET", "upper"), ("baseAddress", "https://mixed.example.com/")), options);

        Assert.Equal("lower", options.ClientId);
        Assert.Equal("upper", options.Secret);
        Assert.Equal(new Uri("https://mixed.example.com/"), options.BaseAddress);
    }

    [Fact]
    public void Bind_SecretWithWhitespaceAndNonAsciiCharacters_IsKeptVerbatim()
    {
        const string secret = "  şifre = €/🔐 \t";
        var options = new HmacClientOptions();

        HmacClientOptionsBinder.Bind(Build(("Secret", secret)), options);

        Assert.Equal(secret, options.Secret);
    }

    [Theory]
    [InlineData("api/v1/")]
    [InlineData("/api/v1/")]
    [InlineData("api.example.com")]
    public void Bind_RelativeBaseAddress_IsKeptAsRelativeUriSoTheValidatorCanReportIt(string value)
    {
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret" };

        HmacClientOptionsBinder.Bind(Build(("BaseAddress", value)), options);

        Assert.NotNull(options.BaseAddress);
        Assert.False(options.BaseAddress.IsAbsoluteUri);
        Assert.Equal(value, options.BaseAddress.OriginalString);
        Assert.Equal([InvalidBaseAddress], HmacClientOptionsValidator.Instance.Validate(null, options).Failures);
    }

    [Theory]
    [InlineData("localhost:5080")]
    [InlineData("ftp://x/")]
    [InlineData("file:///api/")]
    public void Bind_AbsoluteNonHttpBaseAddress_IsKeptAsParsedSoTheValidatorCanReportIt(string value)
    {
        var options = new HmacClientOptions { ClientId = "partner-a", Secret = "secret" };

        HmacClientOptionsBinder.Bind(Build(("BaseAddress", value)), options);

        Assert.NotNull(options.BaseAddress);
        Assert.True(options.BaseAddress.IsAbsoluteUri);
        Assert.NotEqual(Uri.UriSchemeHttp, options.BaseAddress.Scheme);
        Assert.NotEqual(Uri.UriSchemeHttps, options.BaseAddress.Scheme);
        Assert.Equal([InvalidBaseAddress], HmacClientOptionsValidator.Instance.Validate(null, options).Failures);
    }

    [Theory]
    [InlineData("http://")]
    [InlineData("http://exa mple.com/")]
    [InlineData("https://api.example.com:99999/")]
    public void Bind_UnparsableBaseAddress_ThrowsInvalidOperationExceptionNamingTheKeyAndValue(string value)
    {
        var options = new HmacClientOptions();

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => HmacClientOptionsBinder.Bind(Build(("BaseAddress", value)), options));

        Assert.Contains("BaseAddress", exception.Message, StringComparison.Ordinal);
        Assert.Contains(value, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Bind_ChildSectionsUnderKnownKeys_AreNotTreatedAsValues()
    {
        var options = new HmacClientOptions { ClientId = "existing-client" };

        HmacClientOptionsBinder.Bind(Build(("ClientId:Nested", "ignored"), ("Secret", "secret")), options);

        Assert.Equal("existing-client", options.ClientId);
        Assert.Equal("secret", options.Secret);
    }

    private static IConfiguration Build(params (string Key, string Value)[] values) => new ConfigurationBuilder()
        .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
        .Build();
}
