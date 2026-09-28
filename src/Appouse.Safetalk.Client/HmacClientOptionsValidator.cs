using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Client;

/// <summary>
/// Validates <see cref="HmacClientOptions"/> without reflection (trimming and Native AOT friendly).
/// </summary>
internal sealed class HmacClientOptionsValidator : IValidateOptions<HmacClientOptions>
{
    public static HmacClientOptionsValidator Instance { get; } = new();

    public ValidateOptionsResult Validate(string? name, HmacClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string>? failures = null;

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            (failures ??= []).Add($"{nameof(HmacClientOptions.ClientId)} must be provided.");
        }
        else if (options.ClientId.Length > SafetalkHeaderNames.MaxClientIdLength || !IsValidHeaderValue(options.ClientId))
        {
            (failures ??= []).Add(
                $"{nameof(HmacClientOptions.ClientId)} must consist of at most {SafetalkHeaderNames.MaxClientIdLength} printable ASCII characters without leading or trailing whitespace.");
        }

        if (string.IsNullOrEmpty(options.Secret))
        {
            (failures ??= []).Add($"{nameof(HmacClientOptions.Secret)} must be provided.");
        }

        // Scheme-less values such as "localhost:5080" parse as absolute URIs with a bogus scheme, and on Unix "/api/"
        // parses as a file URI: require http(s) so that ValidateOnStart catches them instead of the first request.
        if (options.BaseAddress is { } baseAddress
            && !(baseAddress.IsAbsoluteUri && (baseAddress.Scheme == Uri.UriSchemeHttp || baseAddress.Scheme == Uri.UriSchemeHttps)))
        {
            (failures ??= []).Add(
                $"{nameof(HmacClientOptions.BaseAddress)} must be an absolute http or https URI, for example https://api.example.com/.");
        }

        return failures is null ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static bool IsValidHeaderValue(string value)
    {
        if (char.IsWhiteSpace(value[0]) || char.IsWhiteSpace(value[^1]))
        {
            return false;
        }

        foreach (char c in value)
        {
            if (c is < ' ' or > '~')
            {
                return false;
            }
        }

        return true;
    }
}
