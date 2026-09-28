using Microsoft.Extensions.Configuration;

namespace Appouse.Safetalk.Client;

/// <summary>
/// Binds <see cref="HmacClientOptions"/> from configuration without reflection (trimming and Native AOT friendly).
/// </summary>
internal static class HmacClientOptionsBinder
{
    public static void Bind(IConfiguration configuration, HmacClientOptions options)
    {
        if (configuration[nameof(HmacClientOptions.ClientId)] is { } clientId)
        {
            options.ClientId = clientId;
        }

        if (configuration[nameof(HmacClientOptions.Secret)] is { } secret)
        {
            options.Secret = secret;
        }

        if (configuration[nameof(HmacClientOptions.BaseAddress)] is { Length: > 0 } baseAddress)
        {
            // Anything that is not an absolute http(s) URI is kept as parsed and reported by the options validator.
            options.BaseAddress = Uri.TryCreate(baseAddress, UriKind.RelativeOrAbsolute, out Uri? uri)
                ? uri
                : throw new InvalidOperationException(
                    $"Configuration value '{baseAddress}' of '{nameof(HmacClientOptions.BaseAddress)}' is not a valid URI.");
        }
    }
}
