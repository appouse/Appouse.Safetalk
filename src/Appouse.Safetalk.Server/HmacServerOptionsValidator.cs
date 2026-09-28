using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server;

/// <summary>
/// Validates <see cref="HmacServerOptions"/> without reflection (trimming and Native AOT friendly).
/// </summary>
internal sealed class HmacServerOptionsValidator : IValidateOptions<HmacServerOptions>
{
    public static HmacServerOptionsValidator Instance { get; } = new();

    public ValidateOptionsResult Validate(string? name, HmacServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string>? failures = null;

        if (options.AllowedClockSkew < TimeSpan.FromSeconds(1) || options.AllowedClockSkew > HmacServerOptions.MaxAllowedClockSkew)
        {
            (failures ??= []).Add(
                $"{nameof(HmacServerOptions.AllowedClockSkew)} must be between 1 second and {HmacServerOptions.MaxAllowedClockSkew}.");
        }

        if (options.MaxBodySize < 0)
        {
            (failures ??= []).Add($"{nameof(HmacServerOptions.MaxBodySize)} must not be negative.");
        }

        if (!Enum.IsDefined(options.EnforcementMode))
        {
            (failures ??= []).Add(
                $"{nameof(HmacServerOptions.EnforcementMode)} must be {nameof(HmacEnforcementMode.AllRequests)} or {nameof(HmacEnforcementMode.MarkedEndpointsOnly)}.");
        }

        return failures is null ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
