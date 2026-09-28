using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace Appouse.Safetalk.Server;

/// <summary>
/// Binds <see cref="HmacServerOptions"/> from configuration without reflection (trimming and Native AOT friendly).
/// </summary>
internal static class HmacServerOptionsBinder
{
    public static void Bind(IConfiguration configuration, HmacServerOptions options)
    {
        if (TryGet(configuration, nameof(HmacServerOptions.AllowedClockSkew), out string? clockSkew))
        {
            options.AllowedClockSkew = TimeSpan.TryParse(clockSkew, CultureInfo.InvariantCulture, out TimeSpan value)
                ? value
                : throw Invalid(configuration, nameof(HmacServerOptions.AllowedClockSkew), clockSkew, "a time span such as 00:05:00");
        }

        if (TryGet(configuration, nameof(HmacServerOptions.MaxBodySize), out string? maxBodySize))
        {
            options.MaxBodySize = int.TryParse(maxBodySize, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value)
                ? value
                : throw Invalid(configuration, nameof(HmacServerOptions.MaxBodySize), maxBodySize, "an integer number of bytes");
        }

        if (TryGet(configuration, nameof(HmacServerOptions.EnableReplayProtection), out string? replayProtection))
        {
            options.EnableReplayProtection = bool.TryParse(replayProtection, out bool value)
                ? value
                : throw Invalid(configuration, nameof(HmacServerOptions.EnableReplayProtection), replayProtection, "true or false");
        }

        if (TryGet(configuration, nameof(HmacServerOptions.EnforcementMode), out string? enforcementMode))
        {
            options.EnforcementMode = TryParseEnforcementMode(enforcementMode, out HmacEnforcementMode value)
                ? value
                : throw Invalid(configuration, nameof(HmacServerOptions.EnforcementMode), enforcementMode, "AllRequests or MarkedEndpointsOnly");
        }
    }

    /// <summary>
    /// Accepts exactly one defined name (case-insensitive). <see cref="Enum.TryParse{TEnum}(string, bool, out TEnum)"/>
    /// would also accept numbers and comma-combined names, which could silently select the less protective mode.
    /// </summary>
    private static bool TryParseEnforcementMode(string? value, out HmacEnforcementMode mode)
    {
        foreach (HmacEnforcementMode candidate in Enum.GetValues<HmacEnforcementMode>())
        {
            if (string.Equals(value?.Trim(), candidate.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                mode = candidate;
                return true;
            }
        }

        mode = default;
        return false;
    }

    private static bool TryGet(IConfiguration configuration, string key, out string? value)
    {
        value = configuration[key];
        return !string.IsNullOrWhiteSpace(value);
    }

    private static InvalidOperationException Invalid(IConfiguration configuration, string key, string? value, string expected)
    {
        string path = configuration is IConfigurationSection section ? ConfigurationPath.Combine(section.Path, key) : key;
        return new InvalidOperationException($"Configuration value '{value}' at '{path}' is invalid: expected {expected}.");
    }
}
