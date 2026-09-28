using Microsoft.Extensions.Configuration;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// A configuration provider (like a Key Vault provider) whose whole data set is swapped atomically and then signalled as
/// reloaded, so it can be rotated safely while other threads read it.
/// </summary>
internal sealed class RotatingConfigurationProvider(IReadOnlyDictionary<string, string?> initial) : ConfigurationProvider, IConfigurationSource
{
    public override void Load() => Data = Copy(initial);

    public void Rotate(IReadOnlyDictionary<string, string?> values)
    {
        Data = Copy(values);
        OnReload();
    }

    public IConfigurationProvider Build(IConfigurationBuilder builder) => this;

    private static Dictionary<string, string?> Copy(IReadOnlyDictionary<string, string?> values) =>
        new(values, StringComparer.OrdinalIgnoreCase);
}
