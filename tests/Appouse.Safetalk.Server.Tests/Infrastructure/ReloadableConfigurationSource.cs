using Microsoft.Extensions.Configuration;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A configuration source whose data can be replaced at runtime, raising a reload like a file or Key Vault provider.
/// </summary>
internal sealed class ReloadableConfigurationSource(IEnumerable<KeyValuePair<string, string?>> initialData) : IConfigurationSource
{
    public ReloadableConfigurationProvider Provider { get; } = new(initialData);

    public IConfigurationProvider Build(IConfigurationBuilder builder) => Provider;

    /// <summary>
    /// Creates a configuration root over a new reloadable source.
    /// </summary>
    public static (IConfigurationRoot Root, ReloadableConfigurationProvider Provider) CreateRoot(IEnumerable<KeyValuePair<string, string?>> initialData)
    {
        var source = new ReloadableConfigurationSource(initialData);
        IConfigurationRoot root = new ConfigurationBuilder().Add(source).Build();
        return (root, source.Provider);
    }
}

internal sealed class ReloadableConfigurationProvider : ConfigurationProvider
{
    public ReloadableConfigurationProvider(IEnumerable<KeyValuePair<string, string?>> initialData)
    {
        Data = new Dictionary<string, string?>(initialData, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Replaces all data and raises a reload.
    /// </summary>
    public void Replace(IEnumerable<KeyValuePair<string, string?>> data)
    {
        Data = new Dictionary<string, string?>(data, StringComparer.OrdinalIgnoreCase);
        OnReload();
    }

    /// <summary>
    /// Sets one value (or removes it when <paramref name="value"/> is <see langword="null"/>) and raises a reload.
    /// </summary>
    public void Update(string key, string? value)
    {
        if (value is null)
        {
            Data.Remove(key);
        }
        else
        {
            Data[key] = value;
        }

        OnReload();
    }
}
