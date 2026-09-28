using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// A hand-rolled <see cref="IOptionsMonitor{TOptions}"/> whose named values can be swapped at any time, recording
/// every name that is requested.
/// </summary>
internal sealed class MutableOptionsMonitor : IOptionsMonitor<HmacClientOptions>
{
    private readonly object _gate = new();
    private readonly Dictionary<string, HmacClientOptions> _options = new(StringComparer.Ordinal);
    private readonly List<string?> _requestedNames = [];

    public HmacClientOptions CurrentValue => Get(Options.DefaultName);

    public IReadOnlyList<string?> RequestedNames
    {
        get
        {
            lock (_gate)
            {
                return [.. _requestedNames];
            }
        }
    }

    public void Set(string name, HmacClientOptions options)
    {
        lock (_gate)
        {
            _options[name] = options;
        }
    }

    public HmacClientOptions Get(string? name)
    {
        lock (_gate)
        {
            _requestedNames.Add(name);
            return _options[name ?? Options.DefaultName];
        }
    }

    public IDisposable? OnChange(Action<HmacClientOptions, string?> listener) => null;
}
