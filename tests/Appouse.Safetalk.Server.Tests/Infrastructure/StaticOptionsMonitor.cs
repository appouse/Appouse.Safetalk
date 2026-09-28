using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// An <see cref="IOptionsMonitor{TOptions}"/> that always returns the same (mutable) instance, so tests can change
/// options between calls.
/// </summary>
internal sealed class StaticOptionsMonitor<TOptions>(TOptions value) : IOptionsMonitor<TOptions>
{
    public TOptions CurrentValue { get; } = value;

    public TOptions Get(string? name) => CurrentValue;

    public IDisposable? OnChange(Action<TOptions, string?> listener) => null;
}
