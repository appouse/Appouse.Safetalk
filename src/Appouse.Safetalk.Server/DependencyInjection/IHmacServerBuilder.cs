using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server;

/// <summary>
/// Builder returned by <c>AddHmacServer()</c> to configure secret providers and replay protection.
/// </summary>
public interface IHmacServerBuilder
{
    /// <summary>
    /// Gets the service collection.
    /// </summary>
    IServiceCollection Services { get; }
}

/// <summary>
/// Default <see cref="IHmacServerBuilder"/> implementation.
/// </summary>
internal sealed class HmacServerBuilder(IServiceCollection services) : IHmacServerBuilder
{
    public IServiceCollection Services { get; } = services;
}

/// <summary>
/// Marker registered by <c>AddHmacServer()</c>, used by <c>UseHmacAuthentication()</c> to fail fast when the
/// services were not registered.
/// </summary>
internal sealed class HmacServerMarkerService
{
    public static HmacServerMarkerService Instance { get; } = new();
}
