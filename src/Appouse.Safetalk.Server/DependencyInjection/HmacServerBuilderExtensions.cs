using System.Diagnostics.CodeAnalysis;
using Appouse.Safetalk;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Configures secret resolution and replay protection on an <see cref="IHmacServerBuilder"/>.
/// </summary>
public static class HmacServerBuilderExtensions
{
    /// <summary>
    /// Registers <typeparamref name="TProvider"/> as the <see cref="IHmacSecretProvider"/>, replacing any previous registration.
    /// </summary>
    /// <typeparam name="TProvider">The secret provider (database, Key Vault, ...).</typeparam>
    /// <param name="builder">The HMAC server builder.</param>
    /// <param name="lifetime">The provider lifetime. Scoped by default so it can depend on a <c>DbContext</c>.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IHmacServerBuilder AddSecretProvider<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TProvider>(
        this IHmacServerBuilder builder,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TProvider : class, IHmacSecretProvider
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.RemoveAll<IHmacSecretProvider>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(IHmacSecretProvider), typeof(TProvider), lifetime));
        return builder;
    }

    /// <summary>
    /// Registers a factory-created <see cref="IHmacSecretProvider"/>, replacing any previous registration.
    /// </summary>
    /// <param name="builder">The HMAC server builder.</param>
    /// <param name="factory">Creates the provider.</param>
    /// <param name="lifetime">
    /// The provider lifetime. Scoped by default. The container disposes what a scoped or transient factory returns, so
    /// return a new instance each time, or use <see cref="ServiceLifetime.Singleton"/> for a shared instance.
    /// </param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IHmacServerBuilder AddSecretProvider(
        this IHmacServerBuilder builder,
        Func<IServiceProvider, IHmacSecretProvider> factory,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(factory);

        builder.Services.RemoveAll<IHmacSecretProvider>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(IHmacSecretProvider), factory, lifetime));
        return builder;
    }

    /// <summary>
    /// Registers an <see cref="InMemoryHmacSecretProvider"/> with a fixed set of client secrets,
    /// replacing any previous <see cref="IHmacSecretProvider"/> registration.
    /// </summary>
    /// <param name="builder">The HMAC server builder.</param>
    /// <param name="secrets">Pairs of client identifier and shared secret.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IHmacServerBuilder AddInMemorySecrets(this IHmacServerBuilder builder, IEnumerable<KeyValuePair<string, string>> secrets)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var provider = new InMemoryHmacSecretProvider(secrets);
        builder.Services.RemoveAll<IHmacSecretProvider>();
        builder.Services.AddSingleton<IHmacSecretProvider>(provider);
        return builder;
    }

    /// <summary>
    /// Registers a <see cref="ConfigurationHmacSecretProvider"/> over the given section, replacing any previous
    /// <see cref="IHmacSecretProvider"/> registration. Secrets follow configuration reloads.
    /// </summary>
    /// <param name="builder">The HMAC server builder.</param>
    /// <param name="clients">The section whose children are the clients, for example <c>Safetalk:Clients</c>.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IHmacServerBuilder AddSecretsFromConfiguration(this IHmacServerBuilder builder, IConfiguration clients)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(clients);

        builder.Services.RemoveAll<IHmacSecretProvider>();
        builder.Services.AddSingleton<IHmacSecretProvider>(serviceProvider => new ConfigurationHmacSecretProvider(
            clients,
            serviceProvider.GetService<ILogger<ConfigurationHmacSecretProvider>>()));
        return builder;
    }

    /// <summary>
    /// Enables replay protection with the process-local <see cref="InMemoryHmacReplayCache"/>.
    /// Use <see cref="AddReplayProtection{TCache}"/> with a distributed cache when running multiple instances.
    /// </summary>
    /// <param name="builder">The HMAC server builder.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IHmacServerBuilder AddReplayProtection(this IHmacServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.Configure<HmacServerOptions>(options => options.EnableReplayProtection = true);
        return builder;
    }

    /// <summary>
    /// Enables replay protection with a custom <see cref="IHmacReplayCache"/> (for example one backed by Redis),
    /// registered as a singleton and replacing the default in-memory cache.
    /// </summary>
    /// <typeparam name="TCache">The replay cache implementation.</typeparam>
    /// <param name="builder">The HMAC server builder.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IHmacServerBuilder AddReplayProtection<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TCache>(
        this IHmacServerBuilder builder)
        where TCache : class, IHmacReplayCache
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.RemoveAll<IHmacReplayCache>();
        builder.Services.AddSingleton<IHmacReplayCache, TCache>();
        return builder.AddReplayProtection();
    }
}
