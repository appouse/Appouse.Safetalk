using Appouse.Safetalk;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the services required to verify HMAC signed requests.
/// </summary>
public static class HmacServerServiceCollectionExtensions
{
    /// <summary>
    /// The configuration key, relative to the section passed to <see cref="AddHmacServer(IServiceCollection, IConfiguration)"/>,
    /// whose children are the client secrets.
    /// </summary>
    public const string ClientsConfigurationKey = "Clients";

    /// <summary>
    /// Registers the HMAC request validation services. Chain <c>AddSecretProvider&lt;TProvider&gt;()</c>,
    /// <c>AddSecretsFromConfiguration(...)</c> or <c>AddInMemorySecrets(...)</c> to tell the server how to resolve
    /// client secrets, then call <c>app.UseHmacAuthentication()</c>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Configures <see cref="HmacServerOptions"/>.</param>
    /// <returns>An <see cref="IHmacServerBuilder"/> for further configuration.</returns>
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddHmacServer(options => options.AllowedClockSkew = TimeSpan.FromMinutes(5))
    ///     .AddSecretProvider&lt;DatabaseSecretProvider&gt;()
    ///     .AddReplayProtection();
    /// </code>
    /// </example>
    public static IHmacServerBuilder AddHmacServer(this IServiceCollection services, Action<HmacServerOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(HmacServerMarkerService.Instance);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IHmacSignatureService>(HmacSha256SignatureService.Instance);
        services.TryAddSingleton<IHmacReplayCache, InMemoryHmacReplayCache>();
        services.TryAddSingleton(serviceProvider => new HmacClockSkewTracker(
            serviceProvider.GetRequiredService<IOptionsMonitor<HmacServerOptions>>().CurrentValue.AllowedClockSkew));
        services.TryAddScoped<IHmacRequestValidator, DefaultHmacRequestValidator>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<HmacServerOptions>>(HmacServerOptionsValidator.Instance));

        OptionsBuilder<HmacServerOptions> optionsBuilder = services.AddOptions<HmacServerOptions>();
        if (configureOptions is not null)
        {
            optionsBuilder.Configure(configureOptions);
        }

        optionsBuilder.ValidateOnStart();

        return new HmacServerBuilder(services);
    }

    /// <summary>
    /// Registers the HMAC request validation services with options bound from configuration (reloadable). When the
    /// section has a <c>Clients</c> child, client secrets are read from it through
    /// <see cref="ConfigurationHmacSecretProvider"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration section, for example <c>builder.Configuration.GetSection("Safetalk")</c>.</param>
    /// <returns>An <see cref="IHmacServerBuilder"/> for further configuration.</returns>
    /// <example>
    /// <code>
    /// // appsettings.json
    /// // "Safetalk": {
    /// //   "AllowedClockSkew": "00:05:00",
    /// //   "MaxBodySize": 1048576,
    /// //   "EnableReplayProtection": true,
    /// //   "EnforcementMode": "AllRequests",
    /// //   "Clients": { "partner-a": "..." }
    /// // }
    /// builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));
    /// </code>
    /// </example>
    public static IHmacServerBuilder AddHmacServer(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        IHmacServerBuilder builder = services.AddHmacServer(options => HmacServerOptionsBinder.Bind(configuration, options));
        services.AddSingleton<IOptionsChangeTokenSource<HmacServerOptions>>(
            new ConfigurationChangeTokenSource<HmacServerOptions>(Options.Options.DefaultName, configuration));

        IConfigurationSection clients = configuration.GetSection(ClientsConfigurationKey);
        if (clients.Exists())
        {
            builder.AddSecretsFromConfiguration(clients);
        }

        return builder;
    }
}
