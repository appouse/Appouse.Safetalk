using System.Globalization;
using Appouse.Safetalk;
using Appouse.Safetalk.Redis;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Enables replay protection backed by a Redis-compatible server (Redis, KeyDB).
/// </summary>
public static class RedisHmacServerBuilderExtensions
{
    /// <summary>
    /// Enables replay protection with a <see cref="RedisHmacReplayCache"/> connected to <paramref name="configuration"/>,
    /// replacing the default in-memory cache.
    /// </summary>
    /// <param name="builder">The HMAC server builder.</param>
    /// <param name="configuration">
    /// The StackExchange.Redis configuration string of the Redis or KeyDB server, for example <c>localhost:6379</c>.
    /// </param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddHmacServer(builder.Configuration.GetSection("Safetalk"))
    ///     .AddRedisReplayProtection(builder.Configuration.GetConnectionString("Redis")!);
    /// </code>
    /// </example>
    public static IHmacServerBuilder AddRedisReplayProtection(this IHmacServerBuilder builder, string configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration);

        return builder.AddRedisReplayProtection(options => options.Configuration = configuration);
    }

    /// <summary>
    /// Enables replay protection with a <see cref="RedisHmacReplayCache"/> whose options are bound from configuration
    /// (<c>Configuration</c>, <c>KeyPrefix</c>, <c>Database</c>), replacing the default in-memory cache.
    /// </summary>
    /// <param name="builder">The HMAC server builder.</param>
    /// <param name="section">The configuration section, for example <c>Safetalk:ReplayCache</c>.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IHmacServerBuilder AddRedisReplayProtection(this IHmacServerBuilder builder, IConfiguration section)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(section);

        return builder.AddRedisReplayProtection(options => Bind(section, options));
    }

    /// <summary>
    /// Enables replay protection with a <see cref="RedisHmacReplayCache"/>, replacing the default in-memory cache. Without
    /// <see cref="RedisReplayCacheOptions.Configuration"/>, the <see cref="IConnectionMultiplexer"/> registered in the
    /// service collection is used.
    /// </summary>
    /// <param name="builder">The HMAC server builder.</param>
    /// <param name="configureOptions">Configures <see cref="RedisReplayCacheOptions"/>.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    /// <remarks>Options are validated at application start-up (<c>ValidateOnStart</c>).</remarks>
    public static IHmacServerBuilder AddRedisReplayProtection(this IHmacServerBuilder builder, Action<RedisReplayCacheOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        IServiceCollection services = builder.Services;

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<RedisReplayCacheOptions>, RedisReplayCacheOptionsValidator>());

        OptionsBuilder<RedisReplayCacheOptions> optionsBuilder = services.AddOptions<RedisReplayCacheOptions>();
        if (configureOptions is not null)
        {
            optionsBuilder.Configure(configureOptions);
        }

        optionsBuilder.ValidateOnStart();

        services.TryAddSingleton(serviceProvider =>
        {
            RedisReplayCacheOptions options = serviceProvider.GetRequiredService<IOptions<RedisReplayCacheOptions>>().Value;
            return string.IsNullOrWhiteSpace(options.Configuration)
                ? RedisConnection.Borrow(serviceProvider.GetService<IConnectionMultiplexer>()
                    ?? throw new InvalidOperationException(
                        $"Set {nameof(RedisReplayCacheOptions)}.{nameof(RedisReplayCacheOptions.Configuration)} or register an {nameof(IConnectionMultiplexer)}."))
                : RedisConnection.Create(options.Configuration);
        });

        services.RemoveAll<IHmacReplayCache>();
        services.AddSingleton<IHmacReplayCache>(serviceProvider =>
        {
            RedisReplayCacheOptions options = serviceProvider.GetRequiredService<IOptions<RedisReplayCacheOptions>>().Value;
            return new RedisHmacReplayCache(
                serviceProvider.GetRequiredService<RedisConnection>(),
                serviceProvider.GetRequiredService<TimeProvider>(),
                options.KeyPrefix,
                options.Database);
        });

        return builder.AddReplayProtection();
    }

    /// <summary>
    /// Binds the options without reflection (trimming and Native AOT friendly).
    /// </summary>
    private static void Bind(IConfiguration section, RedisReplayCacheOptions options)
    {
        if (section[nameof(RedisReplayCacheOptions.Configuration)] is { Length: > 0 } configuration)
        {
            options.Configuration = configuration;
        }

        if (section[nameof(RedisReplayCacheOptions.KeyPrefix)] is { } keyPrefix)
        {
            options.KeyPrefix = keyPrefix;
        }

        if (section[nameof(RedisReplayCacheOptions.Database)] is { Length: > 0 } database)
        {
            options.Database = int.TryParse(database, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int value)
                ? value
                : throw new InvalidOperationException(
                    $"Configuration value '{database}' of '{nameof(RedisReplayCacheOptions.Database)}' is not an integer.");
        }
    }
}
