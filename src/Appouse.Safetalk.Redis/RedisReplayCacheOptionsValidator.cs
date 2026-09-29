using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Appouse.Safetalk.Redis;

/// <summary>
/// Validates <see cref="RedisReplayCacheOptions"/> at start-up, including that a connection source exists.
/// </summary>
/// <param name="serviceInspector">
/// Tells whether an <see cref="IConnectionMultiplexer"/> is registered; containers that do not provide it skip that check.
/// </param>
internal sealed class RedisReplayCacheOptionsValidator(IServiceProviderIsService? serviceInspector = null) : IValidateOptions<RedisReplayCacheOptions>
{
    public ValidateOptionsResult Validate(string? name, RedisReplayCacheOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string>? failures = null;

        if (string.IsNullOrWhiteSpace(options.Configuration))
        {
            if (serviceInspector is not null && !serviceInspector.IsService(typeof(IConnectionMultiplexer)))
            {
                (failures ??= []).Add(
                    $"Set {nameof(RedisReplayCacheOptions)}.{nameof(RedisReplayCacheOptions.Configuration)} (a Redis/KeyDB connection string) " +
                    $"or register an {nameof(IConnectionMultiplexer)} in the service collection.");
            }
        }
        else
        {
            try
            {
                _ = ConfigurationOptions.Parse(options.Configuration);
            }
            catch (ArgumentException exception)
            {
                // The message names the offending keyword; the configuration string itself (which may hold a
                // password) is deliberately not repeated.
                (failures ??= []).Add(
                    $"{nameof(RedisReplayCacheOptions.Configuration)} is not a valid StackExchange.Redis configuration string: {exception.Message}");
            }
        }

        if (options.KeyPrefix is null)
        {
            (failures ??= []).Add($"{nameof(RedisReplayCacheOptions.KeyPrefix)} must not be null.");
        }

        if (options.Database < -1)
        {
            (failures ??= []).Add($"{nameof(RedisReplayCacheOptions.Database)} must be -1 (default database) or a database number.");
        }

        return failures is null ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
