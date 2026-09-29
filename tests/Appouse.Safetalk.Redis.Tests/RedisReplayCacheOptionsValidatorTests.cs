using Appouse.Safetalk.Redis.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Appouse.Safetalk.Redis.Tests;

public sealed class RedisReplayCacheOptionsValidatorTests
{
    [Fact]
    public void Validate_NoConfigurationAndNoMultiplexerRegistered_Fails()
    {
        ValidateOptionsResult result = Validate(new RedisReplayCacheOptions(), registerMultiplexer: false);

        Assert.True(result.Failed);
        Assert.Contains(nameof(IConnectionMultiplexer), result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_NoConfigurationWithMultiplexerRegistered_Succeeds()
        => Assert.True(Validate(new RedisReplayCacheOptions(), registerMultiplexer: true).Succeeded);

    [Fact]
    public void Validate_NoConfigurationAndNoServiceInspector_Succeeds()
        => Assert.True(new RedisReplayCacheOptionsValidator(serviceInspector: null).Validate(null, new RedisReplayCacheOptions()).Succeeded);

    [Theory]
    [InlineData("localhost")]
    [InlineData("localhost:6379,password=p,ssl=true,abortConnect=false")]
    [InlineData("keydb-1:6379,keydb-2:6379,defaultDatabase=2")]
    public void Validate_ValidConfiguration_Succeeds(string configuration)
        => Assert.True(Validate(new RedisReplayCacheOptions { Configuration = configuration }, registerMultiplexer: false).Succeeded);

    [Fact]
    public void Validate_InvalidConfiguration_FailsWithoutRepeatingThePassword()
    {
        ValidateOptionsResult result = Validate(
            new RedisReplayCacheOptions { Configuration = "localhost,password=super-secret-value,notAKeyword=1" },
            registerMultiplexer: false);

        Assert.True(result.Failed);
        Assert.Contains("notAKeyword", result.FailureMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("super-secret-value", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_NullKeyPrefix_Fails()
        => Assert.True(Validate(new RedisReplayCacheOptions { Configuration = "localhost", KeyPrefix = null! }, registerMultiplexer: false).Failed);

    [Fact]
    public void Validate_EmptyKeyPrefix_Succeeds()
        => Assert.True(Validate(new RedisReplayCacheOptions { Configuration = "localhost", KeyPrefix = "" }, registerMultiplexer: false).Succeeded);

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, true)]
    [InlineData(15, true)]
    [InlineData(-2, false)]
    [InlineData(int.MinValue, false)]
    public void Validate_Database(int database, bool valid)
        => Assert.Equal(valid, Validate(new RedisReplayCacheOptions { Configuration = "localhost", Database = database }, registerMultiplexer: false).Succeeded);

    private static ValidateOptionsResult Validate(RedisReplayCacheOptions options, bool registerMultiplexer)
    {
        var services = new ServiceCollection();
        if (registerMultiplexer)
        {
            services.AddSingleton(new FakeRedis().Multiplexer);
        }

        using ServiceProvider provider = services.BuildServiceProvider();
        return new RedisReplayCacheOptionsValidator(provider.GetRequiredService<IServiceProviderIsService>()).Validate(null, options);
    }
}
