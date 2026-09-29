using Appouse.Safetalk.Redis.Tests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;

namespace Appouse.Safetalk.Redis.Tests;

public sealed class RedisHmacServerBuilderExtensionsTests
{
    private const string Signature = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    [Fact]
    public void AddRedisReplayProtection_ConnectionString_ReplacesTheInMemoryCacheAndEnablesReplayProtection()
    {
        var services = new ServiceCollection();
        services.AddHmacServer().AddInMemorySecrets([new("partner-a", "secret")]).AddRedisReplayProtection("localhost:6379");

        using ServiceProvider provider = services.BuildServiceProvider(validateScopes: true);

        Assert.IsType<RedisHmacReplayCache>(provider.GetRequiredService<IHmacReplayCache>());
        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IHmacReplayCache));
        Assert.True(provider.GetRequiredService<IOptions<HmacServerOptions>>().Value.EnableReplayProtection);
        Assert.Equal("localhost:6379", provider.GetRequiredService<IOptions<RedisReplayCacheOptions>>().Value.Configuration);
    }

    [Fact]
    public void AddRedisReplayProtection_AddHmacServerCalledAgainAfterwards_KeepsTheRedisCache()
    {
        var services = new ServiceCollection();
        services.AddHmacServer().AddRedisReplayProtection("localhost:6379");
        services.AddHmacServer();

        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.IsType<RedisHmacReplayCache>(provider.GetRequiredService<IHmacReplayCache>());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void AddRedisReplayProtection_MissingConnectionString_Throws(string? configuration)
        => Assert.ThrowsAny<ArgumentException>(() => new ServiceCollection().AddHmacServer().AddRedisReplayProtection(configuration!));

    [Fact]
    public void AddRedisReplayProtection_Section_BindsEveryOption()
    {
        IConfiguration section = BuildSection(new()
        {
            ["Configuration"] = "keydb.internal:6380,password=p",
            ["KeyPrefix"] = "orders-api:",
            ["Database"] = "4",
        });
        var services = new ServiceCollection();
        services.AddHmacServer().AddRedisReplayProtection(section);

        using ServiceProvider provider = services.BuildServiceProvider();
        RedisReplayCacheOptions options = provider.GetRequiredService<IOptions<RedisReplayCacheOptions>>().Value;

        Assert.Equal("keydb.internal:6380,password=p", options.Configuration);
        Assert.Equal("orders-api:", options.KeyPrefix);
        Assert.Equal(4, options.Database);
    }

    [Fact]
    public void AddRedisReplayProtection_SectionWithNonNumericDatabase_ThrowsNamingTheKey()
    {
        var services = new ServiceCollection();
        services.AddHmacServer().AddRedisReplayProtection(BuildSection(new() { ["Configuration"] = "localhost", ["Database"] = "two" }));

        using ServiceProvider provider = services.BuildServiceProvider();

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetRequiredService<IOptions<RedisReplayCacheOptions>>().Value);
        Assert.Contains("Database", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddRedisReplayProtection_InvalidOptions_FailStartupValidation()
    {
        var services = new ServiceCollection();
        services.AddHmacServer().AddRedisReplayProtection(BuildSection(new() { ["Configuration"] = "localhost", ["Database"] = "-5" }));

        using ServiceProvider provider = services.BuildServiceProvider();

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.Contains("Database", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddRedisReplayProtection_WithoutConfigurationOrRegisteredMultiplexer_FailsStartupValidation()
    {
        var services = new ServiceCollection();
        services.AddHmacServer().AddRedisReplayProtection();

        using ServiceProvider provider = services.BuildServiceProvider();

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.Contains(nameof(IConnectionMultiplexer), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AddRedisReplayProtection_WithRegisteredMultiplexer_UsesItWithTheConfiguredOptionsAndClockAndNeverDisposesIt()
    {
        var redis = new FakeRedis();
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 9, 29, 12, 0, 0, TimeSpan.Zero));
        var services = new ServiceCollection();
        services.AddSingleton(redis.Multiplexer);
        services.AddSingleton<TimeProvider>(time);
        services.AddLogging(); // Always present in a host; required by ValidateOnBuild below.
        services.AddHmacServer().AddInMemorySecrets([new("partner-a", "secret")]).AddRedisReplayProtection(options =>
        {
            options.KeyPrefix = "billing:";
            options.Database = 7;
        });

        await using (ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }))
        {
            provider.GetRequiredService<IStartupValidator>().Validate();
            IHmacReplayCache cache = provider.GetRequiredService<IHmacReplayCache>();

            Assert.True(await cache.TryAddAsync(Signature, time.GetUtcNow().AddSeconds(10), TestContext.Current.CancellationToken));
        }

        FakeRedis.StringSetCall call = Assert.Single(redis.StringSetCalls);
        Assert.Equal("billing:" + Signature, (string?)call.Key);
        Assert.Equal(TimeSpan.FromSeconds(10), call.Expiry);
        Assert.Equal(7, Assert.Single(redis.RequestedDatabases));
        Assert.Equal(0, redis.DisposeCalls);
    }

    [Fact]
    public async Task AddRedisReplayProtection_OwnedConnection_IsDisposedWithTheServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddHmacServer().AddRedisReplayProtection("127.0.0.1:1,connectTimeout=200,connectRetry=0");
        ServiceProvider provider = services.BuildServiceProvider();
        RedisConnection connection = provider.GetRequiredService<RedisConnection>();
        IConnectionMultiplexer multiplexer = await connection.GetAsync(TestContext.Current.CancellationToken);

        await provider.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => connection.GetAsync(TestContext.Current.CancellationToken).AsTask());
        Assert.False(multiplexer.IsConnected);
    }

    private static IConfiguration BuildSection(Dictionary<string, string?> values)
        => new ConfigurationBuilder().AddInMemoryCollection(values).Build();
}
