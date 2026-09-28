using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacServerBuilderExtensionsTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public void AddSecretProvider_Generic_DefaultsToScopedLifetime()
    {
        var services = new ServiceCollection();

        services.AddHmacServer().AddSecretProvider<ScopedSecretProvider>();

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
        Assert.Equal(typeof(ScopedSecretProvider), descriptor.ImplementationType);
    }

    [Theory]
    [InlineData(ServiceLifetime.Singleton)]
    [InlineData(ServiceLifetime.Scoped)]
    [InlineData(ServiceLifetime.Transient)]
    public void AddSecretProvider_Generic_HonoursLifetime(ServiceLifetime lifetime)
    {
        var services = new ServiceCollection();

        services.AddHmacServer().AddSecretProvider<ScopedSecretProvider>(lifetime);

        Assert.Equal(lifetime, Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider)).Lifetime);
    }

    [Fact]
    public void AddSecretProvider_Generic_ReplacesPreviousRegistrations()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHmacSecretProvider>(TestCredentials.CreateSecretProvider());
        services.AddSingleton<IHmacSecretProvider>(TestCredentials.CreateSecretProvider());

        services.AddHmacServer()
            .AddInMemorySecrets(TestCredentials.Secrets)
            .AddSecretProvider<ScopedSecretProvider>();

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        Assert.Equal(typeof(ScopedSecretProvider), descriptor.ImplementationType);
    }

    [Fact]
    public void AddSecretProvider_Generic_ScopedProviderIsCreatedOncePerScope()
    {
        var services = new ServiceCollection();
        services.AddSingleton<InstanceTracker>();
        services.AddHmacServer().AddSecretProvider<ScopedSecretProvider>();
        using ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        using (IServiceScope scope = provider.CreateScope())
        {
            Assert.Same(
                scope.ServiceProvider.GetRequiredService<IHmacSecretProvider>(),
                scope.ServiceProvider.GetRequiredService<IHmacSecretProvider>());
        }

        using (IServiceScope scope = provider.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<IHmacSecretProvider>();
        }

        Assert.Equal(2, provider.GetRequiredService<InstanceTracker>().Instances.Count);
    }

    [Theory]
    [InlineData(ServiceLifetime.Singleton)]
    [InlineData(ServiceLifetime.Scoped)]
    [InlineData(ServiceLifetime.Transient)]
    public void AddSecretProvider_Factory_ReplacesPreviousRegistrationAndHonoursLifetime(ServiceLifetime lifetime)
    {
        var services = new ServiceCollection();
        InMemoryHmacSecretProvider expected = TestCredentials.CreateSecretProvider();

        services.AddHmacServer()
            .AddInMemorySecrets(TestCredentials.Secrets)
            .AddSecretProvider(_ => expected, lifetime);

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        Assert.Equal(lifetime, descriptor.Lifetime);
        Assert.NotNull(descriptor.ImplementationFactory);
        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();
        Assert.Same(expected, scope.ServiceProvider.GetRequiredService<IHmacSecretProvider>());
    }

    [Fact]
    public void AddSecretProvider_Factory_DefaultsToScopedLifetime()
    {
        var services = new ServiceCollection();

        services.AddHmacServer().AddSecretProvider(_ => TestCredentials.CreateSecretProvider());

        Assert.Equal(ServiceLifetime.Scoped, Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider)).Lifetime);
    }

    [Fact]
    public void AddSecretProvider_Factory_ReceivesServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<InstanceTracker>();
        InstanceTracker? observed = null;
        services.AddHmacServer().AddSecretProvider(
            serviceProvider =>
            {
                observed = serviceProvider.GetRequiredService<InstanceTracker>();
                return TestCredentials.CreateSecretProvider();
            },
            ServiceLifetime.Singleton);
        using ServiceProvider provider = services.BuildServiceProvider();

        provider.GetRequiredService<IHmacSecretProvider>();

        Assert.Same(provider.GetRequiredService<InstanceTracker>(), observed);
    }

    [Fact]
    public async Task AddInMemorySecrets_RegistersSingletonProviderAndReplacesPrevious()
    {
        var services = new ServiceCollection();

        services.AddHmacServer()
            .AddSecretProvider<ScopedSecretProvider>()
            .AddInMemorySecrets([KeyValuePair.Create("partner-z", "secret-z")]);

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacSecretProvider));
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        InMemoryHmacSecretProvider provider = Assert.IsType<InMemoryHmacSecretProvider>(descriptor.ImplementationInstance);
        Assert.Equal("secret-z", await provider.GetSecretAsync("partner-z", CancellationToken));
    }

    [Fact]
    public void AddInMemorySecrets_InvalidSecrets_ThrowsAtRegistration()
    {
        IHmacServerBuilder builder = new ServiceCollection().AddHmacServer();

        Assert.Throws<ArgumentException>(
            () => builder.AddInMemorySecrets([KeyValuePair.Create("partner", "a"), KeyValuePair.Create("partner", "b")]));
        Assert.DoesNotContain(builder.Services, d => d.ServiceType == typeof(IHmacSecretProvider));
    }

    [Fact]
    public void AddReplayProtection_EnablesOptionAndKeepsInMemoryCache()
    {
        var services = new ServiceCollection();

        services.AddHmacServer().AddReplayProtection();
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.True(provider.GetRequiredService<IOptions<HmacServerOptions>>().Value.EnableReplayProtection);
        Assert.IsType<InMemoryHmacReplayCache>(provider.GetRequiredService<IHmacReplayCache>());
    }

    [Fact]
    public void AddReplayProtection_Generic_ReplacesCacheAndEnablesOption()
    {
        var services = new ServiceCollection();

        services.AddHmacServer().AddReplayProtection<CustomReplayCache>();
        using ServiceProvider provider = services.BuildServiceProvider();

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IHmacReplayCache));
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        Assert.Equal(typeof(CustomReplayCache), descriptor.ImplementationType);
        Assert.True(provider.GetRequiredService<IOptions<HmacServerOptions>>().Value.EnableReplayProtection);
        Assert.Same(provider.GetRequiredService<IHmacReplayCache>(), provider.GetRequiredService<IHmacReplayCache>());
    }

    [Fact]
    public void AddReplayProtection_Generic_SurvivesRepeatedAddHmacServer()
    {
        var services = new ServiceCollection();

        services.AddHmacServer().AddReplayProtection<CustomReplayCache>();
        services.AddHmacServer();

        Assert.Equal(typeof(CustomReplayCache), Assert.Single(services, d => d.ServiceType == typeof(IHmacReplayCache)).ImplementationType);
    }

    [Fact]
    public void BuilderMethods_ReturnSameBuilderForChaining()
    {
        IHmacServerBuilder builder = new ServiceCollection().AddHmacServer();

        Assert.Same(builder, builder.AddInMemorySecrets(TestCredentials.Secrets));
        Assert.Same(builder, builder.AddSecretProvider<ScopedSecretProvider>());
        Assert.Same(builder, builder.AddSecretProvider(_ => TestCredentials.CreateSecretProvider()));
        Assert.Same(builder, builder.AddReplayProtection());
        Assert.Same(builder, builder.AddReplayProtection<CustomReplayCache>());
    }

    [Fact]
    public void BuilderMethods_NullArguments_ThrowArgumentNullException()
    {
        IHmacServerBuilder builder = new ServiceCollection().AddHmacServer();

        Assert.Throws<ArgumentNullException>("builder", () => HmacServerBuilderExtensions.AddSecretProvider<ScopedSecretProvider>(null!));
        Assert.Throws<ArgumentNullException>("builder", () => HmacServerBuilderExtensions.AddSecretProvider(null!, _ => TestCredentials.CreateSecretProvider()));
        Assert.Throws<ArgumentNullException>("factory", () => builder.AddSecretProvider(null!));
        Assert.Throws<ArgumentNullException>("builder", () => HmacServerBuilderExtensions.AddInMemorySecrets(null!, TestCredentials.Secrets));
        Assert.Throws<ArgumentNullException>("secrets", () => builder.AddInMemorySecrets(null!));
        Assert.Throws<ArgumentNullException>("builder", () => HmacServerBuilderExtensions.AddReplayProtection(null!));
        Assert.Throws<ArgumentNullException>("builder", () => HmacServerBuilderExtensions.AddReplayProtection<CustomReplayCache>(null!));
    }
}
