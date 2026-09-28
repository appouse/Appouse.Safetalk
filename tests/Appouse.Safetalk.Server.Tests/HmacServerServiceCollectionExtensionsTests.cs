using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacServerServiceCollectionExtensionsTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public void AddHmacServer_RegistersDefaultServicesWithExpectedLifetimes()
    {
        var services = new ServiceCollection();

        services.AddHmacServer();

        // The validator is registered by type (so ValidateOnBuild checks its dependencies); the internal wrapper passes
        // the clock skew tracker to the default validator.
        ServiceDescriptor validator = Assert.Single(services, d => d.ServiceType == typeof(IHmacRequestValidator));
        Assert.Equal(ServiceLifetime.Scoped, validator.Lifetime);
        Assert.Equal(typeof(DefaultHmacRequestValidator), validator.ImplementationType);
        Assert.Null(validator.ImplementationFactory);
        Assert.Null(validator.ImplementationInstance);
        ServiceDescriptor tracker = Assert.Single(services, d => d.ServiceType == typeof(HmacClockSkewTracker));
        Assert.Equal(ServiceLifetime.Singleton, tracker.Lifetime);
        Assert.NotNull(tracker.ImplementationFactory);
        AssertSingleRegistration<IHmacReplayCache>(services, ServiceLifetime.Singleton, typeof(InMemoryHmacReplayCache));
        Assert.Same(HmacSha256SignatureService.Instance, Assert.Single(services, d => d.ServiceType == typeof(IHmacSignatureService)).ImplementationInstance);
        Assert.Same(TimeProvider.System, Assert.Single(services, d => d.ServiceType == typeof(TimeProvider)).ImplementationInstance);
        Assert.Single(services, d => d.ServiceType == typeof(HmacServerMarkerService));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IHmacSecretProvider));
    }

    [Fact]
    public async Task AddHmacServer_WithSecretsAndLogging_ResolvesWorkingValidator()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
        await using ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        IHmacRequestValidator validator = scope.ServiceProvider.GetRequiredService<IHmacRequestValidator>();
        var request = new SignedRequestBuilder(TimeProvider.System.GetUtcNow().ToUnixTimeSeconds());

        HmacValidationResult result = await validator.ValidateAsync(request.Build(), CancellationToken);

        Assert.IsType<DefaultHmacRequestValidator>(validator);
        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task AddHmacServer_ExistingTimeProvider_IsKeptAndUsedByValidator()
    {
        var time = new FakeTimeProvider(TestCredentials.Now);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(time);
        services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
        await using ServiceProvider provider = services.BuildServiceProvider();
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        IHmacRequestValidator validator = scope.ServiceProvider.GetRequiredService<IHmacRequestValidator>();

        HmacValidationResult result = await validator.ValidateAsync(
            new SignedRequestBuilder(TestCredentials.Now.ToUnixTimeSeconds()).Build(),
            CancellationToken);

        Assert.Same(time, provider.GetRequiredService<TimeProvider>());
        Assert.True(result.Succeeded); // Would be out of range if the system clock were used.
    }

    [Fact]
    public void AddHmacServer_ConfigureDelegate_IsApplied()
    {
        var services = new ServiceCollection();
        services.AddHmacServer(options =>
        {
            options.AllowedClockSkew = TimeSpan.FromMinutes(2);
            options.MaxBodySize = 1024;
            options.EnableReplayProtection = true;
        });
        using ServiceProvider provider = services.BuildServiceProvider();

        HmacServerOptions options = provider.GetRequiredService<IOptions<HmacServerOptions>>().Value;

        Assert.Equal(TimeSpan.FromMinutes(2), options.AllowedClockSkew);
        Assert.Equal(1024, options.MaxBodySize);
        Assert.True(options.EnableReplayProtection);
    }

    [Fact]
    public void AddHmacServer_CalledTwice_DoesNotDuplicateServicesAndAppliesBothConfigurations()
    {
        var services = new ServiceCollection();
        services.AddHmacServer(options => options.MaxBodySize = 1024);
        services.AddHmacServer(options => options.EnableReplayProtection = true);
        using ServiceProvider provider = services.BuildServiceProvider();

        HmacServerOptions options = provider.GetRequiredService<IOptions<HmacServerOptions>>().Value;

        Assert.Single(services, d => d.ServiceType == typeof(IHmacRequestValidator));
        Assert.Single(services, d => d.ServiceType == typeof(IHmacReplayCache));
        Assert.Single(provider.GetServices<IValidateOptions<HmacServerOptions>>(), v => v is HmacServerOptionsValidator);
        Assert.Equal(1024, options.MaxBodySize);
        Assert.True(options.EnableReplayProtection);
    }

    [Fact]
    public void AddHmacServer_RegistersOptionsValidator()
    {
        var services = new ServiceCollection();
        services.AddHmacServer(options => options.MaxBodySize = -1);
        using ServiceProvider provider = services.BuildServiceProvider();

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<HmacServerOptions>>().Value);

        Assert.Contains(exception.Failures, failure => failure.Contains(nameof(HmacServerOptions.MaxBodySize), StringComparison.Ordinal));
    }

    [Fact]
    public async Task AddHmacServer_InvalidOptions_FailOnHostStart()
    {
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Services.AddHmacServer(options => options.AllowedClockSkew = TimeSpan.Zero);
        using IHost host = builder.Build();

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(CancellationToken));

        Assert.Contains(exception.Failures, failure => failure.Contains(nameof(HmacServerOptions.AllowedClockSkew), StringComparison.Ordinal));
    }

    [Fact]
    public async Task AddHmacServer_ValidOptions_HostStarts()
    {
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Services.AddHmacServer(options => options.AllowedClockSkew = TimeSpan.FromMinutes(1));
        using IHost host = builder.Build();

        await host.StartAsync(CancellationToken);
        await host.StopAsync(CancellationToken);
    }

    [Fact]
    public void AddHmacServer_ReturnsBuilderOverSameServiceCollection()
    {
        var services = new ServiceCollection();

        IHmacServerBuilder builder = services.AddHmacServer();

        Assert.Same(services, builder.Services);
    }

    [Fact]
    public void AddHmacServer_NullServices_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("services", () => HmacServerServiceCollectionExtensions.AddHmacServer(null!));
    }

    [Fact]
    public async Task AddHmacServer_ValidatorIsResolvedPerScope()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
        await using ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        await using AsyncServiceScope first = provider.CreateAsyncScope();
        await using AsyncServiceScope second = provider.CreateAsyncScope();

        Assert.NotSame(
            first.ServiceProvider.GetRequiredService<IHmacRequestValidator>(),
            second.ServiceProvider.GetRequiredService<IHmacRequestValidator>());
        Assert.Same(
            first.ServiceProvider.GetRequiredService<IHmacReplayCache>(),
            second.ServiceProvider.GetRequiredService<IHmacReplayCache>());
        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IHmacRequestValidator>());
    }

    [Fact]
    public async Task AddHmacServer_TypeRegisteredValidator_ResolvesToDefaultValidatorWithSharedTracker()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
        await using ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });

        await using AsyncServiceScope first = provider.CreateAsyncScope();
        await using AsyncServiceScope second = provider.CreateAsyncScope();

        Assert.IsType<DefaultHmacRequestValidator>(first.ServiceProvider.GetRequiredService<IHmacRequestValidator>());
        Assert.IsType<DefaultHmacRequestValidator>(second.ServiceProvider.GetRequiredService<IHmacRequestValidator>());
        Assert.Same(
            first.ServiceProvider.GetRequiredService<HmacClockSkewTracker>(),
            second.ServiceProvider.GetRequiredService<HmacClockSkewTracker>());
    }

    [Fact]
    public void AddHmacServer_CalledTwice_RegistersOneValidatorFactoryAndOneTracker()
    {
        var services = new ServiceCollection();

        services.AddHmacServer();
        services.AddHmacServer();
        services.AddAuthentication().AddHmac();

        Assert.Single(services, d => d.ServiceType == typeof(IHmacRequestValidator));
        Assert.Single(services, d => d.ServiceType == typeof(HmacClockSkewTracker));
    }

    [Fact]
    public async Task AddHmacServer_ValidatorRegisteredBefore_IsKept()
    {
        var custom = new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId));
        var services = new ServiceCollection();
        services.AddSingleton<IHmacRequestValidator>(custom);

        services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
        await using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Same(custom, provider.GetRequiredService<IHmacRequestValidator>());
    }

    [Fact]
    public async Task ClockSkewTracker_CapturesClockSkewAtFirstResolutionNotAtRegistration()
    {
        (IConfigurationRoot root, ReloadableConfigurationProvider source) = ReloadableConfigurationSource.CreateRoot(
        [
            new("Safetalk:AllowedClockSkew", "00:01:00"),
        ]);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHmacServer(root.GetSection("Safetalk")).AddInMemorySecrets(TestCredentials.Secrets);
        await using ServiceProvider provider = services.BuildServiceProvider();

        source.Update("Safetalk:AllowedClockSkew", "00:02:00");
        HmacClockSkewTracker tracker = provider.GetRequiredService<HmacClockSkewTracker>();
        source.Update("Safetalk:AllowedClockSkew", "00:05:00");

        Assert.Equal(TimeSpan.FromMinutes(2), tracker.MaxClockSkew);
        Assert.Same(tracker, provider.GetRequiredService<HmacClockSkewTracker>());
        Assert.Equal(TimeSpan.FromMinutes(2), provider.GetRequiredService<HmacClockSkewTracker>().MaxClockSkew);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(int.MaxValue)]
    public async Task AddHmacServer_UndefinedEnforcementMode_FailsOnHostStart(int mode)
    {
        HostApplicationBuilder builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Services.AddHmacServer(options => options.EnforcementMode = (HmacEnforcementMode)mode);
        using IHost host = builder.Build();

        OptionsValidationException exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(CancellationToken));

        Assert.Contains(exception.Failures, failure => failure.Contains(nameof(HmacServerOptions.EnforcementMode), StringComparison.Ordinal));
    }

    private static void AssertSingleRegistration<TService>(IServiceCollection services, ServiceLifetime lifetime, Type implementationType)
    {
        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(TService));
        Assert.Equal(lifetime, descriptor.Lifetime);
        Assert.Equal(implementationType, descriptor.ImplementationType);
    }
}
