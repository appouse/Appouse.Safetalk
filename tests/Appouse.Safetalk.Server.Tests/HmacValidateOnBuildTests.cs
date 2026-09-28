using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// <see cref="IHmacRequestValidator"/> is registered by type, so <see cref="ServiceProviderOptions.ValidateOnBuild"/>
/// reports a missing <see cref="IHmacSecretProvider"/> (or a missing dependency of it) at start-up instead of on the
/// first signed request, including when only the <c>AddHmac()</c> authentication scheme is used.
/// </summary>
public sealed class HmacValidateOnBuildTests
{
    private static readonly ServiceProviderOptions Validating = new() { ValidateOnBuild = true, ValidateScopes = true };

    public interface IPartnerStore
    {
        string? FindSecret(string clientId);
    }

    [Fact]
    public void AddHmacOnly_WithoutSecretProvider_ValidateOnBuildReportsTheMissingSecretProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();

        AggregateException exception = Assert.Throws<AggregateException>(() => services.BuildServiceProvider(Validating));

        AssertReportsMissing(exception, typeof(IHmacSecretProvider));
    }

    [Fact]
    public void AddHmacServerOnly_WithoutSecretProvider_ValidateOnBuildReportsTheMissingSecretProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHmacServer();

        AggregateException exception = Assert.Throws<AggregateException>(() => services.BuildServiceProvider(Validating));

        AssertReportsMissing(exception, typeof(IHmacSecretProvider));
    }

    [Fact]
    public void SecretProviderWithMissingDependency_ValidateOnBuildReportsTheDependency()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHmacServer().AddSecretProvider<StoreBackedSecretProvider>();
        services.AddAuthentication().AddHmac();

        AggregateException exception = Assert.Throws<AggregateException>(() => services.BuildServiceProvider(Validating));

        AssertReportsMissing(exception, typeof(IPartnerStore));
    }

    [Theory]
    [InlineData(ServiceLifetime.Scoped)]
    [InlineData(ServiceLifetime.Transient)]
    [InlineData(ServiceLifetime.Singleton)]
    public async Task SecretProviderWithDependencies_ValidateOnBuildSucceedsForEveryLifetime(ServiceLifetime lifetime)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IPartnerStore>(new DictionaryPartnerStore());
        services.AddHmacServer().AddSecretProvider<StoreBackedSecretProvider>(lifetime);
        services.AddAuthentication().AddHmac();

        await using ServiceProvider provider = services.BuildServiceProvider(Validating);
        await using AsyncServiceScope scope = provider.CreateAsyncScope();

        Assert.IsType<DefaultHmacRequestValidator>(scope.ServiceProvider.GetRequiredService<IHmacRequestValidator>());
    }

    [Fact]
    public async Task AddHmacServerFromConfigurationWithClients_ValidateOnBuildSucceeds()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection([new("Safetalk:Clients:partner-a", TestCredentials.Secret)])
            .Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHmacServer(configuration.GetSection("Safetalk"));

        await using ServiceProvider provider = services.BuildServiceProvider(Validating);

        Assert.NotNull(provider.GetRequiredService<IHmacSecretProvider>());
    }

    [Fact]
    public async Task WebApplication_AddHmacOnlyWithValidateOnBuild_FailsAtBuildNotOnTheFirstRequest()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(HmacValidateOnBuildTests).Assembly.GetName().Name,
            EnvironmentName = Environments.Production,
        });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Host.UseDefaultServiceProvider(options =>
        {
            options.ValidateOnBuild = true;
            options.ValidateScopes = true;
        });
        builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
        builder.Services.AddAuthorization();

        WebApplication? app = null;
        AggregateException exception = Assert.Throws<AggregateException>(() => app = builder.Build());
        if (app is not null)
        {
            await app.DisposeAsync();
        }

        AssertReportsMissing(exception, typeof(IHmacSecretProvider));
    }

    private static void AssertReportsMissing(AggregateException exception, Type missing) =>
        Assert.Contains(
            exception.Flatten().InnerExceptions,
            inner => inner.Message.Contains(missing.Name, StringComparison.Ordinal)
                && inner.Message.Contains(typeof(IHmacRequestValidator).FullName!, StringComparison.Ordinal));

    public sealed class StoreBackedSecretProvider(IPartnerStore store) : IHmacSecretProvider
    {
        public ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(store.FindSecret(clientId));
    }

    private sealed class DictionaryPartnerStore : IPartnerStore
    {
        public string? FindSecret(string clientId) => TestCredentials.Secrets.GetValueOrDefault(clientId);
    }
}
