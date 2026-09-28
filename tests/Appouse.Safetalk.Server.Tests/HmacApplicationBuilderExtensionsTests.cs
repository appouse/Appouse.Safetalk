using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacApplicationBuilderExtensionsTests
{
    [Fact]
    public void UseHmacAuthentication_WithoutAddHmacServer_ThrowsInvalidOperationException()
    {
        using ServiceProvider services = new ServiceCollection().AddLogging().BuildServiceProvider();
        var app = new ApplicationBuilder(services);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => app.UseHmacAuthentication());

        Assert.Contains("AddHmacServer", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UseHmacAuthentication_WithoutSecretProvider_ThrowsInvalidOperationException()
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddHmacServer();
        using ServiceProvider services = serviceCollection.BuildServiceProvider();
        var app = new ApplicationBuilder(services);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => app.UseHmacAuthentication());

        Assert.Contains(nameof(IHmacSecretProvider), exception.Message, StringComparison.Ordinal);
        Assert.Contains("AddSecretProvider", exception.Message, StringComparison.Ordinal);
        Assert.Contains("AddSecretsFromConfiguration", exception.Message, StringComparison.Ordinal);
        Assert.Contains("AddInMemorySecrets", exception.Message, StringComparison.Ordinal);
        Assert.Contains("'" + HmacServerServiceCollectionExtensions.ClientsConfigurationKey + "'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UseHmacAuthentication_ConfigurationWithoutClientsChild_ThrowsMentioningTheClientsChild()
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddHmacServer(new ConfigurationBuilder()
            .AddInMemoryCollection([new KeyValuePair<string, string?>("Safetalk:Client:partner-a", "secret-a")])
            .Build()
            .GetSection("Safetalk"));
        using ServiceProvider services = serviceCollection.BuildServiceProvider();
        var app = new ApplicationBuilder(services);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => app.UseHmacAuthentication());

        Assert.Contains("'Clients'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UseHmacAuthentication_DoesNotResolveTheValidatorUntilARequestArrives()
    {
        // The validator is scoped and resolved per request (it may depend on scoped secret providers).
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddSingleton<InstanceTracker>();
        serviceCollection.AddHmacServer().AddSecretProvider<ScopedSecretProvider>();
        await using ServiceProvider services = serviceCollection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        var app = new ApplicationBuilder(services);
        app.UseHmacAuthentication();
        app.Run(_ => Task.CompletedTask);
        RequestDelegate pipeline = app.Build();
        InstanceTracker tracker = services.GetRequiredService<InstanceTracker>();
        Assert.Empty(tracker.Instances);

        for (int i = 0; i < 2; i++)
        {
            await using AsyncServiceScope scope = services.CreateAsyncScope();
            DefaultHttpContext context = new SignedRequestBuilder(TimeProvider.System.GetUtcNow().ToUnixTimeSeconds()).Build();
            context.RequestServices = scope.ServiceProvider;
            await pipeline(context);
            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        }

        Assert.Equal(2, tracker.Instances.Count);
    }

    [Fact]
    public void UseHmacAuthentication_WithScopedSecretProvider_ReturnsSameBuilder()
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddSingleton<InstanceTracker>();
        serviceCollection.AddHmacServer().AddSecretProvider<ScopedSecretProvider>();
        using ServiceProvider services = serviceCollection.BuildServiceProvider();
        var app = new ApplicationBuilder(services);

        IApplicationBuilder result = app.UseHmacAuthentication();

        Assert.Same(app, result);
    }

    [Fact]
    public async Task UseHmacAuthentication_BuiltPipeline_RejectsUnsignedAndForwardsSignedRequests()
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
        await using ServiceProvider services = serviceCollection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        var app = new ApplicationBuilder(services);
        string? forwardedClientId = null;
        app.UseHmacAuthentication();
        app.Run(context =>
        {
            forwardedClientId = context.GetHmacClientId();
            return Task.CompletedTask;
        });
        RequestDelegate pipeline = app.Build();

        await using (AsyncServiceScope scope = services.CreateAsyncScope())
        {
            var unsigned = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            await pipeline(unsigned);
            Assert.Equal(StatusCodes.Status401Unauthorized, unsigned.Response.StatusCode);
            Assert.Null(forwardedClientId);
        }

        await using (AsyncServiceScope scope = services.CreateAsyncScope())
        {
            DefaultHttpContext signed = new SignedRequestBuilder(TimeProvider.System.GetUtcNow().ToUnixTimeSeconds()).Build();
            signed.RequestServices = scope.ServiceProvider;
            await pipeline(signed);
            Assert.Equal(StatusCodes.Status200OK, signed.Response.StatusCode);
            Assert.Equal(TestCredentials.ClientId, forwardedClientId);
        }
    }

    [Fact]
    public void UseHmacAuthentication_NullApp_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("app", () => HmacApplicationBuilderExtensions.UseHmacAuthentication(null!));
    }
}
