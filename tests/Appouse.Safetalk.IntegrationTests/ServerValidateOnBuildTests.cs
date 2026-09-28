using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Round 4: <c>AddHmacServer()</c> registers <see cref="IHmacRequestValidator"/> by type again (an internal validator
/// that wires the clock skew cap), so the host's <c>ValidateOnBuild</c> (on by default in Development) checks its
/// dependencies at <c>Build()</c>. These tests run the library's registration unwrapped.
/// </summary>
public sealed class ServerValidateOnBuildTests
{
    /// <summary>
    /// Development host without any secret provider: <c>Build()</c> fails and names the validator and the missing
    /// <see cref="IHmacSecretProvider"/>, before any request could be served.
    /// </summary>
    [Fact]
    public async Task DevelopmentHost_WithoutSecretProvider_FailsAtBuildNamingTheValidatorAndTheMissingProvider()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Safetalk:MaxBodySize"] = "1024" })
            .Build();

        AggregateException exception = await Assert.ThrowsAsync<AggregateException>(() => SafetalkServer.StartAsync(
            TestHostKind.TestServer,
            new ServerSetup { Configuration = configuration.GetSection("Safetalk"), RecordValidationResults = false },
            ct));

        string message = exception.ToString();
        Assert.Contains(nameof(IHmacRequestValidator), message, StringComparison.Ordinal);
        Assert.Contains("DefaultHmacRequestValidator", message, StringComparison.Ordinal);
        Assert.Contains(nameof(IHmacSecretProvider), message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Outside Development (no <c>ValidateOnBuild</c>) the application still refuses to start: <c>UseHmacAuthentication()</c>
    /// explains how to register secrets. The registration itself is by type (no factory), scoped.
    /// </summary>
    [Fact]
    public async Task ProductionHost_WithoutSecretProvider_BuildsButUseHmacAuthenticationExplainsTheFix()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(ServerValidateOnBuildTests).Assembly.GetName().Name,
            EnvironmentName = Environments.Production,
            ContentRootPath = AppContext.BaseDirectory,
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddHmacServer();
        ServiceDescriptor registration = Assert.Single(builder.Services, descriptor => descriptor.ServiceType == typeof(IHmacRequestValidator));
        await using WebApplication app = builder.Build();

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => app.UseHmacAuthentication());

        Assert.Equal(
            ("DefaultHmacRequestValidator", false, ServiceLifetime.Scoped),
            (registration.ImplementationType?.Name, registration.ImplementationFactory is not null, registration.Lifetime));
        Assert.Contains(nameof(IHmacSecretProvider), exception.Message, StringComparison.Ordinal);
        Assert.Contains("AddSecretProvider<TProvider>()", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The unwrapped, type-registered validator on a Development host (scope and build validation on) verifies signed
    /// requests, rejects unsigned ones and, with replay protection, replays.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task DevelopmentHost_UnwrappedLibraryValidator_VerifiesAndRejectsReplays(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                RecordValidationResults = false,
                ConfigureHmac = hmac => hmac.AddSecretProvider<DatabaseSecretProvider>().AddReplayProtection(),
                ConfigureServices = services =>
                {
                    services.AddScoped<ClientSecretsDbContext>();
                    services.AddSingleton(new SecretLookupLog());
                },
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        using HttpClient unsigned = server.CreateUnsignedClient();

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);
        using HttpRequestMessage replay = Assert.Single(capture.Requests).ToRequestMessage();
        using HttpResponseMessage replayed = await unsigned.SendAsync(replay, ct);
        using HttpResponseMessage anonymous = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);
        using HttpResponseMessage health = await unsigned.GetAsync(new Uri("/health", UriKind.Relative), ct);

        Assert.Equal((TestCredentials.ClientId, true), (whoAmI.ClientId, whoAmI.IsAuthenticated));
        replayed.AssertUnauthorized();
        anonymous.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.Empty(server.ValidationResults); // Nothing recorded: the library's registration ran unwrapped.
    }
}
