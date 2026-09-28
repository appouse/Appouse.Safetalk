using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Custom <see cref="IHmacSecretProvider"/> implementations (database / Key Vault stand-ins) end to end.
/// </summary>
public sealed class SecretProviderTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ScopedProviderWithScopedDependency_IsResolvedPerRequestWithTheClaimedClientId(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var log = new SecretLookupLog();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureHmac = hmac => hmac.AddSecretProvider<DatabaseSecretProvider>(),
                ConfigureServices = services =>
                {
                    services.AddScoped<ClientSecretsDbContext>();
                    services.AddSingleton(log);
                },
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse first = await client.GetWhoAmIAsync(ct);
        WhoAmIResponse second = await client.GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, first.ClientId);
        Assert.Equal(TestCredentials.ClientId, second.ClientId);
        SecretLookup[] lookups = [.. log.Lookups];
        Assert.Equal(2, lookups.Length);
        Assert.All(lookups, lookup =>
        {
            Assert.Equal(TestCredentials.ClientId, lookup.ClientId);
            Assert.True(lookup.TokenCanBeCanceled); // The request-aborted token flows to the provider.
        });
        Assert.NotEqual(lookups[0].DbContextInstanceId, lookups[1].DbContextInstanceId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ProviderReturningNullForDisabledClient_IsRejectedAsUnknownClient(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var provider = new RotatingSecretProvider();
        provider.Set(TestCredentials.OtherClientId, null);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddSecretProvider(_ => provider, ServiceLifetime.Singleton) },
            ct);
        await using ServiceProvider enabledServices = TestClientFactory.Create(server);
        await using ServiceProvider disabledServices = TestClientFactory.Create(
            server,
            new ClientSetup { ClientId = TestCredentials.OtherClientId, Secret = TestCredentials.OtherSecret });

        WhoAmIResponse enabled = await enabledServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);
        using HttpResponseMessage disabled = await disabledServices.GetRequiredService<SafetalkApiClient>().GetAsync("/api/whoami", ct);

        Assert.Equal(TestCredentials.ClientId, enabled.ClientId);
        disabled.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnknownClient, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ServerSideSecretRotation_OldSecretIsRejected_NewSecretIsAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        const string RotatedSecret = "cm90YXRlZC1zZWNyZXQtZm9yLXBhcnRuZXItYS0yMDI2LTA5";
        var provider = new RotatingSecretProvider();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddSecretProvider(_ => provider, ServiceLifetime.Singleton) },
            ct);
        await using ServiceProvider oldClientServices = TestClientFactory.Create(server);
        await using ServiceProvider newClientServices = TestClientFactory.Create(server, new ClientSetup { Secret = RotatedSecret });
        SafetalkApiClient oldClient = oldClientServices.GetRequiredService<SafetalkApiClient>();
        SafetalkApiClient newClient = newClientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage beforeRotation = await oldClient.GetAsync("/api/whoami", ct);
        provider.Set(TestCredentials.ClientId, RotatedSecret);
        using HttpResponseMessage oldAfterRotation = await oldClient.GetAsync("/api/whoami", ct);
        using HttpResponseMessage newAfterRotation = await newClient.GetAsync("/api/whoami", ct);

        Assert.Equal(HttpStatusCode.OK, beforeRotation.StatusCode);
        oldAfterRotation.AssertUnauthorized();
        Assert.Equal(HttpStatusCode.OK, newAfterRotation.StatusCode);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UnicodeSecret_IsUsedAsUtf8KeyOnBothSides(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        const string UnicodeSecret = "gizli-anahtar-çğıöşü-ÇĞİÖŞÜ-🔐-0123456789";
        var provider = new RotatingSecretProvider();
        provider.Set(TestCredentials.ClientId, UnicodeSecret);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddSecretProvider(_ => provider, ServiceLifetime.Singleton) },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { Secret = UnicodeSecret });

        WhoAmIResponse whoAmI = await clientServices.GetRequiredService<SafetalkApiClient>().GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }
}
