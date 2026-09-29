using System.Globalization;
using System.Net;
using System.Text;
using Appouse.Safetalk.Redis.Tests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Appouse.Safetalk.Redis.Tests;

/// <summary>
/// Several API instances sharing one Redis or KeyDB server: a request accepted by one instance cannot be replayed
/// against any other.
/// </summary>
public sealed class DistributedReplayProtectionTests(RedisServers servers)
{
    private const string ClientId = "partner-a";
    private const string Secret = "partner-a-secret-0123456789abcdef";

    private readonly string _keyPrefix = $"e2e:{Guid.NewGuid():N}:";

    [Theory]
    [InlineData(RedisServerKind.Redis)]
    [InlineData(RedisServerKind.KeyDb)]
    public async Task SignedRequest_AcceptedByOneInstance_IsRejectedAsAReplayByEveryInstance(RedisServerKind kind)
    {
        string configuration = servers.GetConfiguration(kind);
        using IHost instanceA = await StartInstanceAsync(hmac => hmac.AddRedisReplayProtection(options =>
        {
            options.Configuration = configuration;
            options.KeyPrefix = _keyPrefix;
        }));
        using IHost instanceB = await StartInstanceAsync(hmac => hmac.AddRedisReplayProtection(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Configuration"] = configuration, ["KeyPrefix"] = _keyPrefix })
            .Build()));
        byte[] body = Encoding.UTF8.GetBytes("""{"orderId":42}""");
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

        HttpStatusCode accepted = await SendAsync(instanceA, body, timestamp);
        HttpStatusCode replayedToB = await SendAsync(instanceB, body, timestamp);
        HttpStatusCode replayedToA = await SendAsync(instanceA, body, timestamp);
        HttpStatusCode freshRequestToB = await SendAsync(instanceB, Encoding.UTF8.GetBytes("""{"orderId":43}"""), timestamp);

        Assert.Equal(
            (HttpStatusCode.OK, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.OK),
            (accepted, replayedToB, replayedToA, freshRequestToB));
    }

    [Theory]
    [InlineData(RedisServerKind.Redis)]
    [InlineData(RedisServerKind.KeyDb)]
    public async Task ConcurrentCopiesSentToSeveralInstances_ExactlyOneIsAccepted(RedisServerKind kind)
    {
        string configuration = servers.GetConfiguration(kind);
        IHost[] instances = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => StartInstanceAsync(hmac =>
            hmac.AddRedisReplayProtection(options =>
            {
                options.Configuration = configuration;
                options.KeyPrefix = _keyPrefix;
            }))));
        try
        {
            byte[] body = Encoding.UTF8.GetBytes("""{"transfer":1000}""");
            string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

            HttpStatusCode[] results = await Task.WhenAll(Enumerable.Range(0, 30).Select(i => SendAsync(instances[i % instances.Length], body, timestamp)));

            Assert.Equal(1, results.Count(status => status == HttpStatusCode.OK));
            Assert.Equal(29, results.Count(status => status == HttpStatusCode.Unauthorized));
        }
        finally
        {
            foreach (IHost instance in instances)
            {
                instance.Dispose();
            }
        }
    }

    private static async Task<IHost> StartInstanceAsync(Action<IHmacServerBuilder> configureReplayProtection)
    {
        IHost host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    configureReplayProtection(services.AddHmacServer().AddInMemorySecrets([new(ClientId, Secret)]));
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseHmacAuthentication();
                    app.UseEndpoints(endpoints => endpoints.MapPost("/api/orders", (HttpContext context) => context.GetHmacClientId()));
                }))
            .Build();

        await host.StartAsync(TestContext.Current.CancellationToken);
        return host;
    }

    private static async Task<HttpStatusCode> SendAsync(IHost instance, byte[] body, string timestamp)
    {
        const string path = "/api/orders";
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new ByteArrayContent(body) };
        request.Headers.Add(SafetalkHeaderNames.ClientId, ClientId);
        request.Headers.Add(SafetalkHeaderNames.Timestamp, timestamp);
        request.Headers.Add(SafetalkHeaderNames.Signature, HmacSha256SignatureService.Instance.ComputeSignature(Secret, "POST", path, timestamp, body));

        using HttpClient client = instance.GetTestClient();
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        return response.StatusCode;
    }
}
