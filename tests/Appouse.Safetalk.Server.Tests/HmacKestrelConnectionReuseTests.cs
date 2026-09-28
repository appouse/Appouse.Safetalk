using System.Globalization;
using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// Kestrel reuses feature collections and <see cref="HttpContext"/> instances across the requests of a keep-alive
/// connection. The validation result cached for one request must never be seen by the next one.
/// </summary>
public sealed class HmacKestrelConnectionReuseTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task KeepAliveConnection_VerifiedRequestDoesNotAuthenticateTheNextRequest()
    {
        await using KestrelApplication app = await StartAsync();
        using HttpClient client = CreateSingleConnectionClient(app);

        using HttpResponseMessage signed = await client.SendAsync(Sign(app, HttpMethod.Get, "/whoami"), CancellationToken);
        using HttpResponseMessage unsignedProtected = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri("/whoami", UriKind.Relative)), CancellationToken);
        using HttpResponseMessage unsignedOpen = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri("/open", UriKind.Relative)), CancellationToken);

        string[] first = (await signed.Content.ReadAsStringAsync(CancellationToken)).Split('|');
        string[] third = (await unsignedOpen.Content.ReadAsStringAsync(CancellationToken)).Split('|');
        Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
        Assert.Equal(TestCredentials.ClientId, first[1]);
        Assert.Equal(HttpStatusCode.Unauthorized, unsignedProtected.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unsignedOpen.StatusCode);
        Assert.Equal(first[0], third[0]); // Same connection.
        Assert.Equal("anonymous", third[1]);
        Assert.Equal("False", third[2]);
    }

    [Fact]
    public async Task KeepAliveConnection_RejectedRequestDoesNotRejectTheNextValidRequest()
    {
        await using KestrelApplication app = await StartAsync();
        using HttpClient client = CreateSingleConnectionClient(app);

        using HttpResponseMessage invalid = await client.SendAsync(Sign(app, HttpMethod.Get, "/whoami", secret: "wrong-secret"), CancellationToken);
        using HttpResponseMessage valid = await client.SendAsync(Sign(app, HttpMethod.Get, "/whoami?n=2"), CancellationToken);
        using HttpResponseMessage validAgain = await client.SendAsync(Sign(app, HttpMethod.Get, "/whoami?n=3"), CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        Assert.Equal(HttpStatusCode.OK, validAgain.StatusCode);
        string[] second = (await valid.Content.ReadAsStringAsync(CancellationToken)).Split('|');
        string[] third = (await validAgain.Content.ReadAsStringAsync(CancellationToken)).Split('|');
        Assert.Equal(second[0], third[0]);
        Assert.Equal(TestCredentials.ClientId, third[1]);
    }

    [Fact]
    public async Task KeepAliveConnection_ReplayOnTheSameConnectionIsStillDetected()
    {
        await using KestrelApplication app = await StartAsync();
        using HttpClient client = CreateSingleConnectionClient(app);
        string timestamp = app.Timestamp;
        string signature = TestCredentials.Sign("GET", "/whoami", timestamp, []);

        using HttpResponseMessage original = await client.SendAsync(WithSignature("/whoami", timestamp, signature), CancellationToken);
        using HttpResponseMessage replay = await client.SendAsync(WithSignature("/whoami", timestamp, signature), CancellationToken);

        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    private static HttpClient CreateSingleConnectionClient(KestrelApplication app) =>
        new(new SocketsHttpHandler { MaxConnectionsPerServer = 1, PooledConnectionLifetime = Timeout.InfiniteTimeSpan })
        {
            BaseAddress = new Uri("http://127.0.0.1:" + app.Port.ToString(CultureInfo.InvariantCulture)),
        };

    private static HttpRequestMessage Sign(KestrelApplication app, HttpMethod method, string pathAndQuery, string secret = TestCredentials.Secret)
    {
        string timestamp = app.Timestamp;
        return WithSignature(pathAndQuery, timestamp, TestCredentials.Sign(method.Method, pathAndQuery, timestamp, [], secret), method);
    }

    private static HttpRequestMessage WithSignature(string pathAndQuery, string timestamp, string signature, HttpMethod? method = null)
    {
        var request = new HttpRequestMessage(method ?? HttpMethod.Get, new Uri(pathAndQuery, UriKind.Relative));
        request.Headers.Add(SafetalkHeaderNames.ClientId, TestCredentials.ClientId);
        request.Headers.Add(SafetalkHeaderNames.Timestamp, timestamp);
        request.Headers.Add(SafetalkHeaderNames.Signature, signature);
        return request;
    }

    private static string Describe(HttpContext context) =>
        $"{context.Connection.Id}|{context.GetHmacClientId() ?? "anonymous"}|{context.User.Identity?.IsAuthenticated == true}";

    private static Task<KestrelApplication> StartAsync() =>
        KestrelApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets).AddReplayProtection();
                builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
            },
            app =>
            {
                app.UseAuthentication();
                app.UseHmacAuthentication();
                app.MapGet("/whoami", Describe);
                app.MapGet("/open", Describe).SkipHmacValidation();
            });
}
