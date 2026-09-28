using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A <see cref="WebApplication"/> hosted on <see cref="TestServer"/> with a fake clock registered as
/// <see cref="TimeProvider"/>, plus helpers to send signed requests.
/// </summary>
internal sealed class TestApplication : IAsyncDisposable
{
    private readonly WebApplication _app;

    private TestApplication(WebApplication app, FakeTimeProvider time)
    {
        _app = app;
        Time = time;
        Client = app.GetTestClient();
    }

    public FakeTimeProvider Time { get; }

    public HttpClient Client { get; }

    public IServiceProvider Services => _app.Services;

    public static async Task<TestApplication> StartAsync(Action<WebApplicationBuilder> configureBuilder, Action<WebApplication> configurePipeline)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(TestApplication).Assembly.GetName().Name,
            EnvironmentName = Environments.Production,
        });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        var time = new FakeTimeProvider(TestCredentials.Now);
        builder.Services.AddSingleton<TimeProvider>(time);
        builder.Services.AddSingleton<RequestCounter>();
        configureBuilder(builder);

        WebApplication app = builder.Build();
        try
        {
            configurePipeline(app);
            await app.StartAsync(TestContext.Current.CancellationToken);
            return new TestApplication(app, time);
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }
    }

    public HttpRequestMessage CreateSignedRequest(
        HttpMethod method,
        string pathAndQuery,
        HttpContent? content = null,
        byte[]? signedBody = null,
        string clientId = TestCredentials.ClientId,
        string secret = TestCredentials.Secret)
    {
        string timestamp = TestCredentials.FormatTimestamp(Time.GetUtcNow().ToUnixTimeSeconds());
        var request = new HttpRequestMessage(method, new Uri(pathAndQuery, UriKind.Relative)) { Content = content };
        request.Headers.Add(SafetalkHeaderNames.ClientId, clientId);
        request.Headers.Add(SafetalkHeaderNames.Timestamp, timestamp);
        request.Headers.Add(SafetalkHeaderNames.Signature, TestCredentials.Sign(method.Method, pathAndQuery, timestamp, signedBody ?? [], secret));
        return request;
    }

    public HttpRequestMessage CreateSignedRequest(HttpMethod method, string pathAndQuery, byte[] body) =>
        CreateSignedRequest(method, pathAndQuery, new ByteArrayContent(body), body);

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
    {
        using (request)
        {
            return await Client.SendAsync(request, TestContext.Current.CancellationToken);
        }
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
    }
}
