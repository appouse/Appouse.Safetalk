using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A <see cref="WebApplication"/> on a real Kestrel server bound to a free loopback port, with a fake clock, and a
/// raw socket helper to send request lines that <see cref="HttpClient"/> cannot produce (absolute-form, asterisk-form).
/// </summary>
internal sealed class KestrelApplication : IAsyncDisposable
{
    private readonly WebApplication _app;

    private KestrelApplication(WebApplication app, FakeTimeProvider time, int port)
    {
        _app = app;
        Time = time;
        Port = port;
    }

    public FakeTimeProvider Time { get; }

    public int Port { get; }

    public IServiceProvider Services => _app.Services;

    public static async Task<KestrelApplication> StartAsync(Action<WebApplicationBuilder> configureBuilder, Action<WebApplication> configurePipeline)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(KestrelApplication).Assembly.GetName().Name,
            EnvironmentName = Environments.Production,
        });
        builder.WebHost.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        builder.Logging.ClearProviders();

        var time = new FakeTimeProvider(TestCredentials.Now);
        builder.Services.AddSingleton<TimeProvider>(time);
        configureBuilder(builder);

        WebApplication app = builder.Build();
        try
        {
            configurePipeline(app);
            await app.StartAsync(TestContext.Current.CancellationToken);
            string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            return new KestrelApplication(app, time, new Uri(address).Port);
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }
    }

    public string Timestamp => TestCredentials.FormatTimestamp(Time.GetUtcNow().ToUnixTimeSeconds());

    /// <summary>
    /// Sends a request with the given request line and signature headers over a raw socket and returns the status code.
    /// </summary>
    public async Task<int> SendRawAsync(string requestLine, string timestamp, string signature, string clientId = TestCredentials.ClientId)
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        string request =
            requestLine + "\r\n" +
            "Host: 127.0.0.1:" + Port.ToString(CultureInfo.InvariantCulture) + "\r\n" +
            SafetalkHeaderNames.ClientId + ": " + clientId + "\r\n" +
            SafetalkHeaderNames.Timestamp + ": " + timestamp + "\r\n" +
            SafetalkHeaderNames.Signature + ": " + signature + "\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n\r\n";

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, Port, cancellationToken);
        NetworkStream stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cancellationToken);

        using var reader = new StreamReader(stream, Encoding.ASCII);
        string? statusLine = await reader.ReadLineAsync(cancellationToken);
        Assert.NotNull(statusLine);
        string[] parts = statusLine.Split(' ', 3);
        return int.Parse(parts[1], CultureInfo.InvariantCulture);
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
