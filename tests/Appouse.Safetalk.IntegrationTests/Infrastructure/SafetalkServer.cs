using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// A running protected application (<c>AddHmacServer()</c> + <c>UseHmacAuthentication()</c>) hosted either by the
/// in-memory TestServer or by a real Kestrel server on a dynamic loopback port.
/// </summary>
internal sealed class SafetalkServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly TestServer? _testServer;
    private readonly ValidationLog _validationLog;

    private SafetalkServer(WebApplication app, Uri baseAddress, TestServer? testServer, ValidationLog validationLog)
    {
        _app = app;
        _testServer = testServer;
        _validationLog = validationLog;
        BaseAddress = baseAddress;
    }

    /// <summary>
    /// The root address of the server, for example <c>http://127.0.0.1:54321/</c>.
    /// </summary>
    public Uri BaseAddress { get; }

    public IServiceProvider Services => _app.Services;

    /// <summary>
    /// Every validation result produced by the HMAC middleware, in order.
    /// </summary>
    public IReadOnlyCollection<HmacValidationResult> ValidationResults => _validationLog.Results;

    /// <summary>
    /// The failure reason of the most recent validation.
    /// </summary>
    public HmacValidationFailure LastFailure => _validationLog.Last.Failure;

    public static Task<SafetalkServer> StartAsync(TestHostKind kind, CancellationToken cancellationToken)
        => StartAsync(kind, new ServerSetup(), cancellationToken);

    public static async Task<SafetalkServer> StartAsync(TestHostKind kind, ServerSetup setup, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(setup);

        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(SafetalkServer).Assembly.GetName().Name,
            EnvironmentName = Environments.Development,
            ContentRootPath = AppContext.BaseDirectory,
        });

        builder.Logging.ClearProviders();
        if (setup.Logs is { } logs)
        {
            builder.Logging.AddProvider(logs).AddFilter<LogCapture>("Appouse.Safetalk", LogLevel.Debug);
        }

        builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(5));

        if (kind == TestHostKind.TestServer)
        {
            builder.WebHost.UseTestServer();
        }
        else
        {
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            if (setup.Protocols is { } protocols)
            {
                builder.WebHost.ConfigureKestrel(kestrel => kestrel.ConfigureEndpointDefaults(listen => listen.Protocols = protocols));
            }
        }

        builder.Services.AddControllers().AddApplicationPart(typeof(SafetalkServer).Assembly);
        builder.Services.AddAuthorization(options => options.AddPolicy(
            EchoEndpoints.PartnerAOnlyPolicy,
            policy => policy.RequireClaim(HmacAuthenticationDefaults.ClientIdClaimType, TestCredentials.ClientId)));
        if (setup.UseProblemDetails)
        {
            builder.Services.AddProblemDetails();
        }

        IHmacServerBuilder hmac;
        if (setup.Configuration is { } configuration)
        {
            hmac = builder.Services.AddHmacServer(configuration);
            if (setup.ConfigureOptions is { } configureOptions)
            {
                builder.Services.Configure(configureOptions);
            }
        }
        else
        {
            hmac = builder.Services
                .AddHmacServer(setup.ConfigureOptions)
                .AddInMemorySecrets(TestCredentials.All);
        }

        setup.ConfigureHmac?.Invoke(hmac);

        if (setup.AddHmacAuthenticationScheme)
        {
            builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
        }

        // Transparent decorator that records the (otherwise undisclosed) validation outcome. It wraps the validator
        // created by the library's own registration (by type since round 4: the internal DefaultHmacRequestValidator,
        // which also wires the clock skew tracker), so the tests exercise exactly what AddHmacServer() registers. Being a
        // factory, this wrapper hides the validator's dependencies from ValidateOnBuild; ServerValidateOnBuildTests
        // covers that on an unwrapped host.
        var validationLog = new ValidationLog();
        builder.Services.AddSingleton(validationLog);
        if (setup.RecordValidationResults)
        {
            ServiceDescriptor libraryValidator = builder.Services.Last(descriptor => descriptor.ServiceType == typeof(IHmacRequestValidator));
            builder.Services.RemoveAll<IHmacRequestValidator>();
            builder.Services.AddScoped<IHmacRequestValidator>(services => new RecordingRequestValidator(
                CreateLibraryValidator(libraryValidator, services),
                services.GetRequiredService<ValidationLog>()));
        }

        if (setup.TimeProvider is not null)
        {
            builder.Services.AddSingleton(setup.TimeProvider);
        }

        setup.ConfigureServices?.Invoke(builder.Services);

        WebApplication app = builder.Build();
        try
        {
            if (setup.PathBase is not null)
            {
                app.UsePathBase(setup.PathBase);
                app.UseRouting();
            }

            setup.ConfigurePipeline?.Invoke(app);
            if (setup.ProtectOnly is { } predicate)
            {
                app.UseWhen(predicate, branch => branch.UseHmacAuthentication());
            }
            else
            {
                app.UseHmacAuthentication();
            }

            setup.ConfigurePipelineAfterHmac?.Invoke(app);
            app.UseAuthorization(); // As in the README: after UseHmacAuthentication().

            EchoEndpoints.Map(app);
            setup.ConfigureEndpoints?.Invoke(app);
            ControllerActionEndpointConventionBuilder controllers = app.MapControllers();
            setup.ConfigureControllers?.Invoke(controllers);

            await app.StartAsync(cancellationToken);

            if (kind == TestHostKind.TestServer)
            {
                TestServer testServer = app.GetTestServer();
                return new SafetalkServer(app, testServer.BaseAddress, testServer, validationLog);
            }

            string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            return new SafetalkServer(app, new Uri(address.TrimEnd('/') + "/"), testServer: null, validationLog);
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }
    }

    private static IHmacRequestValidator CreateLibraryValidator(ServiceDescriptor descriptor, IServiceProvider services)
    {
        object validator = descriptor.ImplementationFactory?.Invoke(services)
            ?? descriptor.ImplementationInstance
            ?? ActivatorUtilities.CreateInstance(services, descriptor.ImplementationType!);

        return (IHmacRequestValidator)validator;
    }

    /// <summary>
    /// Creates the innermost handler that talks to this server: the TestServer handler, or a plain
    /// <see cref="SocketsHttpHandler"/> for Kestrel.
    /// </summary>
    public HttpMessageHandler CreatePrimaryHandler()
        => _testServer?.CreateHandler() ?? new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };

    /// <summary>
    /// Creates an <see cref="HttpClient"/> that does NOT sign requests (unsigned calls and replays).
    /// </summary>
    public HttpClient CreateUnsignedClient() => new(CreatePrimaryHandler(), disposeHandler: true) { BaseAddress = BaseAddress };

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _app.StopAsync(CancellationToken.None);
        }
        finally
        {
            await _app.DisposeAsync();
        }
    }
}
