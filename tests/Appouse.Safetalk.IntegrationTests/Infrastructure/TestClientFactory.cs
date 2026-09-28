using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Builds client-side service providers that use the real <c>AddHmacClient&lt;TClient&gt;</c> registration and
/// point at a <see cref="SafetalkServer"/>.
/// </summary>
internal static class TestClientFactory
{
    public static ServiceProvider Create(SafetalkServer server) => Create(server, new ClientSetup());

    public static ServiceProvider Create(SafetalkServer server, ClientSetup setup)
    {
        ArgumentNullException.ThrowIfNull(setup);

        var services = new ServiceCollection();
        if (setup.TimeProvider is not null)
        {
            services.AddSingleton(setup.TimeProvider);
        }

        IHttpClientBuilder builder = services
            .AddHmacClient<SafetalkApiClient>(options =>
            {
                options.ClientId = setup.ClientId;
                options.Secret = setup.Secret;
            })
            .UseServer(server, setup.RequestVersion);

        if (setup.HandlerBeforeSigning is { } before)
        {
            // Added AFTER AddHmacClient on purpose: the signing handler is always the innermost delegating handler,
            // so this handler still runs in front of it and sees the request before it is signed.
            builder.AddHttpMessageHandler(before);
        }

        if (setup.HandlerAfterSigning is { } after)
        {
            builder.WrapPrimaryHandler(server, after);
        }

        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    /// <summary>
    /// Points an HTTP client registration at the server (base address and primary handler).
    /// </summary>
    public static IHttpClientBuilder UseServer(this IHttpClientBuilder builder, SafetalkServer server, Version? requestVersion = null)
    {
        return builder
            .ConfigureHttpClient(client =>
            {
                client.BaseAddress = server.BaseAddress;
                if (requestVersion is not null)
                {
                    client.DefaultRequestVersion = requestVersion;
                    client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact;
                }
            })
            .ConfigurePrimaryHttpMessageHandler(server.CreatePrimaryHandler);
    }

    /// <summary>
    /// Places <paramref name="createHandler"/> between the signing handler and the network by wrapping the primary
    /// handler. The signing handler is always the innermost <em>additional</em> handler, so this is the only place
    /// where a handler sees (and can tamper with) the signed request, like a proxy or a man-in-the-middle would.
    /// </summary>
    public static IHttpClientBuilder WrapPrimaryHandler(this IHttpClientBuilder builder, SafetalkServer server, Func<DelegatingHandler> createHandler)
    {
        return builder.ConfigurePrimaryHttpMessageHandler(() =>
        {
            DelegatingHandler handler = createHandler();
            handler.InnerHandler = server.CreatePrimaryHandler();
            return handler;
        });
    }
}
