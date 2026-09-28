using Appouse.Safetalk;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Adds <see cref="HmacAuthenticationMiddleware"/> to the request pipeline.
/// </summary>
public static class HmacApplicationBuilderExtensions
{
    /// <summary>
    /// The property ASP.NET Core's <c>UseRouting()</c> sets on the application builder.
    /// </summary>
    private const string EndpointRouteBuilderKey = "__EndpointRouteBuilder";

    /// <summary>
    /// The property carried by the root <c>WebApplication</c> builder, which adds routing in front of the whole
    /// pipeline unless <c>UseRouting()</c> is called explicitly. Branch builders (<c>UseWhen</c>, <c>Map</c>) do not carry it.
    /// </summary>
    private const string GlobalEndpointRouteBuilderKey = "__GlobalEndpointRouteBuilder";

    /// <summary>
    /// Adds the middleware that verifies HMAC signed requests and rejects invalid ones with <c>401 Unauthorized</c>.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The same <paramref name="app"/> for chaining.</returns>
    /// <remarks>
    /// <para>
    /// Place it after routing (implicit for <c>WebApplication</c>) and before the endpoints, so that endpoint metadata
    /// (<see cref="SkipHmacValidationAttribute"/>, <see cref="RequireHmacValidationAttribute"/>) is honoured and
    /// controllers see the authenticated client. When <c>UseRouting()</c> is registered after this middleware, the
    /// metadata cannot be read: every request is then validated (fail closed) and a warning is logged. Inside a
    /// <c>UseWhen</c>/<c>Map</c> branch, where the order cannot be determined, requests without a selected endpoint are
    /// validated in every mode; call <c>UseRouting()</c> before the branch to make unmatched routes return 404.
    /// </para>
    /// <para>
    /// When authorization services are registered (<c>AddControllers()</c> and <c>AddAuthorization()</c> both do),
    /// <c>WebApplication</c> inserts the authorization middleware <em>before</em> any user middleware unless
    /// <c>app.UseAuthorization()</c> is called explicitly. Call it right after this method so that <c>[Authorize]</c>
    /// sees the HMAC client, and register <c>AddAuthentication().AddHmac()</c> so that failed policies return
    /// <c>401</c>/<c>403</c> instead of throwing.
    /// </para>
    /// <para>
    /// Run it before middleware that replaces or reads the request body, such as <c>UseRequestDecompression()</c> or
    /// the form-field variant of <c>UseHttpMethodOverride()</c>: the signature covers the bytes sent on the wire. The
    /// <c>X-HTTP-Method-Override</c> header is not signed: requests carrying it are rejected unless
    /// <c>UseHttpMethodOverride()</c> applied it before routing (then the overriding method is verified), and a method
    /// rewritten after routing is rejected because the selected endpoint does not accept it.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// <c>AddHmacServer()</c> was not called, or no <see cref="IHmacSecretProvider"/> is registered.
    /// </exception>
    public static IApplicationBuilder UseHmacAuthentication(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        IServiceProvider services = app.ApplicationServices;
        if (services.GetService<HmacServerMarkerService>() is null)
        {
            throw new InvalidOperationException(
                "Unable to find the required HMAC services. Call 'services.AddHmacServer(...)' in the application startup code.");
        }

        IServiceProviderIsService? serviceInspector = services.GetService<IServiceProviderIsService>();
        if (serviceInspector is not null && !serviceInspector.IsService(typeof(IHmacSecretProvider)))
        {
            throw new InvalidOperationException(
                $"No {nameof(IHmacSecretProvider)} is registered. Call 'AddHmacServer().AddSecretProvider<TProvider>()', " +
                "'AddHmacServer().AddSecretsFromConfiguration(section)' or 'AddHmacServer().AddInMemorySecrets(...)', " +
                $"or add a '{HmacServerServiceCollectionExtensions.ClientsConfigurationKey}' child to the section passed to 'AddHmacServer(IConfiguration)'.");
        }

        IOptionsMonitor<HmacServerOptions> options = services.GetRequiredService<IOptionsMonitor<HmacServerOptions>>();
        app.Properties.TryGetValue(EndpointRouteBuilderKey, out object? routeBuilderAtRegistration);

        return app.Use(next =>
        {
            // Runs when the pipeline is built, after every Use* call.
            app.Properties.TryGetValue(EndpointRouteBuilderKey, out object? routeBuilderAtBuild);

            // UseRouting() registered after this middleware writes a (new) route builder: the endpoint is selected later.
            bool routingRegisteredAfter = routeBuilderAtBuild is not null && !ReferenceEquals(routeBuilderAtBuild, routeBuilderAtRegistration);

            // WebApplication adds routing in front of the whole pipeline only when endpoints are mapped on it directly.
            bool implicitRoutingInFront = routeBuilderAtBuild is null
                && app.Properties.TryGetValue(GlobalEndpointRouteBuilderKey, out object? globalRouteBuilder)
                && globalRouteBuilder is IEndpointRouteBuilder { DataSources.Count: > 0 };

            ILogger<HmacAuthenticationMiddleware>? logger = services.GetService<ILoggerFactory>()?.CreateLogger<HmacAuthenticationMiddleware>();
            if (routingRegisteredAfter && logger is not null)
            {
                HmacAuthenticationMiddleware.Log.RoutingRegisteredAfterMiddleware(logger);
            }

            HmacAuthenticationMiddleware.RoutingOrder routingOrder =
                routingRegisteredAfter ? HmacAuthenticationMiddleware.RoutingOrder.After
                : routeBuilderAtRegistration is not null || implicitRoutingInFront ? HmacAuthenticationMiddleware.RoutingOrder.Before
                : HmacAuthenticationMiddleware.RoutingOrder.Unknown;

            var middleware = new HmacAuthenticationMiddleware(next, options, routingOrder, logger);
            return context => middleware.InvokeAsync(context, context.RequestServices.GetRequiredService<IHmacRequestValidator>());
        });
    }
}
