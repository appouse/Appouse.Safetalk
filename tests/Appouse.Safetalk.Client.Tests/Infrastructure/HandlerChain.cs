using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Inspects the handler pipeline that <c>IHttpClientFactory</c> really builds for a client, by following
/// <see cref="DelegatingHandler.InnerHandler"/> from the handler returned by <see cref="IHttpMessageHandlerFactory"/>.
/// </summary>
internal static class HandlerChain
{
    /// <summary>
    /// Returns every handler of the named client's pipeline, outermost first, down to (and including) the first handler
    /// that is not a <see cref="DelegatingHandler"/> or that is <paramref name="primary"/>.
    /// </summary>
    public static IReadOnlyList<HttpMessageHandler> Walk(IServiceProvider provider, string name, HttpMessageHandler? primary = null)
    {
        var handlers = new List<HttpMessageHandler>();
        HttpMessageHandler? current = provider.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(name);
        while (current is not null)
        {
            handlers.Add(current);
            if (ReferenceEquals(current, primary))
            {
                break;
            }

            current = (current as DelegatingHandler)?.InnerHandler;
        }

        return handlers;
    }

    /// <summary>
    /// Returns the delegating handlers the registrations contributed (the factory's own lifetime tracking and logging
    /// handlers, and the primary handler, excluded), outermost first.
    /// </summary>
    public static IReadOnlyList<DelegatingHandler> ContributedHandlers(IServiceProvider provider, string name, HttpMessageHandler primary)
        => [.. Walk(provider, name, primary)
            .Where(handler => !ReferenceEquals(handler, primary) && !IsFactoryInfrastructure(handler))
            .Cast<DelegatingHandler>()];

    private static bool IsFactoryInfrastructure(HttpMessageHandler handler)
    {
        Type type = handler.GetType();
        return type.Name == "LifetimeTrackingHttpMessageHandler"
            || string.Equals(type.Namespace, "Microsoft.Extensions.Http.Logging", StringComparison.Ordinal);
    }
}

/// <summary>
/// Records, for every pipeline the factory builds, the exact content of
/// <see cref="HttpMessageHandlerBuilder.AdditionalHandlers"/> once every registration action has run. Register it after
/// the clients so that it runs inside the factory's default logging filter.
/// </summary>
internal sealed class AdditionalHandlersRecorder : IHttpMessageHandlerBuilderFilter
{
    private readonly object _gate = new();
    private readonly Dictionary<string, List<DelegatingHandler>> _handlers = new(StringComparer.Ordinal);

    public IReadOnlyList<DelegatingHandler> For(string name)
    {
        lock (_gate)
        {
            Assert.True(_handlers.TryGetValue(name, out List<DelegatingHandler>? handlers), $"No pipeline was built for '{name}'.");
            return [.. handlers];
        }
    }

    public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next) => builder =>
    {
        next(builder);
        lock (_gate)
        {
            _handlers[builder.Name ?? string.Empty] = [.. builder.AdditionalHandlers];
        }
    };
}
