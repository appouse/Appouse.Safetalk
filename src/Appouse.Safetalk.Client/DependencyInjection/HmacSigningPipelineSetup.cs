using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Client;

/// <summary>
/// Immutable marker registered for every client that has a signing registration of its own.
/// <c>ConfigureHttpClientDefaults</c> registrations skip those clients, so a client's own registration always wins,
/// whatever the registration order. Markers are resolved from the provider being used, so providers built from the
/// same collection at different times each see exactly their own registrations.
/// </summary>
internal sealed class HmacSigningClientRegistration(string clientName)
{
    public string ClientName { get; } = clientName;
}

/// <summary>
/// Applies one signing registration to the clients it covers when their <see cref="HttpClientFactoryOptions"/> are
/// built, i.e. after every registration has been made. Running as a post-configuration places the signing-state
/// handler outermost and the signing handler innermost, around every handler added with <c>AddHttpMessageHandler</c>
/// (including resilience handlers).
/// </summary>
internal sealed class HmacSigningPipelineSetup(
    string? clientName,
    string optionsName,
    IServiceProvider services) : IPostConfigureOptions<HttpClientFactoryOptions>
{
    private HashSet<string>? _clientsWithOwnRegistration;

    public void PostConfigure(string? name, HttpClientFactoryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        string currentClient = name ?? Options.DefaultName;
        bool applies = clientName is null
            ? !GetClientsWithOwnRegistration().Contains(currentClient) // Defaults: only clients without their own registration.
            : string.Equals(clientName, currentClient, StringComparison.Ordinal);
        if (!applies)
        {
            return;
        }

        IOptionsMonitor<HmacClientOptions> clientOptions = services.GetRequiredService<IOptionsMonitor<HmacClientOptions>>();
        options.HttpClientActions.Add(httpClient =>
        {
            // A base address configured explicitly on the HttpClient (ConfigureHttpClient) takes precedence.
            if (httpClient.BaseAddress is null && clientOptions.Get(optionsName).BaseAddress is { } baseAddress)
            {
                httpClient.BaseAddress = baseAddress;
            }
        });

        bool isDefaultsRegistration = clientName is null;
        options.HttpMessageHandlerBuilderActions.Add(handlerBuilder => AttachSigningHandlers(handlerBuilder, optionsName, isDefaultsRegistration));
    }

    private HashSet<string> GetClientsWithOwnRegistration()
        => _clientsWithOwnRegistration ??= services.GetServices<HmacSigningClientRegistration>()
            .Select(registration => registration.ClientName)
            .ToHashSet(StringComparer.Ordinal);

    private static void AttachSigningHandlers(HttpMessageHandlerBuilder handlerBuilder, string optionsName, bool isDefaultsRegistration)
    {
        IList<DelegatingHandler> handlers = handlerBuilder.AdditionalHandlers;

        // A signer the application added itself (AddHttpMessageHandler(() => new HmacSigningHandler(...))) is the
        // client's own choice: the defaults never replace it.
        if (isDefaultsRegistration && handlers.Any(handler => handler is HmacSigningHandler { IsManagedByFactory: false }))
        {
            return;
        }

        // One signer per pipeline: a repeated registration of the same client replaces the handlers created earlier by
        // this integration (never handlers the application added itself).
        for (int i = handlers.Count - 1; i >= 0; i--)
        {
            if (handlers[i] is HmacSigningHandler { IsManagedByFactory: true } or HmacSigningStateHandler)
            {
                handlers[i].Dispose();
                handlers.RemoveAt(i);
            }
        }

        handlers.Insert(0, new HmacSigningStateHandler());
        handlers.Add(new HmacSigningHandler(
            handlerBuilder.Services.GetRequiredService<IOptionsMonitor<HmacClientOptions>>(),
            optionsName,
            handlerBuilder.Services.GetRequiredService<IHmacSignatureService>(),
            handlerBuilder.Services.GetRequiredService<TimeProvider>(),
            handlerBuilder.Services.GetRequiredService<ILogger<HmacSigningHandler>>()));
    }
}
