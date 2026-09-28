using Appouse.Safetalk;
using Appouse.Safetalk.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Adds HMAC request signing to any named or typed <see cref="HttpClient"/>.
/// </summary>
public static class HmacHttpClientBuilderExtensions
{
    /// <summary>
    /// The options name used by <c>ConfigureHttpClientDefaults(b => b.AddHmacSigning(...))</c>. It cannot collide with
    /// a client name, including the empty name of the factory's default client.
    /// </summary>
    internal const string DefaultsOptionsName = "Appouse.Safetalk.HttpClientDefaults";

    /// <summary>
    /// Adds <see cref="HmacSigningHandler"/> to the client's handler pipeline and registers its named options.
    /// </summary>
    /// <param name="builder">The HTTP client builder.</param>
    /// <param name="configureOptions">Configures the client credentials (evaluated once).</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    /// <remarks>
    /// <para>
    /// The signing handler is always the innermost delegating handler (closest to the network), whatever the order in
    /// which other handlers are added. Retry and hedging handlers added to the same client (<c>AddStandardResilienceHandler()</c>,
    /// <c>AddStandardHedgingHandler()</c>, <c>AddHttpMessageHandler</c>, ...) therefore get every attempt signed with a
    /// strictly increasing timestamp, and handlers that modify the request run before it is signed.
    /// </para>
    /// <para>
    /// <c>ConfigureHttpClientDefaults(b => b.AddHmacSigning(...))</c> signs every <c>IHttpClientFactory</c> client that
    /// has no signing registration of its own (including calls to third-party services); a client's own registration
    /// always wins, whatever the registration order, and the defaults' <see cref="HmacClientOptions.BaseAddress"/> never
    /// applies to it. A <see cref="HmacSigningHandler"/> the application added itself is never replaced by the defaults.
    /// Registering the same client again replaces its signing handler, but options registrations are cumulative: a later
    /// registration overrides only the values it sets.
    /// </para>
    /// <para>
    /// Options are validated at application start-up (<c>ValidateOnStart</c>). Use the <see cref="IConfiguration"/>
    /// overload for credentials that must be rotated without a restart.
    /// </para>
    /// </remarks>
    public static IHttpClientBuilder AddHmacSigning(this IHttpClientBuilder builder, Action<HmacClientOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configureOptions);

        // ConfigureHttpClientDefaults builders have no name.
        string? clientName = builder.Name;
        string optionsName = GetOptionsName(builder);
        IServiceCollection services = builder.Services;

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IHmacSignatureService>(HmacSha256SignatureService.Instance);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<HmacClientOptions>>(HmacClientOptionsValidator.Instance));
        services.AddOptions<HmacClientOptions>(optionsName)
            .Configure(configureOptions)
            .ValidateOnStart();

        if (clientName is not null)
        {
            services.AddSingleton(new HmacSigningClientRegistration(clientName));
        }

        services.AddSingleton<IPostConfigureOptions<HttpClientFactoryOptions>>(serviceProvider =>
            new HmacSigningPipelineSetup(clientName, optionsName, serviceProvider));

        return builder;
    }

    /// <summary>
    /// Adds <see cref="HmacSigningHandler"/> to the client's handler pipeline with credentials bound from configuration.
    /// Reloads of the section (for example a rotated secret) are applied to the next request.
    /// </summary>
    /// <param name="builder">The HTTP client builder.</param>
    /// <param name="configuration">
    /// The section holding <c>ClientId</c>, <c>Secret</c> and, optionally, <c>BaseAddress</c>.
    /// </param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static IHttpClientBuilder AddHmacSigning(this IHttpClientBuilder builder, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        builder.Services.AddSingleton<IOptionsChangeTokenSource<HmacClientOptions>>(
            new ConfigurationChangeTokenSource<HmacClientOptions>(GetOptionsName(builder), configuration));

        return builder.AddHmacSigning(options => HmacClientOptionsBinder.Bind(configuration, options));
    }

    private static string GetOptionsName(IHttpClientBuilder builder) => builder.Name ?? DefaultsOptionsName;
}
