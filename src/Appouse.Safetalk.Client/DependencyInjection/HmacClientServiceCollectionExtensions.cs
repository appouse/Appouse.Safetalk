using System.Diagnostics.CodeAnalysis;
using Appouse.Safetalk.Client;
using Microsoft.Extensions.Configuration;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers <see cref="HttpClient"/>s (through <c>IHttpClientFactory</c>) whose requests are signed with HMAC-SHA256.
/// </summary>
/// <remarks>
/// Every overload returns the <see cref="IHttpClientBuilder"/>, so further configuration (base address, timeouts,
/// <c>AddStandardResilienceHandler()</c>, ...) can be chained. The signing handler always stays closest to the
/// network, so retries are re-signed.
/// </remarks>
public static class HmacClientServiceCollectionExtensions
{
    /// <summary>
    /// Registers <typeparamref name="TClient"/> as a typed <see cref="HttpClient"/> whose requests are signed by
    /// <see cref="HmacSigningHandler"/>.
    /// </summary>
    /// <typeparam name="TClient">The typed client.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Configures the client credentials (evaluated once).</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> for further configuration.</returns>
    /// <example>
    /// <code>
    /// services.AddHmacClient&lt;OrdersApiClient&gt;(options =>
    /// {
    ///     options.ClientId = "partner-a";
    ///     options.Secret = configuration["Safetalk:Secret"]!;
    ///     options.BaseAddress = new Uri("https://api.example.com/");
    /// });
    /// </code>
    /// </example>
    public static IHttpClientBuilder AddHmacClient<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(
        this IServiceCollection services,
        Action<HmacClientOptions> configureOptions)
        where TClient : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        return services.AddHttpClient<TClient>().AddHmacSigning(configureOptions);
    }

    /// <summary>
    /// Registers <typeparamref name="TClient"/> as a typed <see cref="HttpClient"/> whose credentials and base address
    /// are bound from configuration and follow its reloads (secret rotation without restart).
    /// </summary>
    /// <typeparam name="TClient">The typed client.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The section holding <c>ClientId</c>, <c>Secret</c> and, optionally, <c>BaseAddress</c>.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> for further configuration.</returns>
    /// <example>
    /// <code>
    /// // appsettings.json: "OrdersApi": { "BaseAddress": "https://api.example.com/", "ClientId": "partner-a", "Secret": "..." }
    /// services.AddHmacClient&lt;OrdersApiClient&gt;(configuration.GetSection("OrdersApi"));
    /// </code>
    /// </example>
    public static IHttpClientBuilder AddHmacClient<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(
        this IServiceCollection services,
        IConfiguration configuration)
        where TClient : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        return services.AddHttpClient<TClient>().AddHmacSigning(configuration);
    }

    /// <summary>
    /// Registers <typeparamref name="TClient"/>, implemented by <typeparamref name="TImplementation"/>, as a typed
    /// <see cref="HttpClient"/> whose requests are signed by <see cref="HmacSigningHandler"/>.
    /// </summary>
    /// <typeparam name="TClient">The typed client contract.</typeparam>
    /// <typeparam name="TImplementation">The typed client implementation.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Configures the client credentials (evaluated once).</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> for further configuration.</returns>
    public static IHttpClientBuilder AddHmacClient<TClient, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(
        this IServiceCollection services,
        Action<HmacClientOptions> configureOptions)
        where TClient : class
        where TImplementation : class, TClient
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        return services.AddHttpClient<TClient, TImplementation>().AddHmacSigning(configureOptions);
    }

    /// <summary>
    /// Registers <typeparamref name="TClient"/>, implemented by <typeparamref name="TImplementation"/>, as a typed
    /// <see cref="HttpClient"/> whose credentials and base address are bound from configuration and follow its reloads.
    /// </summary>
    /// <typeparam name="TClient">The typed client contract.</typeparam>
    /// <typeparam name="TImplementation">The typed client implementation.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The section holding <c>ClientId</c>, <c>Secret</c> and, optionally, <c>BaseAddress</c>.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> for further configuration.</returns>
    public static IHttpClientBuilder AddHmacClient<TClient, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TImplementation>(
        this IServiceCollection services,
        IConfiguration configuration)
        where TClient : class
        where TImplementation : class, TClient
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        return services.AddHttpClient<TClient, TImplementation>().AddHmacSigning(configuration);
    }

    /// <summary>
    /// Registers a named <see cref="HttpClient"/> whose requests are signed by <see cref="HmacSigningHandler"/>.
    /// Create it with <c>IHttpClientFactory.CreateClient(name)</c>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The logical name of the client.</param>
    /// <param name="configureOptions">Configures the client credentials (evaluated once).</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> for further configuration.</returns>
    public static IHttpClientBuilder AddHmacClient(this IServiceCollection services, string name, Action<HmacClientOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(configureOptions);

        return services.AddHttpClient(name).AddHmacSigning(configureOptions);
    }

    /// <summary>
    /// Registers a named <see cref="HttpClient"/> whose credentials and base address are bound from configuration and
    /// follow its reloads. Create it with <c>IHttpClientFactory.CreateClient(name)</c>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The logical name of the client.</param>
    /// <param name="configuration">The section holding <c>ClientId</c>, <c>Secret</c> and, optionally, <c>BaseAddress</c>.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> for further configuration.</returns>
    public static IHttpClientBuilder AddHmacClient(this IServiceCollection services, string name, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(configuration);

        return services.AddHttpClient(name).AddHmacSigning(configuration);
    }
}
