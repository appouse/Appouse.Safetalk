using System.Collections.Frozen;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Appouse.Safetalk.Server;

/// <summary>
/// An <see cref="IHmacSecretProvider"/> that reads client secrets from a configuration section and follows its reloads
/// (for example Azure Key Vault or AWS Secrets Manager configuration providers).
/// </summary>
/// <remarks>
/// <para>Each child of the section is a client; its value is the secret, or an object with a <c>Secret</c> key:</para>
/// <code>
/// "Clients": {
///   "partner-a": "secret-a",
///   "partner-b": { "Secret": "secret-b" }
/// }
/// </code>
/// <para>
/// Use one form per client in <em>every</em> configuration source. A client configured as a string in one source and
/// as an object in another is ambiguous (the merged configuration cannot tell which secret has priority), so it is
/// ignored and logged as an error: requests from it are rejected as unknown.
/// </para>
/// <para>
/// Client identifiers are matched ordinally (case-sensitive) against the spelling surfaced by configuration. Keys are
/// merged case-insensitively across sources and the last source's spelling wins, so spell a client identifier
/// identically in every source (environment variables included).
/// </para>
/// <para>
/// Lookups are served from an immutable snapshot rebuilt on every reload. Register the provider as a container-owned
/// singleton (<c>AddSecretsFromConfiguration</c>); once disposed it throws instead of serving stale secrets.
/// </para>
/// </remarks>
public sealed partial class ConfigurationHmacSecretProvider : IHmacSecretProvider, IDisposable
{
    private const string SecretKey = "Secret";

    private readonly IConfiguration _clients;
    private readonly ILogger? _logger;
    private readonly IDisposable _reloadRegistration;
    private volatile FrozenDictionary<string, string> _secrets;
    private volatile bool _disposed;

    /// <summary>
    /// Initializes a new provider.
    /// </summary>
    /// <param name="clients">The configuration section whose children are the clients.</param>
    public ConfigurationHmacSecretProvider(IConfiguration clients)
        : this(clients, logger: null)
    {
    }

    /// <summary>
    /// Initializes a new provider that reports ambiguous client entries to <paramref name="logger"/>.
    /// </summary>
    /// <param name="clients">The configuration section whose children are the clients.</param>
    /// <param name="logger">The logger, or <see langword="null"/>.</param>
    public ConfigurationHmacSecretProvider(IConfiguration clients, ILogger<ConfigurationHmacSecretProvider>? logger)
    {
        ArgumentNullException.ThrowIfNull(clients);

        _clients = clients;
        _logger = logger;
        _secrets = Load();
        _reloadRegistration = ChangeToken.OnChange(clients.GetReloadToken, () => _secrets = Load());
    }

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">The provider has been disposed.</exception>
    public ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        return ValueTask.FromResult(_secrets.GetValueOrDefault(clientId));
    }

    /// <summary>
    /// Stops listening for configuration reloads. Later lookups throw <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        _disposed = true;
        _reloadRegistration.Dispose();
    }

    private FrozenDictionary<string, string> Load()
    {
        Dictionary<string, string> secrets = new(StringComparer.Ordinal);
        foreach (IConfigurationSection client in _clients.GetChildren())
        {
            if (client.Value is not null && client.GetChildren().Any())
            {
                if (_logger is not null)
                {
                    Log.AmbiguousClient(_logger, client.Key, client.Path);
                }

                continue; // Fail closed: never guess which of two secrets has priority.
            }

            string? secret = client.Value ?? client[SecretKey];
            if (!string.IsNullOrEmpty(secret))
            {
                secrets[client.Key] = secret;
            }
        }

        return secrets.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static partial class Log
    {
        [LoggerMessage(
            EventId = 20,
            Level = LogLevel.Error,
            Message = "Client '{ClientId}' at '{Path}' is configured both as a string and as an object with a Secret key; it is ignored until one form is removed.")]
        public static partial void AmbiguousClient(ILogger logger, string clientId, string path);
    }
}
