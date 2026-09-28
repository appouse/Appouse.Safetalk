using System.Collections.Frozen;

namespace Appouse.Safetalk.Server;

/// <summary>
/// An <see cref="IHmacSecretProvider"/> backed by an immutable in-memory dictionary.
/// Suitable for tests, samples and deployments with a small, static set of partners.
/// </summary>
/// <remarks>Client identifiers are compared ordinally (case-sensitive).</remarks>
public sealed class InMemoryHmacSecretProvider : IHmacSecretProvider
{
    private readonly FrozenDictionary<string, string> _secrets;

    /// <summary>
    /// Initializes a new provider.
    /// </summary>
    /// <param name="secrets">Pairs of client identifier and shared secret.</param>
    /// <exception cref="ArgumentException">A client identifier or secret is empty, or a client identifier is duplicated.</exception>
    public InMemoryHmacSecretProvider(IEnumerable<KeyValuePair<string, string>> secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);

        Dictionary<string, string> validated = new(StringComparer.Ordinal);
        foreach ((string clientId, string secret) in secrets)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(clientId, nameof(secrets));
            ArgumentException.ThrowIfNullOrEmpty(secret, nameof(secrets));

            if (!validated.TryAdd(clientId, secret))
            {
                throw new ArgumentException($"The client identifier '{clientId}' is registered more than once.", nameof(secrets));
            }
        }

        _secrets = validated.ToFrozenDictionary(StringComparer.Ordinal);
    }

    /// <inheritdoc />
    public ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return ValueTask.FromResult(_secrets.GetValueOrDefault(clientId));
    }
}
