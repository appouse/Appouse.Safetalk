using System.Collections.Concurrent;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>A scoped stand-in for an EF Core <c>DbContext</c> holding client secrets.</summary>
public sealed class ClientSecretsDbContext
{
    public Guid InstanceId { get; } = Guid.NewGuid();

    public IReadOnlyDictionary<string, string> Secrets { get; } = TestCredentials.All;
}

/// <summary>Records every secret lookup made by <see cref="DatabaseSecretProvider"/>.</summary>
public sealed class SecretLookupLog
{
    private readonly ConcurrentQueue<SecretLookup> _lookups = new();

    public IReadOnlyCollection<SecretLookup> Lookups => _lookups;

    public void Add(SecretLookup lookup) => _lookups.Enqueue(lookup);
}

/// <summary>One secret lookup.</summary>
public sealed record SecretLookup(string ClientId, Guid DbContextInstanceId, bool TokenCanBeCanceled);

/// <summary>
/// A scoped <see cref="IHmacSecretProvider"/> depending on a scoped "DbContext", as recommended by the README.
/// </summary>
public sealed class DatabaseSecretProvider(ClientSecretsDbContext db, SecretLookupLog log) : IHmacSecretProvider
{
    public ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default)
    {
        log.Add(new SecretLookup(clientId, db.InstanceId, cancellationToken.CanBeCanceled));
        return ValueTask.FromResult(db.Secrets.GetValueOrDefault(clientId));
    }
}

/// <summary>A singleton provider whose secrets can be rotated or disabled at run time.</summary>
public sealed class RotatingSecretProvider : IHmacSecretProvider
{
    private readonly ConcurrentDictionary<string, string> _secrets = new(TestCredentials.All, StringComparer.Ordinal);

    /// <summary>Replaces the secret of a client, or disables the client when <paramref name="secret"/> is <see langword="null"/>.</summary>
    public void Set(string clientId, string? secret)
    {
        if (secret is null)
        {
            _secrets.TryRemove(clientId, out _);
        }
        else
        {
            _secrets[clientId] = secret;
        }
    }

    public ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_secrets.GetValueOrDefault(clientId));
}
