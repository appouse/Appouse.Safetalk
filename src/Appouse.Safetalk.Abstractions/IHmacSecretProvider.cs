namespace Appouse.Safetalk;

/// <summary>
/// Resolves the shared secret of a client from its <c>X-Client-Id</c> value.
/// </summary>
/// <remarks>
/// <para>
/// Implement this interface to load secrets from a database, Azure Key Vault, AWS Secrets Manager, etc., and register
/// it with <c>AddHmacServer().AddSecretProvider&lt;TProvider&gt;()</c>. Implementations are registered as scoped by
/// default, so they may depend on scoped services such as an EF Core <c>DbContext</c>.
/// </para>
/// <para>
/// <b>Match client identifiers exactly (ordinal, case-sensitive).</b> The received value becomes the authenticated
/// client identity (claims, <c>IHmacClientFeature</c>, rate-limit partitions). Case-insensitive stores such as SQL
/// Server with its default collation or Key Vault secret names must compare the stored identifier with the received
/// one ordinally before returning the secret.
/// </para>
/// <para>
/// The provider is called for every signed request; cache secrets (for example with <c>HybridCache</c>) when the
/// backing store is remote.
/// </para>
/// </remarks>
public interface IHmacSecretProvider
{
    /// <summary>
    /// Gets the shared secret of a client.
    /// </summary>
    /// <param name="clientId">The client identifier received in the <c>X-Client-Id</c> header.</param>
    /// <param name="cancellationToken">A token that is cancelled when the request is aborted.</param>
    /// <returns>
    /// The secret, or <see langword="null"/> when the client is unknown or disabled; the request is then rejected
    /// with <c>401 Unauthorized</c>.
    /// </returns>
    ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default);
}
