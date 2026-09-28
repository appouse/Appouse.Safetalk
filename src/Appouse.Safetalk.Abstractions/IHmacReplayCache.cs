namespace Appouse.Safetalk;

/// <summary>
/// Remembers the signatures of accepted requests so that a captured request cannot be replayed while its timestamp
/// is still inside the allowed clock skew window.
/// </summary>
/// <remarks>
/// <para>
/// Entries are keyed on the verified signature alone. The signature is an HMAC bound to the client's secret, whereas
/// the <c>X-Client-Id</c> header is not signed: including it in the key would let an attacker replay a request under
/// a different spelling of the same client id.
/// </para>
/// <para>
/// The default <c>InMemoryHmacReplayCache</c> (Appouse.Safetalk.Server) protects a single instance. When the API runs
/// on several instances, implement this interface over a shared store with an atomic "add if absent" operation, for
/// example Redis <c>SET key value NX PX ttl</c>.
/// </para>
/// </remarks>
public interface IHmacReplayCache
{
    /// <summary>
    /// Atomically records a signature if it has not been seen before.
    /// </summary>
    /// <param name="signature">The verified, normalized (lower-case hexadecimal) request signature.</param>
    /// <param name="expiresAt">
    /// The moment after which the entry is no longer needed because the request timestamp would be rejected anyway.
    /// It always lies in the future when the validator calls this method.
    /// </param>
    /// <param name="cancellationToken">A token that is cancelled when the request is aborted.</param>
    /// <returns>
    /// <see langword="true"/> when the signature was recorded for the first time;
    /// <see langword="false"/> when it was already present (the request is a replay) or <paramref name="expiresAt"/>
    /// has already passed. Implementations must fail closed.
    /// </returns>
    ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
