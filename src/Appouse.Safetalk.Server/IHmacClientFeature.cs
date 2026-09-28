namespace Appouse.Safetalk.Server;

/// <summary>
/// HTTP feature exposing the client whose HMAC signature was verified for the current request. It is set only by
/// <see cref="HmacAuthenticationMiddleware"/> and the <c>AddHmac()</c> authentication scheme, after the registered
/// <see cref="IHmacRequestValidator"/> succeeded; code that calls the validator directly uses the returned
/// <see cref="HmacValidationResult"/>.
/// </summary>
public interface IHmacClientFeature
{
    /// <summary>
    /// Gets the authenticated client identifier.
    /// </summary>
    string ClientId { get; }
}

/// <summary>
/// Default <see cref="IHmacClientFeature"/> implementation.
/// </summary>
internal sealed class HmacClientFeature(string clientId) : IHmacClientFeature
{
    public string ClientId { get; } = clientId;
}
