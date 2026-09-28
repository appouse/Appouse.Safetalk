namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Customizations applied to the signing client built by <see cref="TestClientFactory"/>.
/// </summary>
internal sealed class ClientSetup
{
    public string ClientId { get; init; } = TestCredentials.ClientId;

    public string Secret { get; init; } = TestCredentials.Secret;

    /// <summary>The client clock (for example a <c>FakeTimeProvider</c>).</summary>
    public TimeProvider? TimeProvider { get; init; }

    /// <summary>
    /// A handler added with <c>AddHttpMessageHandler</c> after <c>AddHmacClient</c>. The signing handler is always the
    /// innermost delegating handler, so this one sees the request before it is signed (retry, hedging, enrichment).
    /// </summary>
    public Func<DelegatingHandler>? HandlerBeforeSigning { get; init; }

    /// <summary>
    /// A handler wrapping the primary handler, i.e. between the signing handler and the network. It sees the signed
    /// request (capture, proxy rewriting, man-in-the-middle tampering).
    /// </summary>
    public Func<DelegatingHandler>? HandlerAfterSigning { get; init; }

    /// <summary>The HTTP version requested by default, with an exact version policy.</summary>
    public Version? RequestVersion { get; init; }
}
