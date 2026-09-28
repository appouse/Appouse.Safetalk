namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A JSON payload bound by an endpoint after the middleware has buffered and verified the body.
/// </summary>
public sealed record OrderRequest(int OrderId, int Quantity);
