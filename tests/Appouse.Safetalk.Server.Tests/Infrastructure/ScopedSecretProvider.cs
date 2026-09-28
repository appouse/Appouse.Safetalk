namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A secret provider meant to be registered through DI (for example with a scoped lifetime, like a
/// <c>DbContext</c> backed provider). Each instance registers itself with the <see cref="InstanceTracker"/>.
/// </summary>
public sealed class ScopedSecretProvider : IHmacSecretProvider
{
    public ScopedSecretProvider(InstanceTracker tracker)
    {
        ArgumentNullException.ThrowIfNull(tracker);
        tracker.Register(this);
    }

    public ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(TestCredentials.Secrets.GetValueOrDefault(clientId));
}
