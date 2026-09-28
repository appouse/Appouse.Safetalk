namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// An <see cref="IHmacSecretProvider"/> that records its calls, used to prove the order of the validation steps and
/// how many times secrets are looked up. Thread-safe, so it can be shared by the requests of a test application.
/// </summary>
internal sealed class RecordingSecretProvider(Func<string, string?> lookup) : IHmacSecretProvider
{
    private readonly List<string> _requestedClientIds = [];
    private readonly object _gate = new();

    public IReadOnlyList<string> RequestedClientIds
    {
        get
        {
            lock (_gate)
            {
                return [.. _requestedClientIds];
            }
        }
    }

    public CancellationToken LastCancellationToken { get; private set; }

    public static RecordingSecretProvider ForTestCredentials() =>
        new(clientId => TestCredentials.Secrets.GetValueOrDefault(clientId));

    public ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _requestedClientIds.Add(clientId);
            LastCancellationToken = cancellationToken;
        }

        return ValueTask.FromResult(lookup(clientId));
    }
}
