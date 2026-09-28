namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// An <see cref="IHmacSignatureService"/> that records the secret and canonical request bytes it is asked to sign
/// and returns a fixed signature.
/// </summary>
internal sealed class RecordingSignatureService(string signature = RecordingSignatureService.DefaultSignature) : IHmacSignatureService
{
    public const string DefaultSignature = "recorded-signature";

    private readonly object _gate = new();
    private readonly List<byte[]> _canonicalRequests = [];
    private readonly List<string> _secrets = [];

    public IReadOnlyList<byte[]> CanonicalRequests
    {
        get
        {
            lock (_gate)
            {
                return [.. _canonicalRequests];
            }
        }
    }

    public IReadOnlyList<string> Secrets
    {
        get
        {
            lock (_gate)
            {
                return [.. _secrets];
            }
        }
    }

    public string ComputeSignature(string secret, ReadOnlySpan<byte> canonicalRequest)
    {
        lock (_gate)
        {
            _secrets.Add(secret);
            _canonicalRequests.Add(canonicalRequest.ToArray());
        }

        return signature;
    }

    public bool VerifySignature(string secret, ReadOnlySpan<byte> canonicalRequest, ReadOnlySpan<char> signature) =>
        throw new NotSupportedException("The client never verifies signatures.");
}
