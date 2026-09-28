namespace Appouse.Safetalk.Core.Tests.Infrastructure;

/// <summary>
/// A fake <see cref="IHmacSignatureService"/> that records exactly what it receives.
/// </summary>
internal sealed class RecordingSignatureService : IHmacSignatureService
{
    public string SignatureToReturn { get; init; } = "recorded-signature";

    public bool VerificationResult { get; init; } = true;

    public int CallCount { get; private set; }

    public string? LastSecret { get; private set; }

    public byte[]? LastCanonicalRequest { get; private set; }

    public string? LastSignature { get; private set; }

    public string ComputeSignature(string secret, ReadOnlySpan<byte> canonicalRequest)
    {
        CallCount++;
        LastSecret = secret;
        LastCanonicalRequest = canonicalRequest.ToArray();
        return SignatureToReturn;
    }

    public bool VerifySignature(string secret, ReadOnlySpan<byte> canonicalRequest, ReadOnlySpan<char> signature)
    {
        CallCount++;
        LastSecret = secret;
        LastCanonicalRequest = canonicalRequest.ToArray();
        LastSignature = signature.ToString();
        return VerificationResult;
    }
}
