using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// The clients a <see cref="AllowListRequestValidator"/> blocks, and how often it was consulted.
/// </summary>
public sealed class ClientBlockList
{
    private readonly HashSet<string> _blocked = new(StringComparer.Ordinal);
    private int _calls;
    private int _rejectedSuccesses;

    public ClientBlockList(params string[] blocked)
    {
        foreach (string clientId in blocked)
        {
            _blocked.Add(clientId);
        }
    }

    public int Calls => Volatile.Read(ref _calls);

    public int RejectedSuccesses => Volatile.Read(ref _rejectedSuccesses);

    internal bool IsBlocked(string clientId) => _blocked.Contains(clientId);

    internal void RecordCall() => Interlocked.Increment(ref _calls);

    internal void RecordRejectedSuccess() => Interlocked.Increment(ref _rejectedSuccesses);
}

/// <summary>
/// A decorating <see cref="IHmacRequestValidator"/> that turns some successes of the inner validator into failures,
/// like an IP allow-list or a per-client kill switch applied on top of the signature check.
/// </summary>
internal sealed class AllowListRequestValidator(IHmacRequestValidator inner, ClientBlockList blockList) : IHmacRequestValidator
{
    public async ValueTask<HmacValidationResult> ValidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        blockList.RecordCall();
        HmacValidationResult result = await inner.ValidateAsync(context, cancellationToken);
        if (result.Succeeded && blockList.IsBlocked(result.ClientId))
        {
            blockList.RecordRejectedSuccess();
            return HmacValidationResult.Fail(HmacValidationFailure.UnknownClient, result.ClientId);
        }

        return result;
    }
}
