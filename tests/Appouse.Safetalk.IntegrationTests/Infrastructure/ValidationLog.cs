using System.Collections.Concurrent;
using Appouse.Safetalk.Server;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Records every <see cref="HmacValidationResult"/> produced by the server, so tests can assert the exact
/// rejection reason that the HTTP response deliberately does not disclose.
/// </summary>
internal sealed class ValidationLog
{
    private readonly ConcurrentQueue<HmacValidationResult> _results = new();

    public IReadOnlyCollection<HmacValidationResult> Results => _results;

    public HmacValidationResult Last => _results.Last();

    public void Add(HmacValidationResult result) => _results.Enqueue(result);
}
