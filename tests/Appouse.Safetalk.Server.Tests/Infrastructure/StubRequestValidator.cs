using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// An <see cref="IHmacRequestValidator"/> that returns a fixed result, used to test the middleware in isolation.
/// </summary>
internal sealed class StubRequestValidator(HmacValidationResult result) : IHmacRequestValidator
{
    public int CallCount { get; private set; }

    public CancellationToken LastCancellationToken { get; private set; }

    public ValueTask<HmacValidationResult> ValidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        CallCount++;
        LastCancellationToken = cancellationToken;
        return ValueTask.FromResult(result);
    }
}
