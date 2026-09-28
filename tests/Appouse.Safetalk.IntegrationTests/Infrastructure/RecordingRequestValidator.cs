using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// A transparent decorator over the real <see cref="HmacRequestValidator"/> that records its results. Every call is
/// recorded, including calls answered from the result the validator remembers for the request.
/// </summary>
internal sealed class RecordingRequestValidator(IHmacRequestValidator inner, ValidationLog log) : IHmacRequestValidator
{
    public async ValueTask<HmacValidationResult> ValidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        HmacValidationResult result = await inner.ValidateAsync(context, cancellationToken);
        log.Add(result);
        return result;
    }
}
