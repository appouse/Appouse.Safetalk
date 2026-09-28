namespace Appouse.Safetalk.Server;

/// <summary>
/// Remembers the outcome of <see cref="HmacRequestValidator"/> for the current request, so that the middleware, the
/// authentication handler, custom callers and pipeline re-execution all share a single validation.
/// </summary>
/// <remarks>Internal on purpose: only this library can record a validation result.</remarks>
internal sealed class HmacValidationResultFeature(HmacValidationResult result)
{
    public HmacValidationResult Result { get; } = result;
}
