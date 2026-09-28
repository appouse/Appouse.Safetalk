using System.Diagnostics.CodeAnalysis;

namespace Appouse.Safetalk.Server;

/// <summary>
/// The outcome of validating a signed request.
/// </summary>
/// <remarks>
/// The default value represents a failed validation, so an uninitialized result can never grant access.
/// </remarks>
public readonly record struct HmacValidationResult
{
    private HmacValidationResult(bool succeeded, string? clientId, HmacValidationFailure failure)
    {
        Succeeded = succeeded;
        ClientId = clientId;
        Failure = failure;
    }

    /// <summary>
    /// Gets a value indicating whether the request is authentic.
    /// </summary>
    [MemberNotNullWhen(true, nameof(ClientId))]
    public bool Succeeded { get; }

    /// <summary>
    /// Gets the authenticated client identifier, or the claimed one (if any) when validation failed.
    /// </summary>
    public string? ClientId { get; }

    /// <summary>
    /// Gets the reason the request was rejected, or <see cref="HmacValidationFailure.None"/> on success.
    /// </summary>
    public HmacValidationFailure Failure { get; }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    /// <param name="clientId">The authenticated client identifier.</param>
    /// <returns>A successful result.</returns>
    public static HmacValidationResult Success(string clientId)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        return new HmacValidationResult(succeeded: true, clientId, HmacValidationFailure.None);
    }

    /// <summary>
    /// Creates a failed result.
    /// </summary>
    /// <param name="failure">The reason the request was rejected.</param>
    /// <param name="clientId">The claimed client identifier, if known.</param>
    /// <returns>A failed result.</returns>
    public static HmacValidationResult Fail(HmacValidationFailure failure, string? clientId = null)
    {
        if (failure == HmacValidationFailure.None)
        {
            throw new ArgumentOutOfRangeException(nameof(failure), failure, "A failed result requires a failure reason.");
        }

        return new HmacValidationResult(succeeded: false, clientId, failure);
    }
}
