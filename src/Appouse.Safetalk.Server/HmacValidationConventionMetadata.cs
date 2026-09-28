namespace Appouse.Safetalk.Server;

/// <summary>
/// Metadata added by the <c>SkipHmacValidation()</c> / <c>RequireHmacValidation()</c> endpoint conventions.
/// </summary>
/// <remarks>
/// A distinct type lets <see cref="HmacAuthenticationMiddleware"/> give attributes precedence over conventions:
/// ASP.NET Core appends conventions applied to <c>MapControllers()</c> after controller and action attributes, so
/// without this distinction a broad convention would silently override an explicit attribute.
/// </remarks>
internal sealed class HmacValidationConventionMetadata : IHmacValidationMetadata
{
    public static readonly HmacValidationConventionMetadata Skip = new(requiresValidation: false);
    public static readonly HmacValidationConventionMetadata Require = new(requiresValidation: true);

    private HmacValidationConventionMetadata(bool requiresValidation) => RequiresValidation = requiresValidation;

    public bool RequiresValidation { get; }
}
