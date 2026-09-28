namespace Appouse.Safetalk.Server;

/// <summary>
/// Exempts a controller, action or endpoint from HMAC signature validation (for example health checks).
/// </summary>
/// <remarks>
/// Endpoint metadata is only available when <c>UseHmacAuthentication()</c> runs after routing, which is the default
/// for <c>WebApplication</c>. Attributes take precedence over the <c>SkipHmacValidation()</c>/<c>RequireHmacValidation()</c>
/// conventions; an action attribute overrides a controller attribute. For minimal APIs use the
/// <c>SkipHmacValidation()</c> endpoint convention.
/// <para>
/// The attribute is not inherited (fail closed): declared on a base controller or on a base virtual method, it has no
/// effect on derived controllers or overrides. Two consequences: an action declared in a base controller and <em>not
/// overridden</em> keeps its own skip in every derived controller (override the action to remove it), and a class- or
/// override-level skip cannot lift a <see cref="RequireHmacValidationAttribute"/> inherited from a base class; use an
/// action-level skip for that.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
public sealed class SkipHmacValidationAttribute : Attribute, IHmacValidationMetadata
{
    /// <inheritdoc />
    public bool RequiresValidation => false;
}
