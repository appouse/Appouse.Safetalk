using Microsoft.AspNetCore.Mvc;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A base controller exempted from HMAC validation, with an exempted virtual action. Neither exemption may reach
/// derived controllers or overrides: <see cref="SkipHmacValidationAttribute"/> is not inherited.
/// </summary>
[SkipHmacValidation]
public abstract class SkippedBaseController : ControllerBase
{
    [SkipHmacValidation]
    public virtual ActionResult<string> Status() => "base";

    /// <summary>
    /// A non-virtual action declared (and exempted) on the base class itself: every derived controller exposes this very
    /// method, so its own attribute applies.
    /// </summary>
    [HttpGet("declared-on-base")]
    [SkipHmacValidation]
    public ActionResult<string> DeclaredOnBase() => HttpContext.GetHmacClientId() ?? "anonymous";
}

[ApiController]
[Route("mvc/inheritance/from-skipped")]
public sealed class DerivedFromSkippedBaseController : SkippedBaseController
{
    [HttpGet]
    public ActionResult<string> Get() => HttpContext.GetHmacClientId() ?? "anonymous";

    [HttpGet("status")]
    public override ActionResult<string> Status() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// Derives from an exempted base but opts back in explicitly: it is protected in every mode.
/// </summary>
[ApiController]
[Route("mvc/inheritance/from-skipped-required")]
[RequireHmacValidation]
public sealed class RequiredDerivedFromSkippedBaseController : SkippedBaseController
{
    [HttpGet]
    public ActionResult<string> Get() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// Derives from an exempted base and declares the exemption itself: the exemption applies.
/// </summary>
[ApiController]
[Route("mvc/inheritance/from-skipped-own-skip")]
[SkipHmacValidation]
public sealed class SkippedDerivedFromSkippedBaseController : SkippedBaseController
{
    [HttpGet]
    public ActionResult<string> Get() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// A base controller (not exempted) whose virtual action is exempted: an override does not inherit the exemption.
/// </summary>
public abstract class SkippedVirtualActionBaseController : ControllerBase
{
    [SkipHmacValidation]
    public virtual ActionResult<string> Ping() => "base";
}

[ApiController]
[Route("mvc/inheritance/skipped-virtual")]
public sealed class OverridesSkippedVirtualActionController : SkippedVirtualActionBaseController
{
    [HttpGet("ping")]
    public override ActionResult<string> Ping() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// A base controller whose virtual action requires validation: overrides inherit the requirement.
/// </summary>
public abstract class RequiredVirtualActionBaseController : ControllerBase
{
    [RequireHmacValidation]
    public virtual ActionResult<string> Orders() => "base";
}

[ApiController]
[Route("mvc/inheritance/required-virtual")]
public sealed class OverridesRequiredVirtualActionController : RequiredVirtualActionBaseController
{
    [HttpGet("orders")]
    public override ActionResult<string> Orders() => HttpContext.GetHmacClientId() ?? "anonymous";

    [HttpGet("other")]
    public ActionResult<string> Other() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// Declares the exemption on the override itself, as the documentation instructs, below a base method that requires it.
/// </summary>
[ApiController]
[Route("mvc/inheritance/required-virtual-own-skip")]
public sealed class OwnSkipOnOverrideOfRequiredVirtualActionController : RequiredVirtualActionBaseController
{
    [HttpGet("orders")]
    [SkipHmacValidation]
    public override ActionResult<string> Orders() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// A base controller requiring validation at class level (inherited by derived controllers).
/// </summary>
[RequireHmacValidation]
public abstract class RequiredBaseController : ControllerBase
{
}

/// <summary>
/// Declares the exemption on the controller itself, as the documentation instructs, below a base that requires it.
/// </summary>
[ApiController]
[Route("mvc/inheritance/own-skip-below-required-base")]
[SkipHmacValidation]
public sealed class OwnSkipBelowRequiredBaseController : RequiredBaseController
{
    [HttpGet]
    public ActionResult<string> Get() => HttpContext.GetHmacClientId() ?? "anonymous";
}
