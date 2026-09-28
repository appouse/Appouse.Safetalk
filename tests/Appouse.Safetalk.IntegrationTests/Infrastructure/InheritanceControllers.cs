using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Mvc;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// A base controller exempt at class level and on a virtual action. <see cref="SkipHmacValidationAttribute"/> is not
/// inherited (round 4), so neither exemption reaches derived controllers or overrides.
/// </summary>
[SkipHmacValidation]
public abstract class SkippedPartnerControllerBase : ControllerBase
{
    [HttpGet("overridden")]
    [SkipHmacValidation]
    public virtual ActionResult<string> Overridden() => Ok("base:" + (HttpContext.GetHmacClientId() ?? "anonymous"));

    /// <summary>Not overridden: the action is this very method, so its own attribute applies.</summary>
    [HttpGet("base-action")]
    [SkipHmacValidation]
    public ActionResult<string> BaseAction() => Ok(HttpContext.GetHmacClientId() ?? "anonymous");
}

/// <summary>Derives from a skipped base without declaring any HMAC attribute itself.</summary>
[ApiController]
[Route("api/inheritance/skipped-base")]
public sealed class DerivedFromSkippedController : SkippedPartnerControllerBase
{
    [HttpGet("own")]
    public ActionResult<string> Own() => Ok(HttpContext.GetHmacClientId() ?? "anonymous");

    public override ActionResult<string> Overridden() => Ok("derived:" + (HttpContext.GetHmacClientId() ?? "anonymous"));
}

/// <summary>
/// A base controller that requires a signature. <see cref="RequireHmacValidationAttribute"/> stays inherited.
/// </summary>
[RequireHmacValidation]
public abstract class RequiredPartnerControllerBase : ControllerBase
{
}

/// <summary>Derives from a required base; one action opts out explicitly.</summary>
[ApiController]
[Route("api/inheritance/required-base")]
public sealed class DerivedFromRequiredController : RequiredPartnerControllerBase
{
    [HttpGet("orders")]
    public ActionResult<string> Orders() => Ok(HttpContext.GetHmacClientId() ?? "anonymous");

    [HttpGet("public")]
    [SkipHmacValidation]
    public ActionResult<string> Public() => Ok(HttpContext.GetHmacClientId() ?? "anonymous");
}
