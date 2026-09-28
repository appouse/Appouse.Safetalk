using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A controller that requires HMAC validation at class level, with one action opting out.
/// </summary>
[ApiController]
[Route("mvc/required")]
[RequireHmacValidation]
public sealed class RequiredController : ControllerBase
{
    [HttpGet("default")]
    public ActionResult<string> Default() => HttpContext.GetHmacClientId() ?? "anonymous";

    [HttpGet("skipped")]
    [SkipHmacValidation]
    public ActionResult<string> Skipped() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// A controller exempted from HMAC validation at class level, with one action opting back in.
/// </summary>
[ApiController]
[Route("mvc/skipped")]
[SkipHmacValidation]
public sealed class SkippedController : ControllerBase
{
    [HttpGet("default")]
    public ActionResult<string> Default() => HttpContext.GetHmacClientId() ?? "anonymous";

    [HttpGet("required")]
    [RequireHmacValidation]
    public ActionResult<string> Required() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// A base controller for partner APIs: the attribute is inherited by derived controllers.
/// </summary>
[RequireHmacValidation]
public abstract class PartnerControllerBase : ControllerBase
{
}

[ApiController]
[Route("mvc/inherited")]
public sealed class InheritedPartnerController : PartnerControllerBase
{
    [HttpGet]
    public ActionResult<string> Get() => HttpContext.GetHmacClientId() ?? "anonymous";

    [HttpGet("skipped")]
    [SkipHmacValidation]
    public ActionResult<string> Skipped() => HttpContext.GetHmacClientId() ?? "anonymous";
}

/// <summary>
/// A controller protected by ASP.NET Core authorization, used with the HMAC authentication scheme.
/// </summary>
[ApiController]
[Route("mvc/authorized")]
[Authorize]
public sealed class AuthorizedController : ControllerBase
{
    public const string PartnerBPolicy = "PartnerB";

    [HttpGet]
    public ActionResult<string> Get() => User.Identity?.Name ?? "anonymous";

    [HttpGet("anonymous")]
    [AllowAnonymous]
    public ActionResult<string> Anonymous() => User.Identity?.Name ?? "anonymous";

    [HttpGet("partner-b")]
    [Authorize(Policy = PartnerBPolicy)]
    public ActionResult<string> PartnerB() => User.Identity?.Name ?? "anonymous";
}
