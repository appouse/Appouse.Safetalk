using Microsoft.AspNetCore.Mvc;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A controller with one action exempted from HMAC validation through <see cref="SkipHmacValidationAttribute"/>.
/// </summary>
[ApiController]
[Route("mvc/probe")]
public sealed class ProbeController : ControllerBase
{
    [HttpGet("public")]
    [SkipHmacValidation]
    public ActionResult<string> Public() => HttpContext.GetHmacClientId() ?? "anonymous";

    [HttpGet("protected")]
    public ActionResult<string> Protected() => HttpContext.GetHmacClientId() ?? "anonymous";
}
