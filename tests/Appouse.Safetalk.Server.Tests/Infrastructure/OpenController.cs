using Microsoft.AspNetCore.Mvc;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// A controller exempted from HMAC validation at class level.
/// </summary>
[ApiController]
[Route("mvc/open")]
[SkipHmacValidation]
public sealed class OpenController : ControllerBase
{
    [HttpGet]
    public ActionResult<string> Get() => HttpContext.GetHmacClientId() ?? "anonymous";
}
