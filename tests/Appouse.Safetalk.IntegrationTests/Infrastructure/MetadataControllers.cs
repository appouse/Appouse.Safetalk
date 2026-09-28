using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Mvc;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// A partner (B2B) controller protected at class level; one action opts out.
/// </summary>
[ApiController]
[Route("api/partner")]
[RequireHmacValidation]
public sealed class PartnerOrdersController : ControllerBase
{
    [HttpGet("orders")]
    public ActionResult<string> Orders() => Ok(HttpContext.GetHmacClientId() ?? "anonymous");

    [HttpGet("catalog")]
    [SkipHmacValidation]
    public ActionResult<string> Catalog() => Ok(HttpContext.GetHmacClientId() ?? "anonymous");
}

/// <summary>
/// A public controller exempt at class level; one action opts back in.
/// </summary>
[ApiController]
[Route("api/catalog")]
[SkipHmacValidation]
public sealed class PublicCatalogController : ControllerBase
{
    [HttpGet("items")]
    public ActionResult<string> Items() => Ok(HttpContext.GetHmacClientId() ?? "anonymous");

    [HttpGet("prices")]
    [RequireHmacValidation]
    public ActionResult<string> Prices() => Ok(HttpContext.GetHmacClientId() ?? "anonymous");
}
