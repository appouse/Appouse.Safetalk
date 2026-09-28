using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Mvc;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// An MVC controller of the protected test application. Model binding reads the body after verification.
/// </summary>
[ApiController]
[Route("api/controller/orders")]
public sealed class OrdersController : ControllerBase
{
    [HttpPost]
    public ActionResult<OrderEchoResponse> Create(OrderRequest order)
        => Ok(new OrderEchoResponse(User.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value, order));

    [HttpGet("public")]
    [SkipHmacValidation]
    public ActionResult<string> Public() => Ok("public");
}
