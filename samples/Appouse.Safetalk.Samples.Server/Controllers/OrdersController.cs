using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Mvc;

namespace Appouse.Safetalk.Samples.Server.Controllers;

[ApiController]
[Route("api/orders")]
public sealed class OrdersController : ControllerBase
{
    // The middleware has already verified the signature; the body is still readable for model binding.
    [HttpPost]
    public ActionResult<OrderResponse> Create(CreateOrderRequest request)
    {
        string clientId = HttpContext.GetHmacClientId()!;
        return Ok(new OrderResponse(Random.Shared.Next(1_000, 9_999), request.ProductCode, request.Quantity, clientId));
    }

    [HttpGet("{id:int}")]
    public ActionResult<OrderResponse> Get(int id)
        => Ok(new OrderResponse(id, "SKU-42", 1, User.Identity!.Name!));
}

public sealed record CreateOrderRequest(string ProductCode, int Quantity);

public sealed record OrderResponse(int Id, string ProductCode, int Quantity, string CreatedBy);
