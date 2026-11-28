using AmCart.ProductService.Api.Extensions;
using AmCart.ProductService.Api.Observability;
using AmCart.ProductService.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmCart.ProductService.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/orders")]
public class OrdersController : ControllerBase
{
    private readonly IOrderService _orders;
    private readonly ILogger<OrdersController> _logger;

    public OrdersController(IOrderService orders, ILogger<OrdersController> logger)
    {
        _orders = orders;
        _logger = logger;
    }

    [HttpGet]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
    {
        var userId = User.GetUserId();
        if (userId == null)
            return Unauthorized(new { success = false, error = new { code = "UNAUTHORIZED", message = "Sign in to view orders." } });

        var data = await _orders.ListMyOrdersAsync(userId.Value, page, pageSize, ct);
        return Ok(new { success = true, data });
    }

    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct = default)
    {
        var userId = User.GetUserId();
        if (userId == null)
            return Unauthorized(new { success = false, error = new { code = "UNAUTHORIZED", message = "Sign in to view orders." } });

        var data = await _orders.GetMyOrderAsync(userId.Value, id, ct);
        if (data == null)
        {
            // Either a typo or someone trying order ids that are not theirs (F2-style IDOR probing).
            // One event is harmless; a burst from one user triggers the "order enumeration" alert.
            _logger.LogAccessDenied(HttpContext, "order", "not_found_for_user");
            return NotFound(new { success = false, error = new { code = "NOT_FOUND", message = "Order not found." } });
        }

        return Ok(new { success = true, data });
    }
}
