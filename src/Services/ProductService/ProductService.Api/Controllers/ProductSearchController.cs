using AmCart.ProductService.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AmCart.ProductService.Api.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/v1/products/quick-search")]
public class ProductSearchController : ControllerBase
{
    private const int MaxQueryLength = 100;   // an autocomplete term; bounds the work per request
    private readonly IProductRepository _products;

    public ProductSearchController(IProductRepository products)
    {
        _products = products;
    }

    /// <summary>Autocomplete for the storefront search box.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Search([FromQuery] string? q, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(q))
            return BadRequest(new { success = false, error = new { code = "VALIDATION", message = "Query parameter q is required." } });
        if (q.Length > MaxQueryLength)
            return BadRequest(new { success = false, error = new { code = "VALIDATION", message = $"Query parameter q must be at most {MaxQueryLength} characters." } });
        if (q.Any(char.IsControl))   // C5: NUL and other control characters are never a product name
            return BadRequest(new { success = false, error = new { code = "VALIDATION", message = "Query parameter q contains characters that are not allowed." } });

        var hits = await _products.QuickSearchAsync(q.Trim(), ct);
        return Ok(new { success = true, data = hits });
    }
}
