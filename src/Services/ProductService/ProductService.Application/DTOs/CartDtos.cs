namespace AmCart.ProductService.Application.DTOs;

public class CartLineDto
{
    public Guid CartItemId { get; set; }
    public Guid ProductId { get; set; }
    public string? ProductName { get; set; }
    public string? ProductSlug { get; set; }
    public string? PrimaryImageUrl { get; set; }
    public int Quantity { get; set; }
    public decimal UnitPrice { get; set; }
    public decimal? CompareAtPrice { get; set; }
    public decimal LineSubtotal { get; set; }
    public string Currency { get; set; } = "USD";
    public bool ProductAvailable { get; set; }
}

public class CartDto
{
    public Guid CartId { get; set; }
    public IReadOnlyList<CartLineDto> Items { get; set; } = Array.Empty<CartLineDto>();
    public decimal Subtotal { get; set; }
    public string? CouponCode { get; set; }
    public decimal DiscountAmount { get; set; }
    public decimal Total { get; set; }
    public string Currency { get; set; } = "USD";
}

public class AddCartItemRequest
{
    public Guid ProductId { get; set; }
    public int Quantity { get; set; } = 1;
    // No price here on purpose (F3): the price is always read from the catalog on the server.
}

public class UpdateCartItemRequest
{
    public int Quantity { get; set; }
}

public class ApplyCouponRequest
{
    public string? Code { get; set; }
}

public class MergeCartRequest
{
    public string? SessionId { get; set; }
}
