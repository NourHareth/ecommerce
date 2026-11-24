namespace AmCart.ProductService.Application.DTOs;

/// <summary>Lightweight row returned by the storefront quick-search box.</summary>
public class ProductSearchHitDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string Slug { get; set; } = "";
    public decimal Price { get; set; }
}
