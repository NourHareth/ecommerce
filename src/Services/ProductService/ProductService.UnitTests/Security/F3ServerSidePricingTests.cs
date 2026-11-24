using AmCart.ProductService.Application.DTOs;
using AmCart.ProductService.Application.Interfaces;
using AmCart.ProductService.Application.Services;
using AmCart.ProductService.Domain.Entities;
using Moq;
using Xunit;

namespace AmCart.ProductService.UnitTests.Security;

/// <summary>
/// Regression tests for flaw F3 (price tampering, OWASP A06, CWE-472): the price a customer pays
/// always comes from the catalog, never from the request. docs/security/01-registre-des-failles.md
/// </summary>
public class F3ServerSidePricingTests
{
    private readonly Mock<ICartRepository> _carts = new();
    private readonly Mock<IProductRepository> _products = new();
    private readonly Mock<ICouponRepository> _coupons = new();
    private readonly Cart _cart = new() { Id = Guid.NewGuid(), SessionId = "guest-session" };

    private CartService Sut() => new(_carts.Object, _products.Object, _coupons.Object);

    public F3ServerSidePricingTests()
    {
        _carts.Setup(c => c.GetOrCreateAsync(It.IsAny<Guid?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync(_cart);
        _carts.Setup(c => c.GetByIdAsync(_cart.Id, It.IsAny<CancellationToken>())).ReturnsAsync(_cart);
    }

    [Fact]
    public void Add_to_cart_request_has_no_client_price_field()
    {
        // The API contract itself must not accept a price: an unknown "unitPrice" JSON field is ignored.
        Assert.Null(typeof(AddCartItemRequest).GetProperty("UnitPrice"));
    }

    [Fact]
    public async Task Added_item_is_stored_at_catalog_price()
    {
        var product = TestDb.Product("Shirt", 49.99m);
        _products.Setup(p => p.GetByIdAsync(product.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync(product);
        _carts.Setup(c => c.ListItemsWithProductsAsync(_cart.Id, It.IsAny<CancellationToken>()))
              .ReturnsAsync(Array.Empty<CartItem>());
        CartItem? stored = null;
        _carts.Setup(c => c.AddCartItemAsync(It.IsAny<CartItem>(), It.IsAny<CancellationToken>()))
              .Callback<CartItem, CancellationToken>((item, _) => stored = item)
              .Returns(Task.CompletedTask);

        await Sut().AddItemAsync(null, "guest-session", product.Id, 2);

        Assert.NotNull(stored);
        Assert.Equal(49.99m, stored!.UnitPrice);
        Assert.Equal(99.98m, stored.Subtotal);
    }

    [Fact]
    public async Task Cart_total_ignores_a_tampered_stored_price()
    {
        // Defense in depth: even if a wrong price ever reached the cart_items table,
        // the cart (and therefore checkout) is priced from the catalog.
        var product = TestDb.Product("Shirt", 49.99m);
        var tampered = new CartItem
        {
            Id = Guid.NewGuid(), CartId = _cart.Id, ProductId = product.Id, Product = product,
            Quantity = 1, UnitPrice = 0.01m, Subtotal = 0.01m,
        };
        _carts.Setup(c => c.ListItemsWithProductsAsync(_cart.Id, It.IsAny<CancellationToken>()))
              .ReturnsAsync(new[] { tampered });

        var dto = await Sut().GetCartAsync(null, "guest-session");

        Assert.Equal(49.99m, Assert.Single(dto.Items).UnitPrice);
        Assert.Equal(49.99m, dto.Total);
    }
}
