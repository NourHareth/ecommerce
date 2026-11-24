using AmCart.ProductService.Domain.Entities;
using AmCart.ProductService.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace AmCart.ProductService.UnitTests;

/// <summary>Fresh, isolated in-memory database and entity builders for repository tests.</summary>
internal static class TestDb
{
    public static ProductDbContext Create() =>
        new(new DbContextOptionsBuilder<ProductDbContext>()
            .UseInMemoryDatabase($"amcart-tests-{Guid.NewGuid()}")
            .Options);

    public static Product Product(string name, decimal price, string status = "active") => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        Slug = $"{name.ToLowerInvariant().Replace(' ', '-').Replace("'", "")}-{Guid.NewGuid():N}",
        SKU = $"SKU-{Guid.NewGuid():N}",
        Price = price,
        Quantity = 100,
        Status = status,
    };

    public static Order Order(Guid ownerId) => new()
    {
        Id = Guid.NewGuid(),
        OrderNumber = $"AC-TEST-{Guid.NewGuid():N}",
        CreatedAt = DateTime.UtcNow,
        UserId = ownerId,
        PaymentMethod = "PayPal",
        Subtotal = 49.99m,
        Total = 49.99m,
        BillFirstName = "Alice", BillLastName = "Test", BillCountry = "TN", BillStreet = "1 Test St",
        BillApartment = "A1", BillCity = "Tunis", BillState = "Tunis", BillZip = "1000",
        BillPhone = "+21650000001", BillEmail = "alice@example.test",
        ShipFirstName = "Alice", ShipLastName = "Test", ShipCountry = "TN", ShipStreet = "1 Test St",
        ShipApartment = "A1", ShipCity = "Tunis", ShipState = "Tunis", ShipZip = "1000",
        ShipPhone = "+21650000001", ShipEmail = "alice@example.test",
    };
}
