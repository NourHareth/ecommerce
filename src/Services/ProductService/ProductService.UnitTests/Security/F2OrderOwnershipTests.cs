using AmCart.ProductService.Infrastructure.Repositories;
using Xunit;

namespace AmCart.ProductService.UnitTests.Security;

/// <summary>
/// Regression tests for flaw F2 (IDOR, OWASP A01, CWE-639): a customer must never obtain another
/// customer's order, even with its exact identifier. docs/security/01-registre-des-failles.md
/// </summary>
public class F2OrderOwnershipTests
{
    [Fact]
    public async Task Owner_gets_her_order()
    {
        await using var db = TestDb.Create();
        var alice = Guid.NewGuid();
        var order = TestDb.Order(alice);
        db.Orders.Add(order);
        await db.SaveChangesAsync();

        var result = await new OrderRepository(db).GetByIdForUserAsync(order.Id, alice);

        Assert.NotNull(result);
        Assert.Equal(order.Id, result!.Id);
    }

    [Fact]
    public async Task Another_customer_cannot_get_the_order_even_with_its_id()
    {
        await using var db = TestDb.Create();
        var alice = Guid.NewGuid();
        var bob = Guid.NewGuid();
        var order = TestDb.Order(alice);
        db.Orders.Add(order);
        await db.SaveChangesAsync();

        var result = await new OrderRepository(db).GetByIdForUserAsync(order.Id, bob);

        Assert.Null(result);   // the API then answers 404: existence is not revealed either
    }
}
