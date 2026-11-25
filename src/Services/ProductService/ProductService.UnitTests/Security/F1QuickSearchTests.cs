using AmCart.ProductService.Infrastructure.Repositories;
using Xunit;

namespace AmCart.ProductService.UnitTests.Security;

/// <summary>
/// Regression tests for flaw F1 (SQL injection, OWASP A05, CWE-89): the search term is data, never
/// SQL. The query is built with LINQ, so EF Core sends the term as a parameter. These tests run the
/// real repository query; SQL-level protection is additionally enforced in CI by the Semgrep rule
/// `efcore-raw-sql-non-constant` and confirmed by the DAST scan.
/// docs/security/01-registre-des-failles.md
/// </summary>
public class F1QuickSearchTests
{
    [Fact]
    public async Task Finds_active_products_by_name_case_insensitively()
    {
        await using var db = TestDb.Create();
        db.Products.AddRange(TestDb.Product("Blue Shirt", 10m), TestDb.Product("Red Shoes", 20m));
        await db.SaveChangesAsync();

        var hits = await new ProductRepository(db).QuickSearchAsync("shirt");

        Assert.Equal("Blue Shirt", Assert.Single(hits).Name);
    }

    [Fact]
    public async Task Quote_characters_are_matched_literally()
    {
        await using var db = TestDb.Create();
        db.Products.Add(TestDb.Product("O'Neill Jacket", 80m));
        await db.SaveChangesAsync();

        var hits = await new ProductRepository(db).QuickSearchAsync("o'neill");

        Assert.Single(hits);
    }

    [Fact]
    public async Task Sql_syntax_in_the_term_matches_nothing_and_never_widens_the_result()
    {
        await using var db = TestDb.Create();
        db.Products.AddRange(TestDb.Product("Blue Shirt", 10m), TestDb.Product("Secret Draft", 5m, status: "draft"));
        await db.SaveChangesAsync();

        var hits = await new ProductRepository(db).QuickSearchAsync("zzz' OR '1'='1");

        Assert.Empty(hits);
    }

    [Fact]
    public async Task Draft_products_are_never_returned()
    {
        await using var db = TestDb.Create();
        db.Products.Add(TestDb.Product("Secret Draft", 5m, status: "draft"));
        await db.SaveChangesAsync();

        var hits = await new ProductRepository(db).QuickSearchAsync("secret");

        Assert.Empty(hits);
    }
}
