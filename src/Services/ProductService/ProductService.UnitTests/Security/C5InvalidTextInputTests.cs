using AmCart.ProductService.Api.Controllers;
using AmCart.ProductService.Api.ErrorHandling;
using AmCart.ProductService.Application.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Npgsql;
using Xunit;

namespace AmCart.ProductService.UnitTests.Security;

/// <summary>
/// Regression tests for finding C5 (OWASP A10:2025, CWE-248), found by the DAST scan after the
/// F1 fix: a NUL byte in a text parameter produced an unhandled HTTP 500.
/// docs/security/01-registre-des-failles.md
/// </summary>
public class C5InvalidTextInputTests
{
    private static PostgresException Pg(string sqlState) =>
        new("invalid byte sequence for encoding \"UTF8\": 0x00", "ERROR", "ERROR", sqlState);

    [Fact]
    public void Nul_byte_rejected_by_postgres_is_treated_as_client_input()
    {
        Assert.True(InvalidTextInputExceptionHandler.IsInvalidTextInput(Pg(PostgresErrorCodes.CharacterNotInRepertoire)));
    }

    [Fact]
    public void Still_detected_when_wrapped_by_ef_core()
    {
        var wrapped = new DbUpdateException("save failed", Pg(PostgresErrorCodes.CharacterNotInRepertoire));
        Assert.True(InvalidTextInputExceptionHandler.IsInvalidTextInput(wrapped));
    }

    [Fact]
    public void Other_database_errors_remain_server_errors()
    {
        Assert.False(InvalidTextInputExceptionHandler.IsInvalidTextInput(Pg(PostgresErrorCodes.UniqueViolation)));
    }

    [Fact]
    public void Non_database_errors_remain_server_errors()
    {
        Assert.False(InvalidTextInputExceptionHandler.IsInvalidTextInput(new InvalidOperationException("boom")));
    }

    [Theory]
    [InlineData("\0")]
    [InlineData("shirt\u0000")]
    [InlineData("a\u0007b")]
    public async Task Quick_search_rejects_control_characters_without_querying_the_database(string q)
    {
        var repository = new Mock<IProductRepository>(MockBehavior.Strict);
        var controller = new ProductSearchController(repository.Object, NullLogger<ProductSearchController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };

        var result = await controller.Search(q);

        Assert.IsType<BadRequestObjectResult>(result);
        repository.VerifyNoOtherCalls();
    }
}
