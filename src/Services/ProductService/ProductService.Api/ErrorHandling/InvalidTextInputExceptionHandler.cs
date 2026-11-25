using Microsoft.AspNetCore.Diagnostics;
using Npgsql;

namespace AmCart.ProductService.Api.ErrorHandling;

/// <summary>
/// C5 (OWASP A10:2025, CWE-248): PostgreSQL rejects text containing characters it cannot store,
/// such as NUL (\0), with SQLSTATE 22021. Left unhandled, that becomes an HTTP 500 for what is
/// really bad client input. This handler answers 400 instead; every other exception keeps the
/// default generic 500 (no details leaked).
/// </summary>
public sealed class InvalidTextInputExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        if (!IsInvalidTextInput(exception))
            return false;

        httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
        await httpContext.Response.WriteAsJsonAsync(new
        {
            success = false,
            error = new { code = "VALIDATION", message = "The request contains characters that are not allowed." }
        }, cancellationToken);
        return true;
    }

    /// <summary>True when the exception (or one it wraps, e.g. DbUpdateException) is SQLSTATE 22021.</summary>
    public static bool IsInvalidTextInput(Exception? exception)
    {
        for (var e = exception; e != null; e = e.InnerException)
        {
            if (e is PostgresException { SqlState: PostgresErrorCodes.CharacterNotInRepertoire })
                return true;
        }
        return false;
    }
}
