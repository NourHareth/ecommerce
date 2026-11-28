using AmCart.UserService.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AmCart.UserService.UnitTests.Security;

/// <summary>
/// Regression tests for finding C7 (OWASP A09:2025, CWE-532): verification and password-reset links,
/// which carry single-use tokens, were written to the logs with the recipient's address.
/// docs/security/01-registre-des-failles.md
/// </summary>
public class C7NoSecretsInLogsTests
{
    private const string Address = "alice.martin@example.com";
    private const string Token = "single-use-aaaaaaaaaaaaaaaa";   // fake, low entropy on purpose
    private const string Link = "https://shop.example/reset-password?token=" + Token;

    [Fact]
    public async Task Password_reset_link_and_address_are_not_logged()
    {
        var logger = new CapturingLogger<EmailService>();

        await new EmailService(logger).SendPasswordResetAsync(Address, "Alice", Link);

        Assert.Single(logger.Lines);
        Assert.DoesNotContain(Token, logger.AllText);
        Assert.DoesNotContain("reset-password", logger.AllText);
        Assert.DoesNotContain(Address, logger.AllText);
        Assert.DoesNotContain("alice.martin", logger.AllText);
    }

    [Fact]
    public async Task Verification_link_and_address_are_not_logged()
    {
        var logger = new CapturingLogger<EmailService>();

        await new EmailService(logger).SendEmailVerificationAsync(Address, "Alice", Link);

        Assert.DoesNotContain(Token, logger.AllText);
        Assert.DoesNotContain(Address, logger.AllText);
    }

    [Theory]
    [InlineData("alice@example.com", "a***@e***")]
    [InlineData("x@y", "x***@y***")]
    [InlineData("no-at-sign", "***")]
    [InlineData("@example.com", "***")]
    [InlineData("", "none")]
    [InlineData(null, "none")]
    public void Address_is_masked(string? email, string expected)
    {
        Assert.Equal(expected, EmailService.MaskAddress(email));
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Lines { get; } = new();

        public string AllText => string.Join("\n", Lines);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            // The formatted message AND every structured value: both reach the JSON log.
            var values = state as IEnumerable<KeyValuePair<string, object?>> ?? Array.Empty<KeyValuePair<string, object?>>();
            Lines.Add(formatter(state, exception) + " " + string.Join(" ", values.Select(kv => $"{kv.Key}={kv.Value}")));
        }
    }
}
