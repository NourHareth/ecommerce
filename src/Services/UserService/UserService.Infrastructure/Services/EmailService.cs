using AmCart.UserService.Application.Interfaces;
using Microsoft.Extensions.Logging;

namespace AmCart.UserService.Infrastructure.Services;

/// <summary>
/// Placeholder e-mail sender: no message leaves the system, the call is only logged.
/// C7 (OWASP A09:2025, CWE-532): it used to log the full verification and password-reset LINKS,
/// tokens included, together with the recipient's address. Anyone able to read the logs could
/// then reset any user's password. It now logs neither the link nor the address in clear.
/// </summary>
public class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;

    public EmailService(ILogger<EmailService> logger)
    {
        _logger = logger;
    }

    public Task SendEmailVerificationAsync(string email, string firstName, string verificationLink, CancellationToken ct = default)
    {
        _logger.LogInformation("{Event}: e-mail verification message for {Recipient}", "email.verification", MaskAddress(email));
        return Task.CompletedTask;
    }

    public Task SendPasswordResetAsync(string email, string firstName, string resetLink, CancellationToken ct = default)
    {
        _logger.LogInformation("{Event}: password reset message for {Recipient}", "email.password_reset", MaskAddress(email));
        return Task.CompletedTask;
    }

    public Task SendWelcomeEmailAsync(string email, string firstName, CancellationToken ct = default)
    {
        _logger.LogInformation("{Event}: welcome message for {Recipient}", "email.welcome", MaskAddress(email));
        return Task.CompletedTask;
    }

    /// <summary>"alice@example.com" becomes "a***@e***": enough to tell messages apart, not to identify someone.</summary>
    public static string MaskAddress(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return "none";
        var at = email.IndexOf('@');
        if (at <= 0 || at == email.Length - 1)
            return "***";
        return $"{email[0]}***@{email[at + 1]}***";
    }
}
