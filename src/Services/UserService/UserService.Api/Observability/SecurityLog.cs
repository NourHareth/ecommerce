using System.Security.Cryptography;
using System.Text;

namespace AmCart.UserService.Api.Observability;

/// <summary>
/// Security telemetry (section 4.7): one structured JSON log line per event. Its State always carries
/// Event (what the detection rules in deploy/k8s/monitoring/loki-rules.yaml match on), UserId and
/// CorrelationId, plus a few non-sensitive details. Same shape as ProductService.
/// Never pass a secret, token, password, e-mail address or raw request value to these methods.
/// </summary>
public static class SecurityLog
{
    public const string InjectionAttempt = "security.injection_attempt";
    public const string InputRejected = "security.input_rejected";
    public const string AuthFailed = "security.auth_failed";

    public static void LogInjectionAttempt(this ILogger logger, HttpContext context,
        string route, string fields, string indicators, int status) =>
        logger.LogWarning(
            "{Event} on {Route}: {Indicators} in {Fields}, answered {Status} (user {UserId}, correlation {CorrelationId})",
            InjectionAttempt, route, indicators, fields, status, UserIdOf(context), context.TraceIdentifier);

    public static void LogInputRejected(this ILogger logger, HttpContext context, string field, string reason) =>
        logger.LogWarning(
            "{Event}: {Field} rejected, {Reason} (user {UserId}, correlation {CorrelationId})",
            InputRejected, field, reason, UserIdOf(context), context.TraceIdentifier);

    /// <summary>
    /// A failed sign-in. The account is identified by <see cref="AccountRef"/>, never by its e-mail:
    /// enough to see many failures against one account (brute force) or one failure on many accounts
    /// (credential stuffing), without writing personal data to the logs.
    /// </summary>
    public static void LogAuthFailed(this ILogger logger, HttpContext context, string? email, string reason) =>
        logger.LogWarning(
            "{Event}: sign-in refused, {Reason} (account {AccountRef}, correlation {CorrelationId})",
            AuthFailed, reason, AccountRef(email), context.TraceIdentifier);

    /// <summary>The caller's user id (a random GUID, not personal data in itself), or "anonymous".</summary>
    public static string UserIdOf(HttpContext context) =>
        context.User.GetUserId()?.ToString() ?? "anonymous";

    /// <summary>Pseudonymous, stable reference to an account: first 12 hex chars of SHA-256(normalised e-mail).</summary>
    public static string AccountRef(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return "none";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(email.Trim().ToLowerInvariant()));
        return Convert.ToHexString(digest)[..12].ToLowerInvariant();
    }
}
