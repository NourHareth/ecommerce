using AmCart.ProductService.Api.Extensions;

namespace AmCart.ProductService.Api.Observability;

/// <summary>
/// Security telemetry (section 4.7): one structured JSON log line per event. Its State always carries
/// Event (what the detection rules in deploy/k8s/monitoring/loki-rules.yaml match on), UserId and
/// CorrelationId, plus a few non-sensitive details.
/// Never pass a secret, token, password, e-mail address or raw request value to these methods.
/// </summary>
public static class SecurityLog
{
    public const string InjectionAttempt = "security.injection_attempt";
    public const string InputRejected = "security.input_rejected";
    public const string AccessDenied = "security.access_denied";

    public static void LogInjectionAttempt(this ILogger logger, HttpContext context,
        string route, string fields, string indicators, int status) =>
        logger.LogWarning(
            "{Event} on {Route}: {Indicators} in {Fields}, answered {Status} (user {UserId}, correlation {CorrelationId})",
            InjectionAttempt, route, indicators, fields, status, UserIdOf(context), context.TraceIdentifier);

    public static void LogInputRejected(this ILogger logger, HttpContext context, string field, string reason) =>
        logger.LogWarning(
            "{Event}: {Field} rejected, {Reason} (user {UserId}, correlation {CorrelationId})",
            InputRejected, field, reason, UserIdOf(context), context.TraceIdentifier);

    public static void LogAccessDenied(this ILogger logger, HttpContext context, string resource, string reason) =>
        logger.LogWarning(
            "{Event}: {Resource}, {Reason} (user {UserId}, correlation {CorrelationId})",
            AccessDenied, resource, reason, UserIdOf(context), context.TraceIdentifier);

    /// <summary>The caller's user id (a random GUID, not personal data in itself), or "anonymous".</summary>
    public static string UserIdOf(HttpContext context) =>
        context.User.GetUserId()?.ToString() ?? "anonymous";
}
