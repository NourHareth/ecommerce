using System.Diagnostics;
using System.Text.RegularExpressions;

namespace AmCart.ProductService.Api.Observability;

/// <summary>
/// Structured request logs with a correlation ID (section 4.7):
/// <list type="bullet">
/// <item>takes X-Correlation-ID from the gateway (nginx sets it on every API call) when it is
/// well-formed, otherwise generates one, and returns it in the response so a user can quote it;</item>
/// <item>writes one "http.request" line per call: method, route TEMPLATE (never the raw path or
/// query string, which can carry tokens or personal data), status, duration, user id;</item>
/// <item>flags injection patterns in query-string and route values as "security.injection_attempt",
/// naming the parameters and the patterns but never logging the values.</item>
/// </list>
/// Health probes are not logged: one line every few seconds, no security value.
/// </summary>
public sealed class RequestTelemetryMiddleware
{
    public const string HeaderName = "X-Correlation-ID";
    public const string RequestEvent = "http.request";
    private const int MaxFieldsReported = 10;

    // Accepting only this shape keeps a client-chosen ID from injecting text into the logs.
    private static readonly Regex ValidId = new("^[A-Za-z0-9-]{8,64}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    private readonly RequestDelegate _next;
    private readonly ILogger<RequestTelemetryMiddleware> _logger;

    public RequestTelemetryMiddleware(RequestDelegate next, ILogger<RequestTelemetryMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = ResolveCorrelationId(context.Request.Headers[HeaderName].ToString());
        context.TraceIdentifier = correlationId;
        context.Response.OnStarting(() =>
        {
            context.Response.Headers[HeaderName] = correlationId;
            return Task.CompletedTask;
        });

        if (IsHealthProbe(context.Request.Path))
        {
            await _next(context);
            return;
        }

        // Read before the pipeline runs: the exception handler clears the endpoint and route values.
        var route = RouteTemplateOf(context);
        var (fields, indicators) = ScanForInjection(context);

        using var scope = _logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId });
        var started = Stopwatch.GetTimestamp();
        try
        {
            await _next(context);
        }
        finally
        {
            var status = context.Response.StatusCode;
            _logger.LogInformation(
                "{Event} {Method} {Route} -> {Status} in {DurationMs} ms (user {UserId}, correlation {CorrelationId})",
                RequestEvent, context.Request.Method, route, status,
                Math.Round(Stopwatch.GetElapsedTime(started).TotalMilliseconds, 1),
                SecurityLog.UserIdOf(context), correlationId);

            if (indicators.Count > 0)
                _logger.LogInjectionAttempt(context, route, string.Join(',', fields), string.Join(',', indicators), status);
        }
    }

    public static string ResolveCorrelationId(string? incoming) =>
        !string.IsNullOrEmpty(incoming) && ValidId.IsMatch(incoming) ? incoming : Guid.NewGuid().ToString("N");

    /// <summary>"/api/v1/orders/{id:guid}" rather than the actual path.</summary>
    public static string RouteTemplateOf(HttpContext context) =>
        context.GetEndpoint() is RouteEndpoint endpoint
            ? "/" + (endpoint.RoutePattern.RawText ?? string.Empty).TrimStart('/')
            : "unmatched";

    public static (List<string> Fields, SortedSet<string> Indicators) ScanForInjection(HttpContext context)
    {
        var fields = new List<string>();
        var indicators = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var (key, values) in context.Request.Query)
            foreach (var value in values)
                Check("query." + SafeName(key), value);

        foreach (var (key, value) in context.Request.RouteValues)
            if (value is string text && key is not ("controller" or "action"))
                Check("route." + SafeName(key), text);

        return (fields, indicators);

        void Check(string field, string? value)
        {
            var found = InjectionIndicators.Find(value);
            if (found.Count == 0)
                return;
            indicators.UnionWith(found);
            if (fields.Count < MaxFieldsReported && !fields.Contains(field))
                fields.Add(field);
        }
    }

    // Parameter names come from the client: keep them short and harmless in the log.
    private static string SafeName(string name) =>
        new(name.Take(32).Select(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' ? c : '?').ToArray());

    private static bool IsHealthProbe(PathString path) =>
        path.StartsWithSegments("/health") || path.StartsWithSegments("/api/v1/health");
}
