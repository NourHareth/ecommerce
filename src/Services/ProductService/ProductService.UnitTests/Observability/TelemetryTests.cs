using AmCart.ProductService.Api.Observability;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AmCart.ProductService.UnitTests.Observability;

/// <summary>
/// Section 4.7: structured logs with a correlation ID, no sensitive data, and detection of
/// injection attempts. The deployed version is checked end to end by tests/detection/replay-attacks.sh.
/// </summary>
public class TelemetryTests
{
    // ------------------------------------------------------------------ detection patterns
    [Theory]
    [InlineData("' OR '1'='1", "sql-boolean")]
    [InlineData("x') and 1=1", "sql-tautology")]
    [InlineData("shirt'--", "sql-comment")]
    [InlineData("a' UNION SELECT name FROM users", "sql-union")]
    [InlineData("1; DROP TABLE products", "sql-stacked")]
    [InlineData("1 and pg_sleep(5)", "sql-delay")]
    [InlineData("x from information_schema.tables", "sql-catalog")]
    [InlineData("<script>alert(1)</script>", "xss")]
    public void Common_injection_payloads_are_flagged(string value, string expectedRule)
    {
        Assert.Contains(expectedRule, InjectionIndicators.Find(value));
    }

    [Theory]
    [InlineData("men's shirt")]
    [InlineData("rock and roll")]
    [InlineData("t-shirt 2-pack")]
    [InlineData("50% off; free shipping")]
    [InlineData("kids' shoes")]
    [InlineData("3f2b9c4e-8a61-4d0e-9b7a-2c5e1f0a9d13")]
    [InlineData("q1w2-e3r4--t5y6_u7i8")]   // base64url token shape: '-' and '_' are legitimate
    [InlineData("")]
    [InlineData(null)]
    public void Ordinary_values_are_not_flagged(string? value)
    {
        Assert.Empty(InjectionIndicators.Find(value));
    }

    // ------------------------------------------------------------------ correlation ID
    [Fact]
    public void Well_formed_correlation_id_from_the_gateway_is_kept()
    {
        Assert.Equal("4bf92f3577b34da6a3ce929d0e0e4736",
            RequestTelemetryMiddleware.ResolveCorrelationId("4bf92f3577b34da6a3ce929d0e0e4736"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("abc\r\nfake log line")]                 // log forging attempt
    [InlineData("a,b,c,d,e,f,g,h,i,j")]
    [InlineData("0123456789012345678901234567890123456789012345678901234567890123456789")]   // > 64
    public void Malformed_correlation_id_is_replaced(string incoming)
    {
        var id = RequestTelemetryMiddleware.ResolveCorrelationId(incoming);
        Assert.NotEqual(incoming, id);
        Assert.Matches("^[0-9a-f]{32}$", id);
    }

    // ------------------------------------------------------------------ the middleware itself
    [Fact]
    public async Task Request_is_logged_with_route_template_and_correlation_id_but_not_the_raw_query()
    {
        var logger = new CapturingLogger<RequestTelemetryMiddleware>();
        var context = QuickSearchRequest("?q=blue%20shirt&token=secret-value-123");
        context.Request.Headers[RequestTelemetryMiddleware.HeaderName] = "4bf92f3577b34da6a3ce929d0e0e4736";

        await new RequestTelemetryMiddleware(_ => Task.CompletedTask, logger).InvokeAsync(context);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal("http.request", entry.State["Event"]);
        Assert.Equal("/api/v1/products/quick-search", entry.State["Route"]);
        Assert.Equal("4bf92f3577b34da6a3ce929d0e0e4736", entry.State["CorrelationId"]);
        Assert.Equal("4bf92f3577b34da6a3ce929d0e0e4736", context.TraceIdentifier);
        Assert.DoesNotContain("secret-value-123", logger.AllText);
        Assert.DoesNotContain("blue", logger.AllText);
    }

    [Fact]
    public async Task Injection_attempt_is_reported_without_the_payload()
    {
        var logger = new CapturingLogger<RequestTelemetryMiddleware>();
        var context = QuickSearchRequest("?q=%27%20OR%20%271%27%3D%271");   // ' OR '1'='1

        await new RequestTelemetryMiddleware(_ => Task.CompletedTask, logger).InvokeAsync(context);

        var attempt = Assert.Single(logger.Entries, e => (string?)e.State["Event"] == SecurityLog.InjectionAttempt);
        Assert.Equal(LogLevel.Warning, attempt.Level);
        Assert.Equal("query.q", attempt.State["Fields"]);
        Assert.Contains("sql-boolean", (string)attempt.State["Indicators"]!);
        Assert.Equal("anonymous", attempt.State["UserId"]);
        Assert.DoesNotContain("OR '1'", logger.AllText);
    }

    [Fact]
    public async Task Health_probes_are_not_logged()
    {
        var logger = new CapturingLogger<RequestTelemetryMiddleware>();
        var context = new DefaultHttpContext();
        context.Request.Path = "/health";

        await new RequestTelemetryMiddleware(_ => Task.CompletedTask, logger).InvokeAsync(context);

        Assert.Empty(logger.Entries);
    }

    private static DefaultHttpContext QuickSearchRequest(string queryString)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Path = "/api/v1/products/quick-search";
        context.Request.QueryString = new QueryString(queryString);
        context.SetEndpoint(new RouteEndpoint(_ => Task.CompletedTask,
            RoutePatternFactory.Parse("api/v1/products/quick-search"), 0, EndpointMetadataCollection.Empty, "quick-search"));
        return context;
    }
}

/// <summary>Keeps every log call's structured state, to assert on what would reach Loki.</summary>
internal sealed class CapturingLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, IReadOnlyDictionary<string, object?> State, string Message)> Entries { get; } = new();

    public string AllText => string.Join("\n", Entries.Select(e =>
        e.Message + " " + string.Join(" ", e.State.Values.Select(v => v?.ToString()))));

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var values = state as IEnumerable<KeyValuePair<string, object?>> ?? Array.Empty<KeyValuePair<string, object?>>();
        Entries.Add((logLevel, values.ToDictionary(kv => kv.Key, kv => kv.Value), formatter(state, exception)));
    }
}
