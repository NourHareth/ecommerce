namespace AmCart.UserService.Api.Observability;

/// <summary>
/// Forwards the current request's correlation ID on calls to ProductService, so one user action
/// can be followed across nginx, UserService and ProductService with a single ID (section 4.7).
/// </summary>
public sealed class CorrelationIdPropagationHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _accessor;

    public CorrelationIdPropagationHandler(IHttpContextAccessor accessor)
    {
        _accessor = accessor;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var correlationId = _accessor.HttpContext?.TraceIdentifier;
        if (!string.IsNullOrEmpty(correlationId) && !request.Headers.Contains(RequestTelemetryMiddleware.HeaderName))
            request.Headers.TryAddWithoutValidation(RequestTelemetryMiddleware.HeaderName, correlationId);
        return base.SendAsync(request, cancellationToken);
    }
}
