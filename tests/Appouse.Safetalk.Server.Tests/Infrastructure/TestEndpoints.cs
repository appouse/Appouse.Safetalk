using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// Minimal API endpoints used by the pipeline tests.
/// </summary>
internal static class TestEndpoints
{
    public const string Echo = "/api/echo";
    public const string WhoAmI = "/api/whoami";
    public const string Orders = "/api/orders";
    public const string Health = "/health";

    /// <summary>
    /// Adds a middleware that counts the requests reaching the endpoints, then maps the endpoints.
    /// Call it after <c>UseHmacAuthentication()</c>.
    /// </summary>
    public static void Map(WebApplication app)
    {
        RequestCounter counter = app.Services.GetRequiredService<RequestCounter>();
        app.Use(async (HttpContext context, RequestDelegate next) =>
        {
            counter.Increment();
            await next(context);
        });

        app.MapPost(Echo, async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            string body = await reader.ReadToEndAsync(context.RequestAborted);
            return Results.Ok(ClientInfoResponse.From(context, body));
        });

        app.MapGet(WhoAmI, (HttpContext context) => Results.Ok(ClientInfoResponse.From(context, string.Empty)));

        app.MapPost(Orders, (OrderRequest order) => Results.Ok(order));

        app.MapGet(Health, (HttpContext context) => Results.Text(context.GetHmacClientId() ?? "anonymous")).SkipHmacValidation();
    }
}
