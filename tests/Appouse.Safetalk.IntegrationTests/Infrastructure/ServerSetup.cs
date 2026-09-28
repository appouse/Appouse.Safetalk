using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Customizations applied to a <see cref="SafetalkServer"/>.
/// </summary>
internal sealed class ServerSetup
{
    /// <summary>Configures <see cref="HmacServerOptions"/> through <c>AddHmacServer(...)</c>.</summary>
    public Action<HmacServerOptions>? ConfigureOptions { get; init; }

    /// <summary>
    /// When set, the server is registered with <c>AddHmacServer(Configuration)</c> (options and, when the section has a
    /// <c>Clients</c> child, secrets bound from configuration) instead of <c>AddHmacServer(...).AddInMemorySecrets(...)</c>.
    /// </summary>
    public IConfiguration? Configuration { get; init; }

    /// <summary>Further configures the <see cref="IHmacServerBuilder"/> (replay protection, ...).</summary>
    public Action<IHmacServerBuilder>? ConfigureHmac { get; init; }

    /// <summary>Registers additional services after the HMAC services.</summary>
    public Action<IServiceCollection>? ConfigureServices { get; init; }

    /// <summary>Adds middleware that runs after routing and before <c>UseHmacAuthentication()</c>.</summary>
    public Action<IApplicationBuilder>? ConfigurePipeline { get; init; }

    /// <summary>Adds middleware that runs right after <c>UseHmacAuthentication()</c> (before authorization).</summary>
    public Action<IApplicationBuilder>? ConfigurePipelineAfterHmac { get; init; }

    /// <summary>Maps additional endpoints next to the echo endpoints.</summary>
    public Action<IEndpointRouteBuilder>? ConfigureEndpoints { get; init; }

    /// <summary>Applies conventions to <c>app.MapControllers()</c>.</summary>
    public Action<ControllerActionEndpointConventionBuilder>? ConfigureControllers { get; init; }

    /// <summary>
    /// Registers <c>AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac()</c>, as the README
    /// recommends for applications that use authorization policies.
    /// </summary>
    public bool AddHmacAuthenticationScheme { get; init; }

    /// <summary>
    /// When set, the middleware only protects matching requests:
    /// <c>app.UseWhen(ProtectOnly, branch => branch.UseHmacAuthentication())</c>.
    /// </summary>
    public Func<HttpContext, bool>? ProtectOnly { get; init; }

    /// <summary>When set, <c>UsePathBase(PathBase)</c> is added in front of routing.</summary>
    public string? PathBase { get; init; }

    /// <summary>The server clock (for example a <c>FakeTimeProvider</c>).</summary>
    public TimeProvider? TimeProvider { get; init; }

    /// <summary>Registers <c>AddProblemDetails()</c>.</summary>
    public bool UseProblemDetails { get; init; }

    /// <summary>Records the library's log entries (Debug and above) of the server.</summary>
    public LogCapture? Logs { get; init; }

    /// <summary>The Kestrel protocols. Ignored by the TestServer.</summary>
    public HttpProtocols? Protocols { get; init; }

    /// <summary>
    /// When <see langword="true"/> (the default), the library's validator is wrapped in a recording decorator so that
    /// <see cref="SafetalkServer.ValidationResults"/> is populated. Set it to <see langword="false"/> to run exactly what
    /// <c>AddHmacServer()</c> registers (by type), including the host's <c>ValidateOnBuild</c> check of its dependencies.
    /// </summary>
    public bool RecordValidationResults { get; init; } = true;
}
