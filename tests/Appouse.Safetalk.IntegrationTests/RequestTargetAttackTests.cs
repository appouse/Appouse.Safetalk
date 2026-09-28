using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Request-target confusion attacks: an attacker re-uses a captured, valid signature with a request target that the
/// server interprets differently from the target that was signed.
/// </summary>
public sealed class RequestTargetAttackTests
{
    private const string AdminPath = "/admin/export";

    /// <summary>
    /// Kestrel splits an absolute-form target at the first <c>?</c> even after a <c>#</c>: for
    /// <c>GET http://host/admin/export#?admin=true</c> the application sees <c>QueryString = ?admin=true</c> whereas
    /// <see cref="Uri.PathAndQuery"/> of the same target is <c>/admin/export</c>. A signature captured for
    /// <c>GET /admin/export</c> must not authorize the smuggled query.
    /// </summary>
    [Fact]
    public async Task Kestrel_AbsoluteFormTargetWithFragmentSmuggledQuery_AndCapturedValidSignature_IsRejectedBeforeTheEndpoint()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var hits = new EndpointHits();
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, AdminEndpointSetup(hits), ct);
        CapturedRequest captured = await CaptureSignedGetAsync(server, AdminPath, ct);
        string smuggled = $"http://{server.BaseAddress.Authority}{AdminPath}#?admin=true";

        // Proof that the vector is real on this Kestrel version: an unprotected endpoint sees the smuggled query.
        RawHttpResponse probe = await RawHttpClient.SendForResponseAsync(
            server.BaseAddress, "GET", $"http://{server.BaseAddress.Authority}/public/echo-query#?admin=true", [], ReadOnlyMemory<byte>.Empty, ct);

        RawHttpResponse attack = await RawHttpClient.SendForResponseAsync(server.BaseAddress, "GET", smuggled, captured.SigningHeaders, ReadOnlyMemory<byte>.Empty, ct);
        HmacValidationFailure attackFailure = server.LastFailure;
        int hitsAfterAttack = hits.Count;
        RawHttpResponse control = await RawHttpClient.SendForResponseAsync(server.BaseAddress, "GET", AdminPath, captured.SigningHeaders, ReadOnlyMemory<byte>.Empty, ct);

        Assert.Equal(HttpStatusCode.OK, probe.StatusCode);
        Assert.Contains("?admin=true", probe.Body, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Unauthorized, attack.StatusCode);
        Assert.Contains("WWW-Authenticate: HMAC-SHA256", attack.Headers, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, attackFailure);
        Assert.Equal(0, hitsAfterAttack);

        // Control: the captured signature itself is valid for the origin-form target it was made for.
        Assert.Equal(HttpStatusCode.OK, control.StatusCode);
        Assert.Equal(string.Empty, Assert.Single(hits.Queries));
    }

    [Theory]
    [InlineData("http://{authority}/admin/export")]
    [InlineData("http://{authority}/admin/export?")]
    [InlineData("http://{authority}/admin/./export")]
    [InlineData("http://{authority}/admin/x/../export")]
    [InlineData("https://{authority}/admin/export")]
    public async Task Kestrel_AbsoluteFormTargetEquivalentToTheSignedPath_IsRejectedAsInvalidRequestTarget(string targetTemplate)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var hits = new EndpointHits();
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, AdminEndpointSetup(hits), ct);
        KeyValuePair<string, string>[] headers = ManualSigner.CreateHeaders("GET", AdminPath, []);
        string target = targetTemplate.Replace("{authority}", server.BaseAddress.Authority, StringComparison.Ordinal);

        HttpStatusCode status = await RawHttpClient.SendAsync(server.BaseAddress, "GET", target, headers, ReadOnlyMemory<byte>.Empty, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, server.LastFailure);
        Assert.Equal(0, hits.Count);
    }

    /// <summary>
    /// Kestrel itself refuses an absolute-form target with an upper-case scheme (it is not recognised as absolute-form
    /// and is parsed as an invalid authority-form); either way the endpoint is never reached.
    /// </summary>
    [Fact]
    public async Task Kestrel_AbsoluteFormTargetWithUpperCaseScheme_NeverReachesTheEndpoint()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var hits = new EndpointHits();
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, AdminEndpointSetup(hits), ct);

        HttpStatusCode status = await RawHttpClient.SendAsync(
            server.BaseAddress,
            "GET",
            $"HTTP://{server.BaseAddress.Authority}{AdminPath}#?admin=true",
            ManualSigner.CreateHeaders("GET", AdminPath, []),
            ReadOnlyMemory<byte>.Empty,
            ct);

        Assert.True(status is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized, $"Unexpected status {status}.");
        Assert.Equal(0, hits.Count);
        Assert.DoesNotContain(server.ValidationResults, result => result.Succeeded);
    }

    [Fact]
    public async Task Kestrel_AsteriskFormTarget_IsRejectedAsInvalidRequestTarget()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);

        HttpStatusCode status = await RawHttpClient.SendAsync(
            server.BaseAddress,
            "OPTIONS",
            "*",
            ManualSigner.CreateHeaders("OPTIONS", "*", []),
            ReadOnlyMemory<byte>.Empty,
            ct);

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, server.LastFailure);
    }

    /// <summary>
    /// The request target is checked before the secret lookup: an absolute-form probe does not reach the secret store
    /// and cannot be used to tell known from unknown clients.
    /// </summary>
    [Fact]
    public async Task Kestrel_AbsoluteFormTargetFromUnknownClient_IsRejectedBeforeTheSecretLookup()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup
            {
                ConfigureHmac = hmac => hmac.AddSecretProvider<DatabaseSecretProvider>(),
                ConfigureServices = services =>
                {
                    services.AddScoped<ClientSecretsDbContext>();
                    services.AddSingleton(lookups);
                },
            },
            ct);
        string target = $"http://{server.BaseAddress.Authority}/api/whoami";

        HttpStatusCode status = await RawHttpClient.SendAsync(
            server.BaseAddress,
            "GET",
            target,
            ManualSigner.CreateHeaders("GET", "/api/whoami", [], clientId: "partner-unknown"),
            ReadOnlyMemory<byte>.Empty,
            ct);

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, server.LastFailure);
        Assert.Empty(lookups.Lookups);
    }

    /// <summary>
    /// A custom <see cref="HmacServerOptions.RequestTargetResolver"/> that returns something other than an origin-form
    /// target fails closed, even though client and resolver would agree on the (non origin-form) string.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, "inspect/orders?id=5")]
    [InlineData(TestHostKind.Kestrel, "inspect/orders?id=5")]
    [InlineData(TestHostKind.TestServer, "http://localhost/inspect/orders?id=5")]
    [InlineData(TestHostKind.Kestrel, "http://localhost/inspect/orders?id=5")]
    [InlineData(TestHostKind.TestServer, "*")]
    [InlineData(TestHostKind.Kestrel, "*")]
    [InlineData(TestHostKind.TestServer, "")]
    [InlineData(TestHostKind.Kestrel, "")]
    [InlineData(TestHostKind.TestServer, null)]
    [InlineData(TestHostKind.Kestrel, null)]
    public async Task RequestTargetResolverReturningNonOriginForm_IsRejectedAsInvalidRequestTarget(TestHostKind kind, string? resolvedTarget)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureOptions = options => options.RequestTargetResolver = _ => resolvedTarget! },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/inspect/orders?id=5", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequestTargetResolverThrowing_DoesNotAuthenticateTheRequest(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var hits = new EndpointHits();
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureOptions = options => options.RequestTargetResolver = _ => throw new InvalidOperationException("Resolver failure."),
                ConfigureEndpoints = endpoints => MapAdminEndpoint(endpoints, hits),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        HttpStatusCode status;
        try
        {
            using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync(AdminPath, ct);
            status = response.StatusCode;
        }
        catch (HttpRequestException)
        {
            status = HttpStatusCode.InternalServerError; // The TestServer surfaces unhandled server exceptions to the caller.
        }
        catch (InvalidOperationException)
        {
            status = HttpStatusCode.InternalServerError;
        }

        Assert.Equal(HttpStatusCode.InternalServerError, status);
        Assert.Equal(0, hits.Count);
    }

    private static async Task<CapturedRequest> CaptureSignedGetAsync(SafetalkServer server, string pathAndQuery, CancellationToken cancellationToken)
    {
        var capture = new RequestCapture();
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture, forward: false) });
        using HttpResponseMessage notSent = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync(pathAndQuery, cancellationToken);
        Assert.Equal(HttpStatusCode.Accepted, notSent.StatusCode);
        return Assert.Single(capture.Requests);
    }

    private static ServerSetup AdminEndpointSetup(EndpointHits hits) => new()
    {
        ConfigureEndpoints = endpoints =>
        {
            MapAdminEndpoint(endpoints, hits);
            endpoints.MapGet("/public/echo-query", (HttpContext context) => "query=" + context.Request.QueryString.Value).SkipHmacValidation();
        },
    };

    private static void MapAdminEndpoint(IEndpointRouteBuilder endpoints, EndpointHits hits)
        => endpoints.MapGet(AdminPath, (HttpContext context) =>
        {
            hits.Add(context.Request.QueryString.Value ?? string.Empty);
            return "exported";
        });

    private sealed class EndpointHits
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> _queries = new();

        public int Count => _queries.Count;

        public IReadOnlyCollection<string> Queries => _queries;

        public void Add(string query) => _queries.Enqueue(query);
    }
}
