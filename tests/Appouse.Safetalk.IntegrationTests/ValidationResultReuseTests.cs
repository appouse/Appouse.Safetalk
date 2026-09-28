using System.Net;
using System.Security.Claims;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The default <see cref="IHmacRequestValidator"/> remembers its result for the request: later callers (custom code,
/// the authentication scheme, the middleware) get the same answer without a second secret lookup or body read. Only the
/// middleware and the <c>AddHmac()</c> scheme attach the client to the request, after the registered validator
/// succeeded. The remembered result must never outlive its request.
/// </summary>
public sealed class ValidationResultReuseTests
{
    /// <summary>
    /// An endpoint behind the middleware validates again (for example a library helper): same success, no second
    /// secret lookup, no replay reported, and the body is still intact.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task CustomCallerAfterTheMiddleware_GetsTheSameSuccess_WithoutSecondLookupOrReplay(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, CreateServer(lookups, replayProtection: true), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        byte[] payload = TestData.CreateBytes(50_000, seed: 77);
        using var content = new ByteArrayContent(payload);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/reuse/revalidate", content, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal($"True|None|partner-a|partner-a|{TestData.Sha256Hex(payload)}", await response.Content.ReadAsStringAsync(ct));
        Assert.Single(lookups.Lookups);
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    /// <summary>
    /// <see cref="HmacEnforcementMode.MarkedEndpointsOnly"/>: the middleware leaves an unmarked endpoint alone, which
    /// validates on its own and acts on the returned result. The validator itself never marks the request as verified
    /// (round 4): only the middleware and the <c>AddHmac()</c> scheme do, after the <em>registered</em> validator
    /// succeeded, so a decorating validator can still reject it. <c>GetHmacClientId()</c> therefore stays
    /// <see langword="null"/> for on-demand callers, on success as on failure.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UnmarkedEndpointValidatingOnDemand_UsesTheReturnedResult_ClientIsNeverAttached(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, CreateServer(lookups, replayProtection: true, markedEndpointsOnly: true), ct);
        await using ServiceProvider partnerA = TestClientFactory.Create(server);
        await using ServiceProvider forger = TestClientFactory.Create(server, new ClientSetup { Secret = "not-the-shared-secret" });
        using var validContent = new ByteArrayContent([1, 2, 3]);
        using var forgedContent = new ByteArrayContent([1, 2, 3]);

        using HttpResponseMessage valid = await partnerA.GetRequiredService<SafetalkApiClient>().PostAsync("/reuse/revalidate", validContent, ct);
        using HttpResponseMessage forged = await forger.GetRequiredService<SafetalkApiClient>().PostAsync("/reuse/revalidate", forgedContent, ct);

        // "{succeeded}|{failure}|{result client}|{attached client}|{body sha}": the result carries the client, the
        // request does not.
        string sha = TestData.Sha256Hex([1, 2, 3]);
        Assert.Equal($"True|None|partner-a|none|{sha}", await valid.Content.ReadAsStringAsync(ct));
        Assert.Equal($"False|InvalidSignature|partner-a|none|{sha}", await forged.Content.ReadAsStringAsync(ct));
        Assert.Equal(2, lookups.Lookups.Count); // One per request, although each endpoint validated twice.
    }

    /// <summary>
    /// An on-demand success is not a verification the rest of the pipeline may rely on: the user stays anonymous, and
    /// the same request is still verified only once (no second lookup, no replay) when the <c>AddHmac()</c> scheme is
    /// asked afterwards, which then signs the client in.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task OnDemandSuccess_LeavesTheUserAnonymous_UntilTheSchemeAuthenticatesTheSameVerification(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        ServerSetup setup = CreateServer(lookups, replayProtection: true, markedEndpointsOnly: true);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureOptions = setup.ConfigureOptions,
                ConfigureHmac = setup.ConfigureHmac,
                ConfigureServices = services =>
                {
                    setup.ConfigureServices!(services);

                    // Registered, but not the default scheme: nothing authenticates the request until asked to.
                    services.AddAuthentication().AddHmac().AddHmac("HMAC-Secondary", configureOptions: null);
                },
                ConfigureEndpoints = endpoints => endpoints.MapGet("/reuse/on-demand-then-scheme", async (HttpContext context, IHmacRequestValidator validator, CancellationToken cancellationToken) =>
                {
                    HmacValidationResult result = await validator.ValidateAsync(context, cancellationToken);
                    string before = $"{result.Succeeded}|{context.GetHmacClientId() ?? "none"}|{context.User.Identity?.IsAuthenticated == true}";
                    AuthenticateResult authenticated = await context.AuthenticateAsync(HmacAuthenticationDefaults.AuthenticationScheme);
                    return $"{before}|{authenticated.Succeeded}|{authenticated.Principal?.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value}|{context.GetHmacClientId()}";
                }),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/reuse/on-demand-then-scheme", ct);

        Assert.Equal("True|none|False|True|partner-a|partner-a", await response.Content.ReadAsStringAsync(ct));
        Assert.Single(lookups.Lookups);
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    /// <summary>
    /// With the authentication scheme and the middleware both active, the request carries exactly one HMAC identity.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SchemeAndMiddleware_SignedRequest_CarriesExactlyOneHmacIdentity(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { AddHmacAuthenticationScheme = true, ConfigureHmac = hmac => hmac.AddReplayProtection(), ConfigureEndpoints = MapEndpoints },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().GetAsync("/reuse/identities", ct);

        Assert.Equal("1|partner-a", await response.Content.ReadAsStringAsync(ct));
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    /// <summary>
    /// Kestrel reuses per-connection objects (HTTP/1.1 keep-alive, pooled HTTP/2 streams). A verified request must not
    /// leave its remembered result or client behind for the next request on the same connection.
    /// </summary>
    [Theory]
    [InlineData(HttpProtocols.Http1)]
    [InlineData(HttpProtocols.Http2)]
    public async Task VerifiedRequest_DoesNotLeakItsResultToTheNextRequestOnTheSameConnection(HttpProtocols protocols)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        ServerSetup setup = CreateServer(lookups, replayProtection: true, markedEndpointsOnly: true);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            TestHostKind.Kestrel,
            new ServerSetup
            {
                Protocols = protocols,
                ConfigureOptions = setup.ConfigureOptions,
                ConfigureHmac = setup.ConfigureHmac,
                ConfigureServices = setup.ConfigureServices,
                ConfigureEndpoints = setup.ConfigureEndpoints,
            },
            ct);
        using var handler = new SocketsHttpHandler { MaxConnectionsPerServer = 1, AllowAutoRedirect = false, UseCookies = false };
        using var client = new HttpClient(handler, disposeHandler: false)
        {
            BaseAddress = server.BaseAddress,
            DefaultRequestVersion = protocols == HttpProtocols.Http2 ? HttpVersion.Version20 : HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        using HttpResponseMessage signed = await SendAsync(client, "/reuse/marked", signed: true, ct);
        Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
        Assert.Equal(protocols == HttpProtocols.Http2 ? HttpVersion.Version20 : HttpVersion.Version11, signed.Version);
        string[] first = (await signed.Content.ReadAsStringAsync(ct)).Split('|');
        using HttpResponseMessage unmarked = await SendAsync(client, "/reuse/unmarked", signed: false, ct);
        string[] second = (await unmarked.Content.ReadAsStringAsync(ct)).Split('|');
        using HttpResponseMessage marked = await SendAsync(client, "/reuse/marked", signed: false, ct);
        using HttpResponseMessage onDemand = await SendAsync(client, "/reuse/on-demand", signed: false, ct);
        string[] third = (await onDemand.Content.ReadAsStringAsync(ct)).Split('|');

        Assert.Equal(TestCredentials.ClientId, first[1]);
        Assert.Equal(first[0], second[0]); // Same connection.
        Assert.Equal(("none", "False"), (second[1], second[2]));
        marked.AssertUnauthorized();
        Assert.Equal(first[0], third[0]);
        Assert.Equal(("False", "MissingHeaders", "none"), (third[1], third[2], third[3]));
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string path, bool signed, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(path, UriKind.Relative))
        {
            // A hand-made message does not inherit the client's defaults.
            Version = client.DefaultRequestVersion,
            VersionPolicy = client.DefaultVersionPolicy,
        };
        if (signed)
        {
            foreach ((string name, string value) in ManualSigner.CreateHeaders("GET", path, []))
            {
                request.Headers.TryAddWithoutValidation(name, value);
            }
        }

        return await client.SendAsync(request, cancellationToken);
    }

    private static ServerSetup CreateServer(SecretLookupLog lookups, bool replayProtection, bool markedEndpointsOnly = false) => new()
    {
        ConfigureOptions = markedEndpointsOnly ? options => options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly : null,
        ConfigureHmac = hmac =>
        {
            hmac.AddSecretProvider<DatabaseSecretProvider>();
            if (replayProtection)
            {
                hmac.AddReplayProtection();
            }
        },
        ConfigureServices = services =>
        {
            services.AddScoped<ClientSecretsDbContext>();
            services.AddSingleton(lookups);
        },
        ConfigureEndpoints = MapEndpoints,
    };

    private static void MapEndpoints(IEndpointRouteBuilder endpoints)
    {
        // Validates (again), then reads the whole body: "{succeeded}|{failure}|{result client}|{attached client}|{body sha}".
        endpoints.MapPost("/reuse/revalidate", async (HttpContext context, IHmacRequestValidator validator, CancellationToken cancellationToken) =>
        {
            HmacValidationResult first = await validator.ValidateAsync(context, cancellationToken);
            HmacValidationResult again = await validator.ValidateAsync(context, cancellationToken);
            Assert.Equal(first, again);

            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body, cancellationToken);
            return $"{again.Succeeded}|{again.Failure}|{again.ClientId}|{context.GetHmacClientId() ?? "none"}|{TestData.Sha256Hex(body.ToArray())}";
        });

        endpoints.MapGet("/reuse/identities", (HttpContext context) =>
        {
            ClaimsIdentity[] hmac = [.. context.User.Identities.Where(identity => identity.AuthenticationType == HmacAuthenticationDefaults.AuthenticationType)];
            return $"{hmac.Length}|{context.GetHmacClientId()}";
        }).RequireAuthorization();

        endpoints.MapGet("/reuse/marked", (HttpContext context) => $"{context.Connection.Id}|{context.GetHmacClientId()}").RequireHmacValidation();
        endpoints.MapGet("/reuse/unmarked", (HttpContext context) =>
            $"{context.Connection.Id}|{context.GetHmacClientId() ?? "none"}|{context.User.Identity?.IsAuthenticated == true}");
        endpoints.MapGet("/reuse/on-demand", async (HttpContext context, IHmacRequestValidator validator, CancellationToken cancellationToken) =>
        {
            HmacValidationResult result = await validator.ValidateAsync(context, cancellationToken);
            return $"{context.Connection.Id}|{result.Succeeded}|{result.Failure}|{context.GetHmacClientId() ?? "none"}";
        });
    }
}
