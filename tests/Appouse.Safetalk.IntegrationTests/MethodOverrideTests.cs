using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// <c>X-HTTP-Method-Override</c> is not signed. A signed request carrying it is rejected unless
/// <c>UseHttpMethodOverride()</c> already applied it (the header then names the method being verified), and since
/// round 4 the verified method must also be accepted by the endpoint selected by routing. The form-field variant must
/// run after the middleware: a form consumed before validation is rejected as <see cref="HmacValidationFailure.BodyAlreadyConsumed"/>.
/// </summary>
public sealed class MethodOverrideTests
{
    private const string MethodOverrideHeader = "X-HTTP-Method-Override";
    private const string FormMethodField = "_method";
    private const string CorsPolicy = "partners";
    private const string PartnerOrigin = "https://partner.example";

    public static TheoryData<TestHostKind, string> ForeignOverrides => Combine("DELETE", "delete", "PUT", "GET", "PATCH", "POST2", "POS");

    public static TheoryData<TestHostKind, string> MatchingOverrides => Combine("POST", "post", "Post");

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SignedPost_WithMethodOverrideDelete_IsRejectedWith401_BeforeTheSecretLookup(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithDatabaseSecrets(lookups), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative))
        {
            Content = new ByteArrayContent(TestData.CreateBytes(64)),
        };
        request.Headers.TryAddWithoutValidation(MethodOverrideHeader, "DELETE");

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct);

        response.AssertUnauthorized();
        HmacValidationResult result = Assert.Single(server.ValidationResults);
        Assert.Equal((HmacValidationFailure.UnsignedMethodOverride, TestCredentials.ClientId), (result.Failure, result.ClientId));
        Assert.Empty(lookups.Lookups);
    }

    [Theory]
    [MemberData(nameof(ForeignOverrides))]
    public async Task SignedPost_WithMethodOverrideNamingAnotherMethod_IsRejected(TestHostKind kind, string overrideValue)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await SendSignedPostAsync(clientServices, overrideValue, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, server.LastFailure);
    }

    /// <summary>
    /// A header that names the verified method changes nothing and is accepted (method names compared case-insensitively).
    /// </summary>
    [Theory]
    [MemberData(nameof(MatchingOverrides))]
    public async Task SignedPost_WithMethodOverrideNamingTheSignedMethod_IsAccepted(TestHostKind kind, string overrideValue)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await SendSignedPostAsync(clientServices, overrideValue, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(("POST", TestCredentials.ClientId), (body.Method, body.ClientId));
    }

    /// <summary>
    /// The header repeated (or comma-combined by a proxy) with the signed method first must not slip through.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SignedPost_WithRepeatedMethodOverrideHeader_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative)) { Content = new ByteArrayContent([1, 2, 3]) };
        request.Headers.TryAddWithoutValidation(MethodOverrideHeader, ["POST", "DELETE"]);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, server.LastFailure);
    }

    /// <summary>
    /// A man-in-the-middle adds the header to a request that was signed without it.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MethodOverrideInjectedInTransit_IsRejected_AndTheOverridingHandlerNeverRuns(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigurePipelineAfterHmac = app => app.UseHttpMethodOverride() }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new RequestMutatingHandler(request => request.Headers.TryAddWithoutValidation(MethodOverrideHeader, "DELETE")) });
        using var content = new ByteArrayContent(TestData.CreateBytes(32));

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", content, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, server.LastFailure);
    }

    /// <summary>
    /// With <c>UseHttpMethodOverride()</c> placed after the HMAC middleware, the override would change the method after
    /// verification: the request is rejected although the partner signed it honestly.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseHttpMethodOverrideAfterTheMiddleware_SignedPostWithOverride_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigurePipelineAfterHmac = app => app.UseHttpMethodOverride() }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);

        using HttpResponseMessage response = await SendSignedPostAsync(clientServices, "DELETE", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, server.LastFailure);
    }

    /// <summary>
    /// The README order <c>UseHttpMethodOverride()</c> → <c>UseRouting()</c> → <c>UseHmacAuthentication()</c>: the
    /// override is applied before verification, so the partner must sign the overriding method. A request signed for
    /// that method is accepted and served as it; one signed for the wire method is not.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseHttpMethodOverrideBeforeRoutingAndTheMiddleware_OnlyTheOverridingMethodVerifies(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigurePipeline = app =>
                {
                    app.UseHttpMethodOverride();
                    app.UseRouting();
                },
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpClient partner = server.CreateUnsignedClient();
        byte[] payload = TestData.CreateBytes(100, seed: 5);
        using var overridden = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative)) { Content = new ByteArrayContent(payload) };
        overridden.Headers.TryAddWithoutValidation(MethodOverrideHeader, "DELETE");
        foreach ((string name, string value) in ManualSigner.CreateHeaders("DELETE", "/api/raw", payload))
        {
            overridden.Headers.TryAddWithoutValidation(name, value);
        }

        using HttpResponseMessage signedForDelete = await partner.SendAsync(overridden, ct);
        using HttpResponseMessage signedForPost = await SendSignedPostAsync(clientServices, "DELETE", ct);

        RawBodyResponse body = await signedForDelete.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(("DELETE", TestCredentials.ClientId, TestData.Sha256Hex(payload)), (body.Method, body.ClientId, body.Sha256));
        signedForPost.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    /// <summary>
    /// Round 4: with WebApplication's implicit routing, <c>UseHttpMethodOverride()</c> runs after the endpoint was
    /// selected for the wire method. A request signed for the overriding method would verify (the header then names the
    /// verified method), yet the handler selected for the wire method would run. The selected endpoint does not accept
    /// the verified method, so the request is rejected before the secret lookup, and neither handler runs.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseHttpMethodOverrideAfterImplicitRouting_SignedForTheOverridingMethod_IsRejected_AndNoHandlerRuns(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var handlers = new ConcurrentQueue<string>();
        var lookups = new SecretLookupLog();
        ServerSetup database = WithDatabaseSecrets(lookups);
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup
            {
                ConfigureHmac = database.ConfigureHmac,
                ConfigureServices = database.ConfigureServices,
                ConfigurePipeline = app => app.UseHttpMethodOverride(), // After WebApplication's implicit UseRouting().
                ConfigureEndpoints = endpoints => MapItems(endpoints, handlers),
            },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using HttpClient partner = server.CreateUnsignedClient();
        byte[] payload = TestData.CreateBytes(40, seed: 9);

        using HttpRequestMessage overridden = CreateOverriddenPost("/override/items/7", "DELETE", payload, signedMethod: "DELETE");
        using HttpResponseMessage signedForDelete = await partner.SendAsync(overridden, ct);
        using var signedForPost = new HttpRequestMessage(HttpMethod.Post, new Uri("/override/items/7", UriKind.Relative)) { Content = new ByteArrayContent(payload) };
        signedForPost.Headers.TryAddWithoutValidation(MethodOverrideHeader, "DELETE");
        using HttpResponseMessage signedForWireMethod = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(signedForPost, ct);

        signedForDelete.AssertUnauthorized();
        signedForWireMethod.AssertUnauthorized();
        Assert.Equal(2, server.ValidationResults.Count);
        Assert.All(server.ValidationResults, result => Assert.Equal(
            (HmacValidationFailure.UnsignedMethodOverride, TestCredentials.ClientId),
            (result.Failure, result.ClientId)));
        Assert.Empty(handlers);
        Assert.Empty(lookups.Lookups);
    }

    /// <summary>
    /// The same check for an MVC action: <c>[HttpPost]</c> contributes the method metadata of the controller endpoint.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseHttpMethodOverrideAfterImplicitRouting_MvcPostAction_SignedForTheOverridingMethod_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigurePipeline = app => app.UseHttpMethodOverride() }, ct);
        using HttpClient partner = server.CreateUnsignedClient();
        byte[] payload = """{"productCode":"SKU-1","quantity":1}"""u8.ToArray();
        using HttpRequestMessage request = CreateOverriddenPost("/api/controller/orders", "PUT", payload, signedMethod: "PUT");
        request.Content!.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        using HttpResponseMessage response = await partner.SendAsync(request, ct);

        Assert.Equal((HttpStatusCode.Unauthorized, string.Empty), (response.StatusCode, await response.Content.ReadAsStringAsync(ct)));
        Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, Assert.Single(server.ValidationResults).Failure);
    }

    /// <summary>
    /// Control for the check above: when the endpoint selected for the wire method also accepts the overriding method,
    /// the handler that runs is the one the partner signed for, so the request is accepted and served as that method.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UseHttpMethodOverrideAfterImplicitRouting_EndpointAcceptingBothMethods_ServesTheSignedMethod(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { ConfigurePipeline = app => app.UseHttpMethodOverride() }, ct);
        using HttpClient partner = server.CreateUnsignedClient();
        byte[] payload = TestData.CreateBytes(64, seed: 10);
        using HttpRequestMessage request = CreateOverriddenPost("/api/raw", "DELETE", payload, signedMethod: "DELETE");

        using HttpResponseMessage response = await partner.SendAsync(request, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(("DELETE", TestCredentials.ClientId, TestData.Sha256Hex(payload)), (body.Method, body.ClientId, body.Sha256));
    }

    /// <summary>
    /// The README guidance when HMAC is also the default authentication scheme: <c>UseHttpMethodOverride()</c> →
    /// <c>UseRouting()</c> → <c>UseAuthentication()</c> → <c>UseHmacAuthentication()</c> → <c>UseAuthorization()</c>.
    /// A partner signing the overriding method reaches the handler of that method, authorized by policy.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReadmeOrderWithHmacDefaultScheme_UseAuthenticationAfterTheOverride_ServesTheOverridingMethod(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var handlers = new ConcurrentQueue<string>();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithOverrideAndScheme(handlers, explicitUseAuthentication: true), ct);
        using HttpClient partner = server.CreateUnsignedClient();
        byte[] payload = TestData.CreateBytes(16, seed: 11);
        using HttpRequestMessage request = CreateOverriddenPost("/override/secured/5", "DELETE", payload, signedMethod: "DELETE");

        using HttpResponseMessage response = await partner.SendAsync(request, ct);

        Assert.Equal((HttpStatusCode.OK, "delete-secured:5:DELETE:partner-a"), (response.StatusCode, await response.Content.ReadAsStringAsync(ct)));
        Assert.Equal(["delete-secured"], handlers);
        Assert.NotEmpty(server.ValidationResults);
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    /// <summary>
    /// Why the README asks for the explicit <c>UseAuthentication()</c>: otherwise WebApplication authenticates before any
    /// user middleware, i.e. before the override is applied. The scheme sees the unsigned header naming another method,
    /// rejects the request, and the middleware reuses that result (fail closed; nothing runs).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReadmeOrderWithHmacDefaultScheme_ImplicitUseAuthentication_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var handlers = new ConcurrentQueue<string>();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithOverrideAndScheme(handlers, explicitUseAuthentication: false), ct);
        using HttpClient partner = server.CreateUnsignedClient();
        byte[] payload = TestData.CreateBytes(16, seed: 12);
        using HttpRequestMessage request = CreateOverriddenPost("/override/secured/5", "DELETE", payload, signedMethod: "DELETE");

        using HttpResponseMessage response = await partner.SendAsync(request, ct);

        response.AssertUnauthorized();
        Assert.NotEmpty(server.ValidationResults);
        Assert.All(server.ValidationResults, result => Assert.Equal(HmacValidationFailure.UnsignedMethodOverride, result.Failure));
        Assert.Empty(handlers);
    }

    /// <summary>
    /// Trying to break the endpoint method check through its CORS exception (OPTIONS is accepted for an endpoint that
    /// accepts CORS preflight requests). An attacker holding a partner's signed <c>OPTIONS</c> request re-sends it as a
    /// <c>POST</c> with <c>X-HTTP-Method-Override: OPTIONS</c>. Implicit routing selects the POST handler, the override
    /// turns the method into the signed one, and the request is no preflight (no <c>Origin</c>), so the CORS middleware
    /// lets it through, wherever <c>UseCors()</c> is placed. The POST handler must not run for a request the partner
    /// signed as OPTIONS.
    /// </summary>
    [Theory]
    [InlineData(TestHostKind.TestServer, false)]
    [InlineData(TestHostKind.TestServer, true)]
    [InlineData(TestHostKind.Kestrel, false)]
    [InlineData(TestHostKind.Kestrel, true)]
    public async Task UseHttpMethodOverrideAfterImplicitRouting_OptionsOverrideOnCorsEnabledPostEndpoint_IsRejected(TestHostKind kind, bool useCorsBeforeTheOverride)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var handlers = new ConcurrentQueue<string>();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithOverrideAndCors(handlers, useCorsBeforeTheOverride), ct);
        using HttpClient attacker = server.CreateUnsignedClient();
        byte[] payload = """{"amount":1000}"""u8.ToArray();
        using HttpRequestMessage request = CreateOverriddenPost("/override/cors", "OPTIONS", payload, signedMethod: "OPTIONS");

        using HttpResponseMessage response = await attacker.SendAsync(request, ct);

        // (status, served body, POST handler runs, validation outcome): the actual values are the evidence on failure.
        Assert.Equal(
            (HttpStatusCode.Unauthorized, string.Empty, 0, HmacValidationFailure.UnsignedMethodOverride),
            (response.StatusCode, await response.Content.ReadAsStringAsync(ct), handlers.Count, server.LastFailure));
        response.AssertUnauthorized();
    }

    /// <summary>
    /// Control for the CORS exception: a genuine, signed CORS preflight to a CORS-enabled POST endpoint is accepted and
    /// answered by the CORS middleware without running the POST handler.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SignedCorsPreflight_ToCorsEnabledPostEndpoint_IsAnsweredByTheCorsMiddleware(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var handlers = new ConcurrentQueue<string>();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithOverrideAndCors(handlers), ct);
        using HttpClient partner = server.CreateUnsignedClient();
        using var preflight = new HttpRequestMessage(HttpMethod.Options, new Uri("/override/cors", UriKind.Relative));
        preflight.Headers.TryAddWithoutValidation("Origin", PartnerOrigin);
        preflight.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");
        foreach ((string name, string value) in ManualSigner.CreateHeaders("OPTIONS", "/override/cors", []))
        {
            preflight.Headers.TryAddWithoutValidation(name, value);
        }

        using HttpResponseMessage response = await partner.SendAsync(preflight, ct);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(PartnerOrigin, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Empty(handlers);
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    /// <summary>
    /// Round 4: the form-field variant of <c>UseHttpMethodOverride()</c> in front of the middleware reads (consumes) the
    /// form before the signature can be verified. The request is rejected as <see cref="HmacValidationFailure.BodyAlreadyConsumed"/>
    /// instead of being verified against whatever is left of the body.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task FormFieldOverrideBeforeTheMiddleware_SignedForm_IsRejectedAsBodyAlreadyConsumed(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigurePipeline = app => app.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = FormMethodField }) },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var form = new FormUrlEncodedContent([new("note", "hello"), new("quantity", "3")]);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/form", form, ct);

        Assert.Equal((HttpStatusCode.Unauthorized, string.Empty), (response.StatusCode, await response.Content.ReadAsStringAsync(ct)));
        HmacValidationResult result = Assert.Single(server.ValidationResults);
        Assert.Equal((HmacValidationFailure.BodyAlreadyConsumed, TestCredentials.ClientId), (result.Failure, result.ClientId));
    }

    /// <summary>
    /// The attack the <see cref="HmacValidationFailure.BodyAlreadyConsumed"/> check closes: a signature over an empty
    /// body (for example a captured body-less POST) combined with an attacker's chunked form. The form is read and cached
    /// by the override middleware; re-reading the drained stream would yield zero bytes (and there is no
    /// <c>Content-Length</c> to compare with), so the empty-body signature would verify and the endpoint would process
    /// the attacker's cached form as the partner's.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task FormFieldOverrideBeforeTheMiddleware_ChunkedFormUnderAnEmptyBodySignature_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigurePipeline = app => app.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = FormMethodField }) },
            ct);
        using HttpClient attacker = server.CreateUnsignedClient();
        using var forgedForm = new StreamContent(new NonSeekableReadStream("note=attacker&quantity=1000"u8.ToArray())); // Unknown length: chunked.
        forgedForm.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/form", UriKind.Relative)) { Content = forgedForm };
        foreach ((string name, string value) in ManualSigner.CreateHeaders("POST", "/api/form", []))
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        using HttpResponseMessage response = await attacker.SendAsync(request, ct);

        Assert.DoesNotContain("attacker", await response.Content.ReadAsStringAsync(ct), StringComparison.Ordinal);
        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.BodyAlreadyConsumed, server.LastFailure);
    }

    /// <summary>
    /// No over-rejection: a form read before the middleware from a body that was made rewindable first
    /// (<c>EnableBuffering()</c>) is still verified against the original bytes, and the endpoint gets the cached form.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task FormReadBeforeTheMiddlewareFromABufferedBody_IsVerifiedAgainstTheOriginalBytes(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithBufferedFormReaderBeforeHmac(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        using var form = new FormUrlEncodedContent([new("note", "hello"), new("quantity", "3")]);

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/form", form, ct);

        FormEchoResponse echo = await response.ReadOkJsonAsync<FormEchoResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, echo.ClientId);
        Assert.Equal(("hello", "3"), (echo.Fields["note"], echo.Fields["quantity"]));
    }

    /// <summary>
    /// The empty-body-signature attack against a buffered form reader: the validator re-reads the buffered attacker
    /// bytes, so the signature does not match (fail closed without needing the consumed-body check).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task FormReadBeforeTheMiddlewareFromABufferedBody_ChunkedFormUnderAnEmptyBodySignature_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, WithBufferedFormReaderBeforeHmac(), ct);
        using HttpClient attacker = server.CreateUnsignedClient();
        using var forgedForm = new StreamContent(new NonSeekableReadStream("note=attacker&quantity=1000"u8.ToArray()));
        forgedForm.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/form", UriKind.Relative)) { Content = forgedForm };
        foreach ((string name, string value) in ManualSigner.CreateHeaders("POST", "/api/form", []))
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        using HttpResponseMessage response = await attacker.SendAsync(request, ct);

        Assert.DoesNotContain("attacker", await response.Content.ReadAsStringAsync(ct), StringComparison.Ordinal);
        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    /// <summary>
    /// The README order for the form-field variant: after <c>UseHmacAuthentication()</c>. The form (including the
    /// override field) is part of the signed body, the body stays readable, and the overriding method is served.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task FormFieldOverrideAfterTheMiddleware_SignedFormWithOverrideField_IsVerifiedAndServed(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigurePipelineAfterHmac = app => app.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = FormMethodField }) },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        byte[] formBytes = "_method=DELETE&note=hello"u8.ToArray();
        using var form = new ByteArrayContent(formBytes);
        form.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", form, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(("DELETE", TestCredentials.ClientId, TestData.Sha256Hex(formBytes)), (body.Method, body.ClientId, body.Sha256));
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    private static HttpRequestMessage CreateOverriddenPost(string path, string overrideMethod, byte[] payload, string signedMethod)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(path, UriKind.Relative)) { Content = new ByteArrayContent(payload) };
        request.Headers.TryAddWithoutValidation(MethodOverrideHeader, overrideMethod);
        foreach ((string name, string value) in ManualSigner.CreateHeaders(signedMethod, path, payload))
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        return request;
    }

    private static void MapItems(IEndpointRouteBuilder endpoints, ConcurrentQueue<string> handlers)
    {
        endpoints.MapPost("/override/items/{id:int}", (int id, HttpContext context) =>
        {
            handlers.Enqueue("post");
            return $"post:{id}:{context.Request.Method}:{context.GetHmacClientId()}";
        });
        endpoints.MapDelete("/override/items/{id:int}", (int id, HttpContext context) =>
        {
            handlers.Enqueue("delete");
            return $"delete:{id}:{context.Request.Method}:{context.GetHmacClientId()}";
        });
    }

    private static ServerSetup WithOverrideAndScheme(ConcurrentQueue<string> handlers, bool explicitUseAuthentication) => new()
    {
        AddHmacAuthenticationScheme = true,
        ConfigurePipeline = app =>
        {
            app.UseHttpMethodOverride();
            app.UseRouting();
            if (explicitUseAuthentication)
            {
                app.UseAuthentication();
            }
        },
        ConfigureEndpoints = endpoints =>
        {
            endpoints.MapPost("/override/secured/{id:int}", (int id, HttpContext context) =>
            {
                handlers.Enqueue("post-secured");
                return $"post-secured:{id}:{context.Request.Method}:{context.GetHmacClientId()}";
            }).RequireAuthorization(EchoEndpoints.PartnerAOnlyPolicy);
            endpoints.MapDelete("/override/secured/{id:int}", (int id, HttpContext context) =>
            {
                handlers.Enqueue("delete-secured");
                return $"delete-secured:{id}:{context.Request.Method}:{context.GetHmacClientId()}";
            }).RequireAuthorization(EchoEndpoints.PartnerAOnlyPolicy);
        },
    };

    private static ServerSetup WithBufferedFormReaderBeforeHmac() => new()
    {
        ConfigurePipeline = app => app.Use(async (HttpContext context, RequestDelegate next) =>
        {
            if (context.Request.HasFormContentType)
            {
                context.Request.EnableBuffering();
                _ = await context.Request.ReadFormAsync(context.RequestAborted);
            }

            await next(context);
        }),
    };

    private static ServerSetup WithOverrideAndCors(ConcurrentQueue<string> handlers, bool useCorsBeforeTheOverride = false) => new()
    {
        ConfigureServices = services => services.AddCors(options => options.AddPolicy(
            CorsPolicy,
            policy => policy.WithOrigins(PartnerOrigin).AllowAnyMethod().AllowAnyHeader())),
        ConfigurePipeline = app =>
        {
            // Both run after WebApplication's implicit UseRouting().
            if (useCorsBeforeTheOverride)
            {
                app.UseCors();
            }

            app.UseHttpMethodOverride();
        },
        ConfigurePipelineAfterHmac = app =>
        {
            if (!useCorsBeforeTheOverride)
            {
                app.UseCors();
            }
        },
        ConfigureEndpoints = endpoints => endpoints.MapPost("/override/cors", async (HttpContext context, CancellationToken cancellationToken) =>
        {
            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body, cancellationToken);
            handlers.Enqueue("cors-post");
            return $"cors-post:{context.Request.Method}:{context.GetHmacClientId()}:{body.Length}";
        }).RequireCors(CorsPolicy),
    };

    private static async Task<HttpResponseMessage> SendSignedPostAsync(ServiceProvider clientServices, string overrideValue, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative)) { Content = new ByteArrayContent(TestData.CreateBytes(48)) };
        request.Headers.TryAddWithoutValidation(MethodOverrideHeader, overrideValue);

        return await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, cancellationToken);
    }

    private static ServerSetup WithDatabaseSecrets(SecretLookupLog lookups) => new()
    {
        ConfigureHmac = hmac => hmac.AddSecretProvider<DatabaseSecretProvider>(),
        ConfigureServices = services =>
        {
            services.AddScoped<ClientSecretsDbContext>();
            services.AddSingleton(lookups);
        },
    };

    private static TheoryData<TestHostKind, string> Combine(params string[] values)
    {
        var data = new TheoryData<TestHostKind, string>();
        foreach (TestHostKind kind in Enum.GetValues<TestHostKind>())
        {
            foreach (string value in values)
            {
                data.Add(kind, value);
            }
        }

        return data;
    }
}
