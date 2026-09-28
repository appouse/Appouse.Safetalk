using System.Net;
using System.Net.Http.Json;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Requests that cannot be authenticated are short-circuited with <c>401 Unauthorized</c> before any endpoint runs.
/// </summary>
public sealed class AuthenticationFailureTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task WrongSecret_IsRejectedWith401ChallengeAndEmptyBody(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { Secret = "not-the-shared-secret" });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new StringContent("""{"productCode":"SKU-42"}""", Encoding.UTF8, "application/json");

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        response.AssertUnauthorized();
        Assert.Empty(await response.Content.ReadAsByteArrayAsync(ct));
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
        Assert.Equal(TestCredentials.ClientId, server.ValidationResults.Last().ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SecretOfAnotherKnownClient_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { ClientId = TestCredentials.ClientId, Secret = TestCredentials.OtherSecret });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UnknownClient_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { ClientId = "partner-unknown" });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnknownClient, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClientIdWithDifferentCase_IsTreatedAsUnknownClient(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { ClientId = TestCredentials.ClientId.ToUpperInvariant() });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnknownClient, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UnsignedRequest_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/whoami", UriKind.Relative), ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.MissingHeaders, server.LastFailure);
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, "X-Client-Id")]
    [InlineData(TestHostKind.Kestrel, "X-Client-Id")]
    [InlineData(TestHostKind.TestServer, "X-Timestamp")]
    [InlineData(TestHostKind.Kestrel, "X-Timestamp")]
    [InlineData(TestHostKind.TestServer, "X-Signature")]
    [InlineData(TestHostKind.Kestrel, "X-Signature")]
    public async Task SigningHeaderRemovedInTransit_IsRejectedAsMissingHeaders(TestHostKind kind, string headerName)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new RequestMutatingHandler(request => request.Headers.Remove(headerName)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.MissingHeaders, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MalformedSignature_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new RequestMutatingHandler(request => ReplaceHeader(request, SafetalkHeaderNames.Signature, new string('z', 64))) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task TruncatedSignature_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                HandlerAfterSigning = () => new RequestMutatingHandler(request =>
                    ReplaceHeader(request, SafetalkHeaderNames.Signature, request.Headers.GetValues(SafetalkHeaderNames.Signature).Single()[..63])),
            });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UpperCaseHexSignature_IsAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                HandlerAfterSigning = () => new RequestMutatingHandler(request =>
                    ReplaceHeader(request, SafetalkHeaderNames.Signature, request.Headers.GetValues(SafetalkHeaderNames.Signature).Single().ToUpperInvariant())),
            });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse whoAmI = await client.GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, "not-a-number")]
    [InlineData(TestHostKind.Kestrel, "not-a-number")]
    [InlineData(TestHostKind.TestServer, "-1700000000")]
    [InlineData(TestHostKind.Kestrel, "-1700000000")]
    [InlineData(TestHostKind.TestServer, "1.7e9")]
    [InlineData(TestHostKind.Kestrel, "1.7e9")]
    public async Task NonNumericTimestamp_IsRejected(TestHostKind kind, string timestamp)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new RequestMutatingHandler(request => ReplaceHeader(request, SafetalkHeaderNames.Timestamp, timestamp)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidTimestamp, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RepeatedSignatureHeader_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                HandlerAfterSigning = () => new RequestMutatingHandler(request =>
                    request.Headers.TryAddWithoutValidation(SafetalkHeaderNames.Signature, request.Headers.GetValues(SafetalkHeaderNames.Signature).Single())),
            });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        // HttpClient folds the values into one comma separated line on the wire, the TestServer keeps two values;
        // either way the ambiguous header must not authenticate the request.
        response.AssertUnauthorized();
        Assert.Contains(server.LastFailure, new[] { HmacValidationFailure.MissingHeaders, HmacValidationFailure.InvalidSignature });
    }

    [Fact]
    public async Task Kestrel_RepeatedSignatureHeaderLines_AreRejectedAsAmbiguous()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(TestHostKind.Kestrel, ct);
        KeyValuePair<string, string>[] headers = ManualSigner.CreateHeaders("GET", "/api/whoami", []);
        KeyValuePair<string, string> signature = headers.Single(header => header.Key == SafetalkHeaderNames.Signature);

        HttpStatusCode status = await RawHttpClient.SendAsync(
            server.BaseAddress,
            "GET",
            "/api/whoami",
            [.. headers, signature],
            ReadOnlyMemory<byte>.Empty,
            ct);

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(HmacValidationFailure.MissingHeaders, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task WithProblemDetails_401IsWrittenAsProblemJsonWithoutDisclosingTheReason(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { UseProblemDetails = true }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { Secret = "not-the-shared-secret" });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/whoami", ct);

        response.AssertUnauthorized();
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        string json = await response.Content.ReadAsStringAsync(ct);
        ProblemDetails? problem = await response.Content.ReadFromJsonAsync<ProblemDetails>(ct);
        Assert.NotNull(problem);
        Assert.Equal(401, problem.Status);
        Assert.Equal("The request signature could not be verified.", problem.Detail);
        Assert.DoesNotContain(nameof(HmacValidationFailure.InvalidSignature), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(TestCredentials.ClientId, json, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SkipHmacValidation_MinimalApiEndpoint_IsReachableWithoutSignature(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/health", UriKind.Relative), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync(ct));
        Assert.Empty(server.ValidationResults);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SkipHmacValidation_ControllerAction_IsReachableWithoutSignature(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        using HttpClient unsigned = server.CreateUnsignedClient();

        using HttpResponseMessage response = await unsigned.GetAsync(new Uri("/api/controller/orders/public", UriKind.Relative), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(server.ValidationResults);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ProtectedControllerAction_WithoutSignature_IsRejectedBeforeModelBinding(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        using HttpClient unsigned = server.CreateUnsignedClient();
        using var content = JsonContent.Create(new OrderRequest("SKU-42", 1, null));

        using HttpResponseMessage response = await unsigned.PostAsync(new Uri("/api/controller/orders", UriKind.Relative), content, ct);

        response.AssertUnauthorized();
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task SignedRequestToSkippedEndpoint_IsNotValidatedAndCarriesNoClientIdentity(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/health", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(server.ValidationResults);
    }

    private static void ReplaceHeader(HttpRequestMessage request, string name, string value)
    {
        request.Headers.Remove(name);
        request.Headers.TryAddWithoutValidation(name, value);
    }
}
