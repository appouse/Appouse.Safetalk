using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The real client package (<c>AddHmacClient</c> + <c>HmacSigningHandler</c>) talking to the real server package
/// (<c>AddHmacServer</c> + <c>UseHmacAuthentication</c>), on both the in-memory TestServer and a real Kestrel server.
/// </summary>
public sealed class EndToEndSigningTests
{
    private static readonly OrderRequest SampleOrder = new("SKU-42", 3, "Çok acil — lütfen öğleden önce teslim edin 🚚");

    public static TheoryData<TestHostKind, string> HostsAndContentKinds
    {
        get
        {
            string[] contentKinds = ["ByteArray", "String", "ReadOnlyMemory", "SeekableStream", "NonSeekableStream", "Json", "FormUrlEncoded", "Multipart"];
            var data = new TheoryData<TestHostKind, string>();
            foreach (TestHostKind host in Enum.GetValues<TestHostKind>())
            {
                foreach (string contentKind in contentKinds)
                {
                    data.Add(host, contentKind);
                }
            }

            return data;
        }
    }

    public static TheoryData<TestHostKind, string> HostsAndBodyMethods
    {
        get
        {
            var data = new TheoryData<TestHostKind, string>();
            foreach (TestHostKind host in Enum.GetValues<TestHostKind>())
            {
                data.Add(host, "PUT");
                data.Add(host, "PATCH");
                data.Add(host, "DELETE");
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Get_WithoutBody_AuthenticatesClientAndExposesIdentityToEndpoint(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        WhoAmIResponse whoAmI = await client.GetWhoAmIAsync(ct);

        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientId);
        Assert.True(whoAmI.IsAuthenticated);
        Assert.Equal(TestCredentials.ClientId, whoAmI.UserName);
        Assert.Equal(HmacAuthenticationDefaults.AuthenticationType, whoAmI.AuthenticationType);
        Assert.Equal(TestCredentials.ClientId, whoAmI.ClientIdClaim);
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PostJson_MinimalApiReadFromJsonAsync_ReadsBodyAfterVerification(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.PostAsJsonAsync("/api/orders", SampleOrder, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, echo.ClientId);
        Assert.Equal(SampleOrder, echo.Order);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PostJson_MinimalApiParameterBinding_ReadsBodyAfterVerification(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.PostAsJsonAsync("/api/orders/bound", SampleOrder, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, echo.ClientId);
        Assert.Equal(SampleOrder, echo.Order);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PostJson_ControllerModelBinding_ReadsBodyAfterVerification(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.PostAsJsonAsync("/api/controller/orders", SampleOrder, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, echo.ClientId);
        Assert.Equal(SampleOrder, echo.Order);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PostBinary_EndpointReadingRawBytes_SeesTheWholeBodyFromTheStart(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        // Larger than the default 30 KB in-memory threshold of EnableBuffering (the validator lifts it, see
        // LargeBodyBufferingTests), and read by the endpoint from the rewound buffer.
        byte[] payload = TestData.CreateBytes(96 * 1024);
        using var content = new ByteArrayContent(payload);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, body.ClientId);
        Assert.Equal(payload.Length, body.ContentLength);
        Assert.Equal(payload.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PostBinary_EndpointReadingThroughPipeReader_SeesTheWholeBodyFromTheStart(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        byte[] payload = TestData.CreateBytes(200_003, seed: 42);
        using var content = new ByteArrayContent(payload);

        using HttpResponseMessage response = await client.PostAsync("/api/raw/pipe", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(payload.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(HostsAndContentKinds))]
    public async Task Post_AnyHttpContentType_ServerReceivesExactlyTheSignedBytes(TestHostKind kind, string contentKind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using HttpContent content = CreateContent(contentKind);

        // An identical, never-sent instance gives the expected bytes: the signing handler serializes non-replayable
        // content (streams, JSON, multipart) exactly once, so the sent instance itself may not be readable again.
        using HttpContent reference = CreateContent(contentKind);
        byte[] sent = await reference.ReadAsByteArrayAsync(ct);

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.NotEmpty(sent);
        Assert.Equal(TestCredentials.ClientId, body.ClientId);
        Assert.Equal(sent.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(sent), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PostUnicodeText_SignatureCoversUtf8Bytes_AndBodyIsDecodedIntact(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        const string Text = "Müşteri: Çağrı Öztürk — İstanbul/Şişli, ğüşiöç ĞÜŞİÖÇ, 東京, 🚀";
        using var content = new StringContent(Text, Encoding.UTF8, "text/plain");

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        byte[] utf8 = Encoding.UTF8.GetBytes(Text);
        Assert.Equal(utf8.Length, body.Length);
        Assert.Equal(TestData.Sha256Hex(utf8), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PostFormUrlEncoded_FormIsParsedAfterVerification(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("name", "Çağrı Öztürk"),
            new KeyValuePair<string, string>("expression", "a+b=c&d"),
        ]);

        using HttpResponseMessage response = await client.PostAsync("/api/form", content, ct);

        FormEchoResponse form = await response.ReadOkJsonAsync<FormEchoResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, form.ClientId);
        Assert.Equal("Çağrı Öztürk", form.Fields["name"]);
        Assert.Equal("a+b=c&d", form.Fields["expression"]);
        Assert.Empty(form.Files);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PostMultipart_FieldsAndFilesAreParsedAfterVerification(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] file = TestData.CreateBytes(70_000, seed: 11);
        using MultipartFormDataContent content = CreateMultipart(file);

        using HttpResponseMessage response = await client.PostAsync("/api/form", content, ct);

        FormEchoResponse form = await response.ReadOkJsonAsync<FormEchoResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, form.ClientId);
        Assert.Equal("fatura-2026", form.Fields["reference"]);
        FormFileEcho uploaded = Assert.Single(form.Files);
        Assert.Equal("document", uploaded.Name);
        Assert.Equal("invoice.pdf", uploaded.FileName);
        Assert.Equal(file.Length, uploaded.Length);
        Assert.Equal(TestData.Sha256Hex(file), uploaded.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Post_WithoutContent_IsVerifiedWithEmptyBody(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content: null, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, body.ClientId);
        Assert.Equal(0, body.Length);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Post_WithEmptyContent_IsVerifiedWithEmptyBody(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new ByteArrayContent([]);

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(0, body.Length);
        Assert.Equal(TestData.Sha256Hex([]), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(HostsAndBodyMethods))]
    public async Task BodyCarryingMethods_AreSignedAndVerified(TestHostKind kind, string method)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = Encoding.UTF8.GetBytes("""{"op":"replace","path":"/quantity","value":7}""");
        using var request = new HttpRequestMessage(new HttpMethod(method), new Uri("/api/raw", UriKind.Relative))
        {
            Content = new ByteArrayContent(payload),
        };

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(method, body.Method);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Get_WithBody_BodyIsPartOfTheSignature(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/inspect/search", UriKind.Relative))
        {
            Content = new StringContent("""{"filter":"active"}""", Encoding.UTF8, "application/json"),
        };

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("GET", info.Method);
        Assert.Equal(19, info.BodyLength);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task LowerCaseHttpMethodOnClient_IsVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var request = new HttpRequestMessage(new HttpMethod("post"), new Uri("/inspect/orders?id=5", UriKind.Relative))
        {
            Content = new StringContent("""{"productCode":"SKU-42"}""", Encoding.UTF8, "application/json"),
        };

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        // SocketsHttpHandler normalizes known methods to "POST" on the wire, the TestServer passes "post" through;
        // either way both sides upper-case the method in the canonical request.
        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("POST", info.Method, ignoreCase: true);
        Assert.Equal(TestCredentials.ClientId, info.ClientId);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task CustomHttpMethod_IsVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var request = new HttpRequestMessage(new HttpMethod("PURGE"), new Uri("/inspect/cache/orders", UriKind.Relative));

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("PURGE", info.Method);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ValidRequestToUnknownRoute_PassesAuthenticationAndReturns404(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/does/not/exist", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.True(Assert.Single(server.ValidationResults).Succeeded);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ConcurrentRequests_ThroughOneSharedHandler_AreAllVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureHmac = hmac => hmac.AddReplayProtection() },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        RawBodyResponse[] results = await Task.WhenAll(Enumerable.Range(0, 32).Select(async i =>
        {
            byte[] payload = TestData.CreateBytes(1_000 + (i * 997), seed: (uint)(i + 1));
            using var content = new ByteArrayContent(payload);
            using HttpResponseMessage response = await client.PostAsync($"/api/raw?n={i}", content, ct);
            RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
            Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
            return body;
        }));

        Assert.Equal(32, results.Length);
        Assert.All(server.ValidationResults, result => Assert.True(result.Succeeded));
    }

    private static HttpContent CreateContent(string contentKind) => contentKind switch
    {
        "ByteArray" => new ByteArrayContent(TestData.CreateBytes(10_000)),
        "String" => new StringContent("Merhaba dünya — çğıöşü ÇĞİÖŞÜ 🚀", Encoding.UTF8, "text/plain"),
        "ReadOnlyMemory" => new ReadOnlyMemoryContent(TestData.CreateBytes(4_096, seed: 7)),
        "SeekableStream" => new StreamContent(new MemoryStream(TestData.CreateBytes(50_000, seed: 3))),
        "NonSeekableStream" => new StreamContent(new NonSeekableReadStream(TestData.CreateBytes(50_000, seed: 5))),
        "Json" => JsonContent.Create(SampleOrder),
        "FormUrlEncoded" => new FormUrlEncodedContent([new KeyValuePair<string, string>("a", "1 2"), new KeyValuePair<string, string>("b", "ç&=")]),
        "Multipart" => CreateMultipart(TestData.CreateBytes(8_000, seed: 9)),
        _ => throw new ArgumentOutOfRangeException(nameof(contentKind), contentKind, "Unknown content kind."),
    };

    private static MultipartFormDataContent CreateMultipart(byte[] file)
    {
        var content = new MultipartFormDataContent("safetalk-boundary");
        content.Add(new StringContent("fatura-2026"), "reference");
        var fileContent = new ByteArrayContent(file);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        content.Add(fileContent, "document", "invoice.pdf");
        return content;
    }
}
