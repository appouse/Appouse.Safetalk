using System.Net;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The client signs <see cref="Uri.PathAndQuery"/>; the server must arrive at exactly the same request target on
/// both hosts (raw target on Kestrel, rebuilt target on the TestServer).
/// </summary>
public sealed class RequestTargetTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task PercentEncodedUnicodePathAndQuery_IsVerifiedAndRoutedToUnicodeEndpoint(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/m%C3%BC%C5%9Fteri?q=a%20b&x=%2F", ct);

        CustomerQueryResponse customer = await response.ReadOkJsonAsync<CustomerQueryResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, customer.ClientId);
        Assert.Equal("/api/müşteri", customer.Path);
        Assert.Equal("a b", customer.Q);
        Assert.Equal("/", customer.X);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UnescapedUnicodeInRelativeUri_IsEscapedByUriAndVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/müşteri?q=çğ ış&x=Ü", ct);

        CustomerQueryResponse customer = await response.ReadOkJsonAsync<CustomerQueryResponse>(ct);
        Assert.Equal("çğ ış", customer.Q);
        Assert.Equal("Ü", customer.X);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task LowerCasePercentEncodingOfUnicode_IsNormalizedByUriAndVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/api/m%c3%bc%c5%9fteri?q=%c3%a7", ct);

        CustomerQueryResponse customer = await response.ReadOkJsonAsync<CustomerQueryResponse>(ct);
        Assert.Equal("ç", customer.Q);
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, "/inspect/files/a%2Fb.txt")]
    [InlineData(TestHostKind.Kestrel, "/inspect/files/a%2Fb.txt")]
    [InlineData(TestHostKind.TestServer, "/inspect/files/a%2fb.txt")]
    [InlineData(TestHostKind.Kestrel, "/inspect/files/a%2fb.txt")]
    public async Task EncodedSlashInPath_IsVerifiedAndNotTreatedAsSegmentSeparator(TestHostKind kind, string pathAndQuery)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync(pathAndQuery, ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal(pathAndQuery, info.Path);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReservedAndEncodedCharactersInQuery_AreSignedVerbatim(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        const string Query = "?a=%26%3D%2B&b=x+y&c=%25&d=&e=a%2fb&f=%C3%A7&g=@:!$'()*,;";

        using HttpResponseMessage response = await client.GetAsync("/inspect/query" + Query, ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal(Query, info.QueryString);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UnreservedAndSubDelimiterCharactersInPath_AreVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/inspect/a-b_c.d~e/f+g@h:i!j$k'l(m)n*o,p;q=r/%5Bs%5D/sp%20ace", ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("/inspect/a-b_c.d~e/f+g@h:i!j$k'l(m)n*o,p;q=r/[s]/sp ace", info.Path);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UsePathBase_ClientSignsFullPathIncludingBase_AndIsVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { PathBase = "/base" }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/base/inspect/orders?id=5", ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, info.ClientId);
        Assert.Equal("/base", info.PathBase);
        Assert.Equal("/inspect/orders", info.Path);
        Assert.Equal("?id=5", info.QueryString);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UsePathBase_UnicodePathBelowBase_IsVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { PathBase = "/base" }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/base/api/m%C3%BC%C5%9Fteri?q=%C3%BC", ct);

        CustomerQueryResponse customer = await response.ReadOkJsonAsync<CustomerQueryResponse>(ct);
        Assert.Equal("ü", customer.Q);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task UsePathBase_RequestSignedWithoutTheBase_IsRejected(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, new ServerSetup { PathBase = "/base" }, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                // A proxy that adds the base after the client signed "/inspect/orders".
                HandlerAfterSigning = () => new RequestMutatingHandler(request =>
                    request.RequestUri = new Uri(server.BaseAddress, "/base" + request.RequestUri!.PathAndQuery)),
            });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/inspect/orders", ct);

        response.AssertUnauthorized();
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task Fragment_IsNeitherSentNorSigned(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/inspect/doc?page=2#section-3", ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("?page=2", info.QueryString);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task DotSegments_AreRemovedBeforeSigning_AndVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();

        using HttpResponseMessage response = await client.GetAsync("/inspect/a/../b/./c", ct);

        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal("/inspect/b/c", info.Path);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task AbsoluteRequestUriWithoutBaseAddress_IsSignedAndVerified(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(server.BaseAddress, "/inspect/absolute?x=%2F"));

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
