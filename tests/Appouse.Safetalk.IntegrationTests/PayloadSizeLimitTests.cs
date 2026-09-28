using System.Net;
using System.Net.Http.Json;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// Bodies larger than <see cref="HmacServerOptions.MaxBodySize"/> are rejected with <c>413 Payload Too Large</c>,
/// whether the size is declared up front (Content-Length) or discovered while reading (chunked).
/// </summary>
public sealed class PayloadSizeLimitTests
{
    private const int Limit = 1024;

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ContentLengthAboveMaxBodySize_IsRejectedWith413(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, LimitedServer(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new ByteArrayContent(TestData.CreateBytes(Limit + 1));

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal(HmacValidationFailure.PayloadTooLarge, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ContentLengthEqualToMaxBodySize_IsAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, LimitedServer(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(Limit);
        using var content = new ByteArrayContent(payload);

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [InlineData(TestHostKind.TestServer, Limit + 1)]
    [InlineData(TestHostKind.Kestrel, Limit + 1)]
    [InlineData(TestHostKind.TestServer, 1024 * 1024)]
    [InlineData(TestHostKind.Kestrel, 1024 * 1024)]
    public async Task ChunkedBodyAboveMaxBodySize_IsRejectedWith413(TestHostKind kind, int size)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, LimitedServer(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using HttpRequestMessage request = CreateChunkedRequest(TestData.CreateBytes(size));

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(HmacValidationFailure.PayloadTooLarge, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ChunkedBodyEqualToMaxBodySize_IsAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, LimitedServer(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(Limit);
        using HttpRequestMessage request = CreateChunkedRequest(payload);

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Null(body.ContentLength);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task DefaultMaxBodySize_AcceptsExactlyFourMebibytes(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] payload = TestData.CreateBytes(HmacServerOptions.DefaultMaxBodySize, seed: 4);
        using var content = new ByteArrayContent(payload);

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        RawBodyResponse body = await response.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task DefaultMaxBodySize_RejectsOneByteMoreThanFourMebibytes(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new ByteArrayContent(TestData.CreateBytes(HmacServerOptions.DefaultMaxBodySize + 1));

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(HmacValidationFailure.PayloadTooLarge, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task WithProblemDetails_413IsWrittenAsProblemJson(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { UseProblemDetails = true, ConfigureOptions = options => options.MaxBodySize = Limit },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var content = new ByteArrayContent(TestData.CreateBytes(Limit * 2));

        using HttpResponseMessage response = await client.PostAsync("/api/raw", content, ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        ProblemDetails? problem = await response.Content.ReadFromJsonAsync<ProblemDetails>(ct);
        Assert.NotNull(problem);
        Assert.Equal(413, problem.Status);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task MaxBodySizeZero_AllowsBodylessRequestsOnly(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { ConfigureOptions = options => options.MaxBodySize = 0 },
            ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var emptyContent = new ByteArrayContent([]);
        using var oneByte = new ByteArrayContent([42]);

        using HttpResponseMessage get = await client.GetAsync("/api/whoami", ct);
        using HttpResponseMessage emptyPost = await client.PostAsync("/api/raw", emptyContent, ct);
        using HttpResponseMessage oneBytePost = await client.PostAsync("/api/raw", oneByte, ct);

        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal(HttpStatusCode.OK, emptyPost.StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oneBytePost.StatusCode);
    }

    /// <summary>
    /// The declared size is checked before the secret lookup, so an unknown and a known client get the same 413 and the
    /// response does not reveal whether the client exists (and the secret store is not hit for oversized requests).
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task DeclaredOversizedBody_IsRejectedWith413BeforeTheSecretLookup_ForKnownAndUnknownClients(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, LimitedServerWithLookupLog(lookups), ct);
        await using ServiceProvider unknownServices = TestClientFactory.Create(server, new ClientSetup { ClientId = "partner-unknown" });
        await using ServiceProvider knownServices = TestClientFactory.Create(server);
        using var unknownContent = new ByteArrayContent(TestData.CreateBytes(Limit * 4));
        using var knownContent = new ByteArrayContent(TestData.CreateBytes(Limit * 4));

        using HttpResponseMessage unknown = await unknownServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", unknownContent, ct);
        using HttpResponseMessage known = await knownServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", knownContent, ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, known.StatusCode);
        Assert.Empty(unknown.Headers.WwwAuthenticate);
        Assert.All(server.ValidationResults, result => Assert.Equal(HmacValidationFailure.PayloadTooLarge, result.Failure));
        Assert.Empty(lookups.Lookups);
    }

    /// <summary>
    /// Without a Content-Length the size is only discovered while reading, which happens after the secret lookup:
    /// an unknown client is rejected as such before its body is read.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ChunkedOversizedBodyFromUnknownClient_IsRejectedAsUnknownClientWithoutReadingTheBody(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var lookups = new SecretLookupLog();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, LimitedServerWithLookupLog(lookups), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { ClientId = "partner-unknown" });
        using HttpRequestMessage request = CreateChunkedRequest(TestData.CreateBytes(Limit * 4));

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().SendAsync(request, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.UnknownClient, server.LastFailure);
        Assert.Equal("partner-unknown", Assert.Single(lookups.Lookups).ClientId);
    }

    /// <summary>
    /// Freshness is checked before the size: an expired oversized request is a plain 401, not a 413.
    /// </summary>
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task DeclaredOversizedBodyWithExpiredTimestamp_IsRejectedAsTimestampOutOfRangeFirst(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, LimitedServer(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow.AddMinutes(-10)) });
        using var content = new ByteArrayContent(TestData.CreateBytes(Limit * 4));

        using HttpResponseMessage response = await clientServices.GetRequiredService<SafetalkApiClient>().PostAsync("/api/raw", content, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequestAfterRejectedOversizedBody_IsServedNormally(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, LimitedServer(), ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server);
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using var oversized = new ByteArrayContent(TestData.CreateBytes(Limit * 64));
        byte[] payload = TestData.CreateBytes(Limit / 2, seed: 8);
        using var small = new ByteArrayContent(payload);

        using HttpResponseMessage rejected = await client.PostAsync("/api/raw", oversized, ct);
        using HttpResponseMessage accepted = await client.PostAsync("/api/raw", small, ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, rejected.StatusCode);
        RawBodyResponse body = await accepted.ReadOkJsonAsync<RawBodyResponse>(ct);
        Assert.Equal(TestData.Sha256Hex(payload), body.Sha256);
    }

    private static ServerSetup LimitedServer() => new() { ConfigureOptions = options => options.MaxBodySize = Limit };

    private static ServerSetup LimitedServerWithLookupLog(SecretLookupLog lookups) => new()
    {
        ConfigureOptions = options => options.MaxBodySize = Limit,
        ConfigureHmac = hmac => hmac.AddSecretProvider<DatabaseSecretProvider>(),
        ConfigureServices = services =>
        {
            services.AddScoped<ClientSecretsDbContext>();
            services.AddSingleton(lookups);
        },
    };

    private static HttpRequestMessage CreateChunkedRequest(byte[] payload)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/raw", UriKind.Relative))
        {
            Content = new StreamContent(new NonSeekableReadStream(payload)),
        };
        request.Headers.TransferEncodingChunked = true;
        request.Content.Headers.ContentLength = null;
        return request;
    }
}
