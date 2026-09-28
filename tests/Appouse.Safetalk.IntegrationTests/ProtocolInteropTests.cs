using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// The wire protocol as documented, verified with an independent HMAC implementation (no library code), so that
/// partners on other platforms can interoperate with both the client and the server package.
/// </summary>
public sealed class ProtocolInteropTests
{
    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ClientSignature_EqualsIndependentHmacOverTheDocumentedCanonicalString(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        var capture = new RequestCapture();
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(server, new ClientSetup { HandlerAfterSigning = () => new RequestCaptureHandler(capture) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        byte[] body = Encoding.UTF8.GetBytes("""{"productCode":"SKU-42","note":"çğü"}""");
        using var content = new ByteArrayContent(body);
        long before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        using HttpResponseMessage response = await client.PostAsync("/inspect/m%C3%BC%C5%9Fteri?id=5&q=a%20b", content, ct);

        long after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        CapturedRequest signed = Assert.Single(capture.Requests);
        Assert.Equal(TestCredentials.ClientId, signed.ClientId);
        long timestamp = long.Parse(signed.Timestamp, NumberStyles.None, CultureInfo.InvariantCulture);
        Assert.InRange(timestamp, before, after);
        Assert.Matches("^[0-9a-f]{64}$", signed.Signature);
        string expected = IndependentSignature(
            TestCredentials.Secret,
            $"POST\n/inspect/m%C3%BC%C5%9Fteri?id=5&q=a%20b\n{signed.Timestamp}\n",
            body);
        Assert.Equal(expected, signed.Signature);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task RequestSignedWithoutTheLibrary_IsAcceptedByTheServer(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        using HttpClient partner = server.CreateUnsignedClient();
        byte[] body = Encoding.UTF8.GetBytes("""{"productCode":"SKU-42","quantity":3}""");
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/orders?id=5", UriKind.Relative))
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = new("application/json");
        request.Headers.Add("X-Client-Id", TestCredentials.ClientId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Signature", IndependentSignature(TestCredentials.Secret, $"POST\n/api/orders?id=5\n{timestamp}\n", body));

        using HttpResponseMessage response = await partner.SendAsync(request, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal(TestCredentials.ClientId, echo.ClientId);
        Assert.Equal(new OrderRequest("SKU-42", 3, null), echo.Order);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ReadmeExample_PostOrdersWithFixedTimestamp_IsAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(
            kind,
            new ServerSetup { TimeProvider = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)) },
            ct);
        using HttpClient partner = server.CreateUnsignedClient();
        const string Canonical = "POST\n/api/orders?id=5\n1700000000\n{\"productCode\":\"SKU-42\"}";
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/orders?id=5", UriKind.Relative))
        {
            Content = new StringContent("""{"productCode":"SKU-42"}""", Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Client-Id", TestCredentials.ClientId);
        request.Headers.Add("X-Timestamp", "1700000000");
        request.Headers.Add("X-Signature", IndependentSignature(TestCredentials.Secret, Canonical, []));

        using HttpResponseMessage response = await partner.SendAsync(request, ct);

        OrderEchoResponse echo = await response.ReadOkJsonAsync<OrderEchoResponse>(ct);
        Assert.Equal("SKU-42", echo.Order?.ProductCode);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ServerRejectsSignatureComputedWithCrlfSeparators(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        using HttpClient partner = server.CreateUnsignedClient();
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/whoami", UriKind.Relative));
        request.Headers.Add("X-Client-Id", TestCredentials.ClientId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Signature", IndependentSignature(TestCredentials.Secret, $"GET\r\n/api/whoami\r\n{timestamp}\r\n", []));

        using HttpResponseMessage response = await partner.SendAsync(request, ct);

        response.AssertUnauthorized();
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ServerRejectsBase64EncodedSignature(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        using HttpClient partner = server.CreateUnsignedClient();
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        byte[] mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(TestCredentials.Secret), Encoding.UTF8.GetBytes($"GET\n/api/whoami\n{timestamp}\n"));
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/whoami", UriKind.Relative));
        request.Headers.Add("X-Client-Id", TestCredentials.ClientId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Signature", Convert.ToBase64String(mac));

        using HttpResponseMessage response = await partner.SendAsync(request, ct);

        response.AssertUnauthorized();
    }

    /// <summary>
    /// HMAC-SHA256 with the UTF-8 secret as key over UTF-8(<paramref name="canonicalPrefix"/>) + <paramref name="body"/>,
    /// lower-case hexadecimal — computed with the BCL only.
    /// </summary>
    private static string IndependentSignature(string secret, string canonicalPrefix, byte[] body)
    {
        byte[] canonical = [.. Encoding.UTF8.GetBytes(canonicalPrefix), .. body];
        return Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), canonical)).ToLowerInvariant();
    }
}
