using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Appouse.Safetalk.IntegrationTests.Infrastructure;
using Appouse.Safetalk.Server;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.IntegrationTests;

/// <summary>
/// A man-in-the-middle (a handler placed after the signing handler) alters a correctly signed request in transit.
/// Every signed component — method, path, query, timestamp, client id and body — must be protected.
/// </summary>
public sealed class TamperingTests
{
    private const string SignedTarget = "/inspect/orders?id=5";

    private static readonly byte[] SignedBody = Encoding.UTF8.GetBytes("""{"productCode":"SKU-42","quantity":3,"price":"100.00"}""");

    public static TheoryData<TestHostKind, string> HostsAndTamperings
    {
        get
        {
            string[] tamperings =
            [
                "BodyByteFlipped",
                "BodyTruncated",
                "BodyExtended",
                "BodyRemoved",
                "QueryValueChanged",
                "QueryParameterAdded",
                "QueryRemoved",
                "PathChanged",
                "PathCaseChanged",
                "MethodChanged",
                "TimestampIncremented",
                "TimestampZeroPadded",
                "ClientIdSwappedToAnotherKnownClient",
            ];

            var data = new TheoryData<TestHostKind, string>();
            foreach (TestHostKind host in Enum.GetValues<TestHostKind>())
            {
                foreach (string tampering in tamperings)
                {
                    data.Add(host, tampering);
                }
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(HostsAndTamperings))]
    public async Task SignedRequestAlteredInTransit_IsRejected(TestHostKind kind, string tampering)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup { HandlerAfterSigning = () => new RequestMutatingHandler((request, token) => TamperAsync(request, tampering, token)) });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using HttpRequestMessage request = CreateSignedRequest();

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        response.AssertUnauthorized();
        Assert.Equal(HmacValidationFailure.InvalidSignature, server.LastFailure);
    }

    [Theory]
    [MemberData(nameof(TestHosts.All), MemberType = typeof(TestHosts))]
    public async Task ContentReplacedWithIdenticalBytesInTransit_IsAccepted(TestHostKind kind)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        await using SafetalkServer server = await SafetalkServer.StartAsync(kind, ct);
        await using ServiceProvider clientServices = TestClientFactory.Create(
            server,
            new ClientSetup
            {
                HandlerAfterSigning = () => new RequestMutatingHandler(async (request, token) =>
                    ReplaceContent(request, await request.Content!.ReadAsByteArrayAsync(token))),
            });
        SafetalkApiClient client = clientServices.GetRequiredService<SafetalkApiClient>();
        using HttpRequestMessage request = CreateSignedRequest();

        using HttpResponseMessage response = await client.SendAsync(request, ct);

        // Control for the tampering cases: re-wrapping the content in transit is harmless as long as the bytes match.
        RequestInfoResponse info = await response.ReadOkJsonAsync<RequestInfoResponse>(ct);
        Assert.Equal(SignedBody.Length, info.BodyLength);
    }

    private static HttpRequestMessage CreateSignedRequest()
    {
        var content = new ByteArrayContent(SignedBody);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return new HttpRequestMessage(HttpMethod.Post, new Uri(SignedTarget, UriKind.Relative)) { Content = content };
    }

    private static async Task TamperAsync(HttpRequestMessage request, string tampering, CancellationToken cancellationToken)
    {
        Uri uri = request.RequestUri!;
        switch (tampering)
        {
            case "BodyByteFlipped":
                byte[] flipped = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
                flipped[flipped.Length / 2] ^= 0x01;
                ReplaceContent(request, flipped);
                break;
            case "BodyTruncated":
                ReplaceContent(request, (await request.Content!.ReadAsByteArrayAsync(cancellationToken))[..^1]);
                break;
            case "BodyExtended":
                ReplaceContent(request, [.. await request.Content!.ReadAsByteArrayAsync(cancellationToken), (byte)' ']);
                break;
            case "BodyRemoved":
                request.Content = null;
                break;
            case "QueryValueChanged":
                request.RequestUri = new Uri(uri, "/inspect/orders?id=6");
                break;
            case "QueryParameterAdded":
                request.RequestUri = new Uri(uri, "/inspect/orders?id=5&admin=true");
                break;
            case "QueryRemoved":
                request.RequestUri = new Uri(uri, "/inspect/orders");
                break;
            case "PathChanged":
                request.RequestUri = new Uri(uri, "/inspect/invoices?id=5");
                break;
            case "PathCaseChanged":
                request.RequestUri = new Uri(uri, "/inspect/ORDERS?id=5");
                break;
            case "MethodChanged":
                request.Method = HttpMethod.Put;
                break;
            case "TimestampIncremented":
                long timestamp = long.Parse(request.Headers.GetValues(SafetalkHeaderNames.Timestamp).Single(), CultureInfo.InvariantCulture);
                ReplaceHeader(request, SafetalkHeaderNames.Timestamp, (timestamp + 1).ToString(CultureInfo.InvariantCulture));
                break;
            case "TimestampZeroPadded":
                ReplaceHeader(request, SafetalkHeaderNames.Timestamp, "0" + request.Headers.GetValues(SafetalkHeaderNames.Timestamp).Single());
                break;
            case "ClientIdSwappedToAnotherKnownClient":
                ReplaceHeader(request, SafetalkHeaderNames.ClientId, TestCredentials.OtherClientId);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(tampering), tampering, "Unknown tampering.");
        }
    }

    private static void ReplaceContent(HttpRequestMessage request, byte[] body)
    {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = request.Content?.Headers.ContentType;
        request.Content = content;
    }

    private static void ReplaceHeader(HttpRequestMessage request, string name, string value)
    {
        request.Headers.Remove(name);
        request.Headers.TryAddWithoutValidation(name, value);
    }
}
