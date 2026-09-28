using System.Text;
using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests;

public sealed class HmacSigningHandlerTests : IDisposable
{
    private readonly SigningPipeline _pipeline = new();

    public void Dispose() => _pipeline.Dispose();

    [Fact]
    public async Task SendAsync_GetRequest_AddsClientIdTimestampAndSignatureHeaders()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders?id=5");

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(SigningPipeline.DefaultClientId, sent.GetSingleHeader("X-Client-Id"));
        Assert.Equal(ReferenceSigner.UnixSeconds(SigningPipeline.StartTime), sent.GetSingleHeader("X-Timestamp"));
        Assert.Equal(
            ReferenceSigner.Sign(SigningPipeline.DefaultSecret, "GET", "/api/orders?id=5", "1790000000", []),
            sent.GetSingleHeader("X-Signature"));
    }

    [Fact]
    public async Task SendAsync_Signature_IsLowerCaseHexadecimalHmacSha256()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(64, sent.Signature.Length);
        Assert.All(sent.Signature, c => Assert.True(char.IsAsciiDigit(c) || c is >= 'a' and <= 'f', $"Unexpected character '{c}'."));
    }

    [Fact]
    public async Task SendAsync_PostWithBody_SignatureMatchesSpecificationExample()
    {
        // Worked example from the specification: "{HttpMethod}\n{RequestUri}\n{Timestamp}\n{Body}".
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders?id=5")
        {
            Content = new StringContent("{\"product\":\"tea\",\"quantity\":2}", Encoding.UTF8, "application/json"),
        };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        byte[] expectedCanonical = Encoding.UTF8.GetBytes("POST\n/api/orders?id=5\n1790000000\n{\"product\":\"tea\",\"quantity\":2}");
        Assert.Equal(expectedCanonical, ReferenceSigner.BuildCanonicalRequest("POST", sent.PathAndQuery, sent.Timestamp, sent.BodyOrEmpty));
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_SignedRequest_VerifiesWithCoreSignatureServiceAndOnlyWithTheRightSecret()
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, "https://api.example.com/api/orders/7")
        {
            Content = new StringContent("{\"status\":\"shipped\"}", Encoding.UTF8, "application/json"),
        };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        IHmacSignatureService verifier = HmacSha256SignatureService.Instance;
        Assert.True(verifier.VerifySignature(SigningPipeline.DefaultSecret, "PUT", sent.PathAndQuery, sent.Timestamp, sent.BodyOrEmpty, sent.Signature));
        Assert.False(verifier.VerifySignature("another-secret", "PUT", sent.PathAndQuery, sent.Timestamp, sent.BodyOrEmpty, sent.Signature));
        Assert.False(verifier.VerifySignature(SigningPipeline.DefaultSecret, "PUT", "/api/orders/8", sent.Timestamp, sent.BodyOrEmpty, sent.Signature));
    }

    [Fact]
    public async Task SendAsync_Timestamp_IsUnixSecondsOfTimeProviderTruncatingSubSecondPrecision()
    {
        _pipeline.Time.SetUtcNow(DateTimeOffset.FromUnixTimeMilliseconds(1_790_000_123_999));
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal("1790000123", sent.Timestamp);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, "GET", "/api/orders", "1790000123", []), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_TimeAdvancesBetweenRequests_EachRequestUsesCurrentTimestamp()
    {
        using var first = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");
        using var second = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        CapturedRequest firstSent = await _pipeline.SendAndCaptureAsync(first);
        _pipeline.Time.Advance(TimeSpan.FromMinutes(3));
        CapturedRequest secondSent = await _pipeline.SendAndCaptureAsync(second);

        Assert.Equal("1790000000", firstSent.Timestamp);
        Assert.Equal("1790000180", secondSent.Timestamp);
        Assert.NotEqual(firstSent.Signature, secondSent.Signature);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, secondSent), secondSent.Signature);
    }

    [Fact]
    public async Task SendAsync_TimeProviderWithLocalTimeZone_TimestampIsIndependentOfTimeZone()
    {
        var time = new FakeTimeProvider(SigningPipeline.StartTime);
        time.SetLocalTimeZone(TimeZoneInfo.CreateCustomTimeZone("UTC+03", TimeSpan.FromHours(3), "UTC+03", "UTC+03"));
        var transport = new CapturingHandler();
        using var handler = new HmacSigningHandler(_pipeline.Options, HmacSha256SignatureService.Instance, time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");

        using HttpResponseMessage response = await invoker.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal("1790000000", transport.SingleRequest.Timestamp);
    }

    [Fact]
    public async Task SendAsync_RequestAlreadyCarriesSafetalkHeaders_ReplacesThemWithSingleSignedValues()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");
        request.Headers.TryAddWithoutValidation("x-signature", "forged");
        request.Headers.TryAddWithoutValidation("X-SIGNATURE", "forged-again");
        request.Headers.TryAddWithoutValidation("x-timestamp", "1");
        request.Headers.TryAddWithoutValidation("X-Client-ID", "mallory");

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(SigningPipeline.DefaultClientId, sent.ClientId);
        Assert.Equal("1790000000", sent.Timestamp);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_SafetalkHeadersInHttpClientDefaultRequestHeaders_AreReplacedWithSignedValues()
    {
        using HttpClient client = _pipeline.CreateClient(new Uri("https://api.example.com/"));
        client.DefaultRequestHeaders.TryAddWithoutValidation("X-Client-Id", "impostor");
        client.DefaultRequestHeaders.TryAddWithoutValidation("X-Timestamp", "0");
        client.DefaultRequestHeaders.TryAddWithoutValidation("X-Signature", "0000");

        using HttpResponseMessage response = await client.GetAsync(new Uri("api/orders", UriKind.Relative), TestContext.Current.CancellationToken);

        CapturedRequest sent = _pipeline.Transport.SingleRequest;
        Assert.Equal(SigningPipeline.DefaultClientId, sent.ClientId);
        Assert.Equal("1790000000", sent.Timestamp);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_UnrelatedHeaders_ArePreserved()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");
        request.Headers.Add("X-Correlation-Id", "abc-123");
        request.Headers.Accept.ParseAdd("application/json");

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal("abc-123", sent.GetSingleHeader("X-Correlation-Id"));
        Assert.Equal("application/json", sent.GetSingleHeader("Accept"));
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    [InlineData("PURGE")]
    public async Task SendAsync_HttpMethod_IsSignedAsIs(string method)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), "https://api.example.com/api/resource");

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, method, "/api/resource", sent.Timestamp, []), sent.Signature);
    }

    [Theory]
    [InlineData("post", "POST")]
    [InlineData("Post", "POST")]
    [InlineData("pAtCh", "PATCH")]
    [InlineData("delete", "DELETE")]
    [InlineData("purge", "PURGE")]
    public async Task SendAsync_NonUpperCaseMethod_IsCanonicalizedToUpperCase(string method, string canonicalMethod)
    {
        var recorder = new RecordingSignatureService();
        using var pipeline = new SigningPipeline(signatureService: recorder);
        using var request = new HttpRequestMessage(new HttpMethod(method), "https://api.example.com/api/orders")
        {
            Content = new StringContent("{}"),
        };

        CapturedRequest sent = await pipeline.SendAndCaptureAsync(request);

        byte[] canonicalRequest = Assert.Single(recorder.CanonicalRequests);
        Assert.Equal(Encoding.UTF8.GetBytes(canonicalMethod + "\n/api/orders\n1790000000\n{}"), canonicalRequest);
        Assert.Equal(ReferenceSigner.BuildCanonicalRequest(canonicalMethod, sent.PathAndQuery, sent.Timestamp, sent.BodyOrEmpty), canonicalRequest);
    }

    [Fact]
    public async Task SendAsync_LowerCaseMethod_SignatureEqualsUpperCaseMethodSignature()
    {
        using var lower = new HttpRequestMessage(new HttpMethod("post"), "https://api.example.com/api/orders") { Content = new StringContent("x") };
        using var upper = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new StringContent("x") };

        CapturedRequest lowerSent = await _pipeline.SendAndCaptureAsync(lower);
        CapturedRequest upperSent = await _pipeline.SendAndCaptureAsync(upper);

        Assert.Equal(upperSent.Signature, lowerSent.Signature);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, "POST", "/api/orders", "1790000000", "x"u8), lowerSent.Signature);
    }

    [Fact]
    public async Task SendAsync_CustomSignatureService_ReceivesSecretAndExactCanonicalBytes()
    {
        var recorder = new RecordingSignatureService("custom-signature");
        using var pipeline = new SigningPipeline(signatureService: recorder);
        byte[] body = [0x00, 0x0A, 0xFF, 0x7B, 0x0D];
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/blobs?x=1") { Content = new ByteArrayContent(body) };

        CapturedRequest sent = await pipeline.SendAndCaptureAsync(request);

        Assert.Equal("custom-signature", sent.Signature);
        Assert.Equal(SigningPipeline.DefaultSecret, Assert.Single(recorder.Secrets));
        Assert.Equal(ReferenceSigner.BuildCanonicalRequest("POST", "/api/blobs?x=1", "1790000000", body), Assert.Single(recorder.CanonicalRequests));
    }

    [Fact]
    public async Task SendAsync_ClientIdWithSpacesAndSymbols_IsSentVerbatim()
    {
        const string clientId = "partner a/b:c~1";
        using var pipeline = new SigningPipeline(new HmacClientOptions { ClientId = clientId, Secret = "secret" });
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");

        CapturedRequest sent = await pipeline.SendAndCaptureAsync(request);

        Assert.Equal(clientId, sent.ClientId);
    }

    [Fact]
    public async Task SendAsync_NonAsciiSecret_UsesUtf8EncodedKey()
    {
        const string secret = "şifre-ğüçİö-€-🔐";
        using var pipeline = new SigningPipeline(new HmacClientOptions { ClientId = "partner-a", Secret = secret });
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        CapturedRequest sent = await pipeline.SendAndCaptureAsync(request);

        Assert.Equal(ReferenceSigner.Sign(secret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_SecretLongerThanStackallocThreshold_SignsCorrectly()
    {
        string secret = new string('k', 300) + "ç";
        using var pipeline = new SigningPipeline(new HmacClientOptions { ClientId = "partner-a", Secret = secret });
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new StringContent("{}") };

        CapturedRequest sent = await pipeline.SendAndCaptureAsync(request);

        Assert.Equal(ReferenceSigner.Sign(secret, sent), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_RelativeRequestUri_ThrowsInvalidOperationExceptionAndDoesNotSend()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/orders", UriKind.Relative));

        await Assert.ThrowsAsync<InvalidOperationException>(() => _pipeline.Invoker.SendAsync(request, TestContext.Current.CancellationToken));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.False(request.Headers.Contains("X-Signature"));
    }

    [Fact]
    public async Task SendAsync_NullRequestUri_ThrowsInvalidOperationExceptionAndDoesNotSend()
    {
        using var request = new HttpRequestMessage { Method = HttpMethod.Get };

        await Assert.ThrowsAsync<InvalidOperationException>(() => _pipeline.Invoker.SendAsync(request, TestContext.Current.CancellationToken));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
    }

    [Fact]
    public async Task SendAsync_HttpClientWithoutBaseAddressAndRelativeUri_ThrowsInvalidOperationException()
    {
        using HttpClient client = _pipeline.CreateClient();

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAsync(new Uri("api/orders", UriKind.Relative), TestContext.Current.CancellationToken));

        Assert.Equal(0, _pipeline.Transport.InvocationCount);
    }

    [Fact]
    public async Task SendAsync_ContentSerializationFails_PropagatesExceptionAndDoesNotSend()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new ThrowingContent() };

        Exception exception = await Assert.ThrowsAnyAsync<Exception>(() => _pipeline.Invoker.SendAsync(request, TestContext.Current.CancellationToken));

        Assert.True(exception is IOException or HttpRequestException, $"Unexpected exception {exception.GetType()}.");
        Assert.Equal(0, _pipeline.Transport.InvocationCount);
        Assert.False(request.Headers.Contains("X-Signature"));
    }

    [Fact]
    public async Task SendAsync_ReturnsResponseFromInnerHandler()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        using HttpResponseMessage response = await _pipeline.Invoker.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Same(request, response.RequestMessage);
        Assert.True(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task SendAsync_WithLogger_LogsDebugEventWithoutSecretOrSignature()
    {
        var logger = new ListLogger<HmacSigningHandler>();
        using var pipeline = new SigningPipeline(logger: logger);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders?id=5") { Content = new StringContent("{}") };

        CapturedRequest sent = await pipeline.SendAndCaptureAsync(request);

        LogEntry entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Debug, entry.Level);
        Assert.Equal(1, entry.EventId.Id);
        Assert.Contains("POST", entry.Message, StringComparison.Ordinal);
        Assert.Contains("/api/orders?id=5", entry.Message, StringComparison.Ordinal);
        Assert.Contains(SigningPipeline.DefaultClientId, entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(SigningPipeline.DefaultSecret, entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(sent.Signature, entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendAsync_ConcurrentRequestsThroughOneHandler_EachRequestIsSignedOverItsOwnBody()
    {
        using HttpClient client = _pipeline.CreateClient(new Uri("https://api.example.com/"));
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        await Task.WhenAll(Enumerable.Range(0, 64).Select(async i =>
        {
            using var content = new StringContent(new string((char)('a' + (i % 26)), 100 + (i * 37)));
            using HttpResponseMessage response = await client.PostAsync(new Uri($"api/items/{i}", UriKind.Relative), content, cancellationToken);
        }));

        IReadOnlyList<CapturedRequest> requests = _pipeline.Transport.Requests;
        Assert.Equal(64, requests.Count);
        Assert.All(requests, sent =>
        {
            int index = int.Parse(sent.PathAndQuery["/api/items/".Length..], System.Globalization.CultureInfo.InvariantCulture);
            Assert.Equal(100 + (index * 37), sent.BodyOrEmpty.Length);
            Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);
        });
    }

    [Fact]
    public async Task SendAsync_OptionsMonitorConstructor_ResolvesNamedOptionsOnEveryRequest()
    {
        var monitor = new MutableOptionsMonitor();
        monitor.Set("orders", new HmacClientOptions { ClientId = "orders-client", Secret = "secret-v1" });
        monitor.Set(Microsoft.Extensions.Options.Options.DefaultName, new HmacClientOptions { ClientId = "wrong-client", Secret = "wrong-secret" });
        var time = new FakeTimeProvider(SigningPipeline.StartTime);
        var transport = new CapturingHandler();
        using var handler = new HmacSigningHandler(monitor, "orders", HmacSha256SignatureService.Instance, time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        using var invoker = new HttpMessageInvoker(handler);

        using (var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders"))
        using (await invoker.SendAsync(request, TestContext.Current.CancellationToken))
        {
        }

        monitor.Set("orders", new HmacClientOptions { ClientId = "orders-client-rotated", Secret = "secret-v2" });
        using (var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders"))
        using (await invoker.SendAsync(request, TestContext.Current.CancellationToken))
        {
        }

        Assert.Equal(["orders", "orders"], monitor.RequestedNames);
        CapturedRequest first = transport.Requests[0];
        CapturedRequest second = transport.Requests[1];
        Assert.Equal("orders-client", first.ClientId);
        Assert.Equal(ReferenceSigner.Sign("secret-v1", first), first.Signature);
        Assert.Equal("orders-client-rotated", second.ClientId);
        Assert.Equal(ReferenceSigner.Sign("secret-v2", second), second.Signature);
    }
}
