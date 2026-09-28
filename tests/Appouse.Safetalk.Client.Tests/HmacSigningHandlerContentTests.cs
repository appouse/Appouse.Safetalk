using System.Net.Http.Json;
using System.Text;
using Appouse.Safetalk.Client.Tests.Infrastructure;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// For every kind of request content, the bytes that reach the transport must be exactly the bytes that were signed.
/// </summary>
public sealed class HmacSigningHandlerContentTests : IDisposable
{
    private static readonly string[] Tags = ["hot", "green"];

    private readonly SigningPipeline _pipeline = new();

    public void Dispose() => _pipeline.Dispose();

    [Fact]
    public async Task SendAsync_GetWithoutContent_SignsEmptyBody()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        Assert.Null(sent.Body);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, "GET", "/api/orders", sent.Timestamp, []), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_PostWithoutContent_SignsEmptyBody()
    {
        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(content: null);

        Assert.Null(sent.Body);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, "POST", "/api/orders", sent.Timestamp, []), sent.Signature);
    }

    [Fact]
    public async Task SendAsync_StringContent_SignsUtf8BodyAndKeepsContentType()
    {
        const string json = "{\"name\":\"Çay\",\"city\":\"İstanbul\",\"price\":\"€5\"}";

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StringContent(json, Encoding.UTF8, "application/json"));

        AssertSentBytesAreSignedBytes(sent, Encoding.UTF8.GetBytes(json));
        Assert.Equal("application/json; charset=utf-8", Assert.Single(sent.ContentHeaders["Content-Type"]));
    }

    [Fact]
    public async Task SendAsync_StringContentWithUtf16Encoding_SignsRawEncodedBytes()
    {
        const string text = "merhaba dünya";

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StringContent(text, Encoding.Unicode, "text/plain"));

        AssertSentBytesAreSignedBytes(sent, Encoding.Unicode.GetBytes(text));
    }

    [Fact]
    public async Task SendAsync_ByteArrayContentWithOffsetAndCount_SignsOnlyTheSlice()
    {
        byte[] buffer = CreatePayload(64);

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new ByteArrayContent(buffer, 10, 25));

        AssertSentBytesAreSignedBytes(sent, buffer.AsSpan(10, 25).ToArray());
    }

    [Fact]
    public async Task SendAsync_ByteArrayContentWithBinaryData_SignsEveryByteValue()
    {
        byte[] body = new byte[256];
        for (int i = 0; i < body.Length; i++)
        {
            body[i] = (byte)i;
        }

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new ByteArrayContent(body));

        AssertSentBytesAreSignedBytes(sent, body);
    }

    [Fact]
    public async Task SendAsync_FormUrlEncodedContent_SignsEncodedForm()
    {
        var form = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("name", "Ali Veli"),
            new KeyValuePair<string, string>("city", "İstanbul"),
            new KeyValuePair<string, string>("q", "a&b=c"),
        ]);

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(form);

        AssertSentBytesAreSignedBytes(sent, Encoding.ASCII.GetBytes("name=Ali+Veli&city=%C4%B0stanbul&q=a%26b%3Dc"));
    }

    [Fact]
    public async Task SendAsync_JsonContent_SignsSerializedJson()
    {
        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(JsonContent.Create(new { id = 5, name = "tea", tags = Tags }));

        AssertSentBytesAreSignedBytes(sent, Encoding.UTF8.GetBytes("{\"id\":5,\"name\":\"tea\",\"tags\":[\"hot\",\"green\"]}"));
    }

    [Fact]
    public async Task SendAsync_StreamContentOverNonSeekableStream_SendsIntactBodyThatWasSigned()
    {
        byte[] payload = CreatePayload(10_000);
        var source = new NonSeekableReadStream(payload, maxChunkSize: 333);

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StreamContent(source));

        AssertSentBytesAreSignedBytes(sent, payload);
        Assert.Equal(payload.Length, source.TotalBytesRead);
    }

    [Fact]
    public async Task SendAsync_StreamContentOverLargeNonSeekableStream_GrowsBufferAndSignsWholeBody()
    {
        byte[] payload = CreatePayload(1_048_576 + 17);
        var source = new NonSeekableReadStream(payload, maxChunkSize: 65_536);

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StreamContent(source));

        AssertSentBytesAreSignedBytes(sent, payload);
    }

    [Fact]
    public async Task SendAsync_StreamContentOverSeekableStream_SignsWholeStream()
    {
        byte[] payload = CreatePayload(4_096);

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StreamContent(new MemoryStream(payload)));

        AssertSentBytesAreSignedBytes(sent, payload);
    }

    [Fact]
    public async Task SendAsync_StreamContentOverSeekableStreamWithNonZeroPosition_SignsFromThatPosition()
    {
        byte[] payload = CreatePayload(100);
        var stream = new MemoryStream(payload) { Position = 30 };

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StreamContent(stream));

        AssertSentBytesAreSignedBytes(sent, payload.AsSpan(30).ToArray());
    }

    [Fact]
    public async Task SendAsync_MultipartFormDataContent_SignsExactMultipartBody()
    {
        byte[] file = CreatePayload(2_000);
        using var multipart = new MultipartFormDataContent("safetalk-boundary");
        multipart.Add(new StringContent("Ahmet Yılmaz"), "name");
        multipart.Add(new ByteArrayContent(file), "file", "invoice.pdf");
        multipart.Add(new StreamContent(new NonSeekableReadStream("streamed-part"u8.ToArray(), maxChunkSize: 4)), "notes");
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/uploads") { Content = multipart };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        AssertSentBytesAreSignedBytes(sent, expectedBody: null);
        string body = Encoding.UTF8.GetString(sent.BodyOrEmpty);
        Assert.Contains("--safetalk-boundary", body, StringComparison.Ordinal);
        Assert.Contains("Ahmet Yılmaz", body, StringComparison.Ordinal);
        Assert.Contains("streamed-part", body, StringComparison.Ordinal);
        Assert.True(sent.BodyOrEmpty.AsSpan().IndexOf(file) >= 0, "The file part was not sent intact.");
    }

    [Fact]
    public async Task SendAsync_ReadOnlyMemoryContent_SignsTheMemorySlice()
    {
        byte[] buffer = CreatePayload(500);

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new ReadOnlyMemoryContent(buffer.AsMemory(100, 250)));

        AssertSentBytesAreSignedBytes(sent, buffer.AsSpan(100, 250).ToArray());
    }

    [Fact]
    public async Task SendAsync_EmptyByteArrayContent_SignsEmptyBody()
    {
        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new ByteArrayContent([]));

        AssertSentBytesAreSignedBytes(sent, []);
    }

    [Fact]
    public async Task SendAsync_EmptyStringContent_SignsEmptyBody()
    {
        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StringContent(string.Empty));

        AssertSentBytesAreSignedBytes(sent, []);
    }

    [Fact]
    public async Task SendAsync_EmptyNonSeekableStreamContent_SignsEmptyBody()
    {
        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StreamContent(new NonSeekableReadStream([])));

        AssertSentBytesAreSignedBytes(sent, []);
    }

    [Fact]
    public async Task SendAsync_EmptyBody_SignatureEqualsSignatureOfRequestWithoutContent()
    {
        CapturedRequest withEmptyBody = await _pipeline.PostAndCaptureAsync(new ByteArrayContent([]));
        CapturedRequest withoutContent = await _pipeline.PostAndCaptureAsync(content: null);

        // "{METHOD}\n{PATH}\n{TIMESTAMP}\n" + "" — both requests produce the same canonical request.
        Assert.Equal(withoutContent.Signature, withEmptyBody.Signature);
    }

    [Fact]
    public async Task SendAsync_ContentWithNonRepeatableSerialization_SendsTheBytesThatWereSigned()
    {
        var content = new ChangingContent();

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(content);

        AssertSentBytesAreSignedBytes(sent, "{\"serialization\":1}"u8.ToArray());
        Assert.Equal(1, content.SerializationCount);
    }

    [Fact]
    public async Task SendAsync_StringContentSubclassWithCustomSerialization_SendsTheBytesThatWereSigned()
    {
        var content = new ChangingStringContent();

        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(content);

        AssertSentBytesAreSignedBytes(sent, "attempt-1"u8.ToArray());
        Assert.Equal(1, content.SerializationCount);
    }

    [Fact]
    public async Task SendAsync_GetWithBody_SignsBody()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/search") { Content = new StringContent("{\"q\":\"tea\"}") };

        CapturedRequest sent = await _pipeline.SendAndCaptureAsync(request);

        AssertSentBytesAreSignedBytes(sent, "{\"q\":\"tea\"}"u8.ToArray());
    }

    [Fact]
    public async Task SendAsync_BodyTamperedAfterSigning_NoLongerVerifies()
    {
        CapturedRequest sent = await _pipeline.PostAndCaptureAsync(new StringContent("{\"amount\":100}"));

        byte[] tampered = "{\"amount\":900}"u8.ToArray();
        Assert.False(HmacSha256SignatureService.Instance.VerifySignature(SigningPipeline.DefaultSecret, "POST", sent.PathAndQuery, sent.Timestamp, tampered, sent.Signature));
    }

    private static void AssertSentBytesAreSignedBytes(CapturedRequest sent, byte[]? expectedBody)
    {
        Assert.NotNull(sent.Body);

        if (expectedBody is not null)
        {
            Assert.Equal(expectedBody, sent.Body);
        }

        // The signature must be the HMAC over the exact bytes the transport serialized.
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature);

        // If a Content-Length is announced, it must describe the bytes that are actually sent.
        if (sent.ContentLength is long contentLength)
        {
            Assert.Equal(sent.Body.Length, contentLength);
        }
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)((i * 31) + (i / 251));
        }

        return payload;
    }
}
