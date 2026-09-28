using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// <c>HmacSigningHandler -&gt; CapturingHandler</c> with a fake clock: the smallest pipeline that shows exactly what a
/// signed request looks like on the wire.
/// </summary>
internal sealed class SigningPipeline : IDisposable
{
    public const string DefaultClientId = "partner-a";
    public const string DefaultSecret = "c2FmZXRhbGstdGVzdC1zZWNyZXQtMzItYnl0ZXMhIQ==";

    /// <summary>
    /// 2026-09-21T14:46:40Z, a whole second.
    /// </summary>
    public static readonly DateTimeOffset StartTime = DateTimeOffset.FromUnixTimeSeconds(1_790_000_000);

    public SigningPipeline(
        HmacClientOptions? options = null,
        IHmacSignatureService? signatureService = null,
        ILogger<HmacSigningHandler>? logger = null)
    {
        Options = options ?? new HmacClientOptions { ClientId = DefaultClientId, Secret = DefaultSecret };
        Time = new FakeTimeProvider(StartTime);
        Transport = new CapturingHandler();
        Handler = new HmacSigningHandler(
            Options,
            signatureService ?? HmacSha256SignatureService.Instance,
            Time,
            logger ?? NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = Transport,
        };
        Invoker = new HttpMessageInvoker(Handler, disposeHandler: false);
    }

    public HmacClientOptions Options { get; }

    public FakeTimeProvider Time { get; }

    public CapturingHandler Transport { get; }

    public HmacSigningHandler Handler { get; }

    /// <summary>
    /// Sends requests straight into the handler (no <see cref="HttpClient"/> "already sent" bookkeeping).
    /// </summary>
    public HttpMessageInvoker Invoker { get; }

    public string Secret => Options.Secret;

    public HttpClient CreateClient(Uri? baseAddress = null) => new(Handler, disposeHandler: false) { BaseAddress = baseAddress };

    public async Task<CapturedRequest> SendAndCaptureAsync(HttpRequestMessage request)
    {
        using HttpResponseMessage response = await Invoker.SendAsync(request, TestContext.Current.CancellationToken);
        return Transport.LastRequest;
    }

    public async Task<CapturedRequest> PostAndCaptureAsync(HttpContent? content, string uri = "https://api.example.com/api/orders")
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = content };
        return await SendAndCaptureAsync(request);
    }

    public void Dispose()
    {
        Invoker.Dispose();
        Handler.Dispose();
        Transport.Dispose();
    }
}
