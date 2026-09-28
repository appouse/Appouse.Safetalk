using System.Globalization;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Client;

/// <summary>
/// A <see cref="DelegatingHandler"/> that signs every outgoing request with HMAC-SHA256.
/// </summary>
/// <remarks>
/// <para>For each request (asynchronous or synchronous send) the handler:</para>
/// <list type="number">
///   <item><description>generates the current Unix timestamp (seconds),</description></item>
///   <item><description>builds the canonical request <c>{METHOD}\n{PATH-AND-QUERY}\n{TIMESTAMP}\n{BODY}</c>, serializing the body once, straight into pooled memory,</description></item>
///   <item><description>computes the signature through <see cref="IHmacSignatureService"/>, and</description></item>
///   <item><description>sets the <c>X-Client-Id</c>, <c>X-Timestamp</c> and <c>X-Signature</c> headers, replacing stale values.</description></item>
/// </list>
/// <para>
/// Content that cannot be serialized twice (streams, JSON, multipart, ...) is replaced by the exact bytes that were
/// signed, so what is sent is always what was signed. Every attempt of a request that passes through the handler again
/// (a retry handler re-sending the message, or a hedging handler sending clones of it) is re-signed with a strictly
/// increasing timestamp, so attempts never collide with the server's replay protection. The <c>IHttpClientFactory</c>
/// integration places this handler closest to the network, and attaches the shared signing state before any
/// resilience handler clones the request. Retry and hedging handlers must therefore run <em>inside</em> that pipeline
/// (registered on the same <c>IHttpClientBuilder</c>, for example <c>AddStandardHedgingHandler()</c>). Attempts created
/// before a request enters it — an outer <see cref="DelegatingHandler"/>, Polly around <c>HttpClient.SendAsync</c>,
/// gRPC retries — are independent requests, and two of them signed within the same second carry the same signature.
/// </para>
/// </remarks>
public sealed partial class HmacSigningHandler : DelegatingHandler
{
    /// <summary>
    /// The largest body size hint trusted from <c>Content-Length</c>: the header may be stale (an explicit value on
    /// streamed content), so larger bodies grow the pooled buffer as bytes arrive instead of renting up front.
    /// </summary>
    private const int MaxInitialBodyBufferSize = 1024 * 1024;

    private readonly Func<HmacClientOptions> _optionsAccessor;
    private readonly IHmacSignatureService _signatureService;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new handler with fixed credentials, the default HMAC-SHA256 service and the system clock.
    /// </summary>
    /// <param name="options">The client credentials.</param>
    /// <exception cref="OptionsValidationException"><paramref name="options"/> is invalid.</exception>
    public HmacSigningHandler(HmacClientOptions options)
        : this(options, HmacSha256SignatureService.Instance, TimeProvider.System, NullLogger<HmacSigningHandler>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new handler with fixed credentials.
    /// </summary>
    /// <param name="options">The client credentials.</param>
    /// <param name="signatureService">The service that computes signatures.</param>
    /// <param name="timeProvider">The clock used to produce timestamps.</param>
    /// <param name="logger">The logger.</param>
    /// <exception cref="OptionsValidationException"><paramref name="options"/> is invalid.</exception>
    public HmacSigningHandler(
        HmacClientOptions options,
        IHmacSignatureService signatureService,
        TimeProvider timeProvider,
        ILogger<HmacSigningHandler> logger)
        : this(CreateStaticAccessor(options), signatureService, timeProvider, logger)
    {
    }

    /// <summary>
    /// Initializes a new handler that resolves named, reloadable options on every request.
    /// Used by the <c>IHttpClientFactory</c> integration.
    /// </summary>
    internal HmacSigningHandler(
        IOptionsMonitor<HmacClientOptions> optionsMonitor,
        string optionsName,
        IHmacSignatureService signatureService,
        TimeProvider timeProvider,
        ILogger<HmacSigningHandler> logger)
        : this(() => optionsMonitor.Get(optionsName), signatureService, timeProvider, logger)
    {
        IsManagedByFactory = true;
    }

    /// <summary>
    /// Gets a value indicating whether the handler was created by the <c>IHttpClientFactory</c> integration (and may
    /// therefore be replaced by it), as opposed to a handler the application added itself.
    /// </summary>
    internal bool IsManagedByFactory { get; }

    private HmacSigningHandler(
        Func<HmacClientOptions> optionsAccessor,
        IHmacSignatureService signatureService,
        TimeProvider timeProvider,
        ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(signatureService);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _optionsAccessor = optionsAccessor;
        _signatureService = signatureService;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        await SignAsync(request, async: true, cancellationToken).ConfigureAwait(false);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        // With async: false every I/O call is synchronous, so the operation has completed when it returns.
        ValueTask signing = SignAsync(request, async: false, cancellationToken);
        if (signing.IsCompleted)
        {
            signing.GetAwaiter().GetResult();
        }
        else
        {
            signing.AsTask().GetAwaiter().GetResult();
        }

        return base.Send(request, cancellationToken);
    }

    private async ValueTask SignAsync(HttpRequestMessage request, bool async, CancellationToken cancellationToken)
    {
        Uri requestUri = request.RequestUri is { IsAbsoluteUri: true } absoluteUri
            ? absoluteUri
            : throw new InvalidOperationException("The request URI must be absolute before it can be signed. Configure HttpClient.BaseAddress or use an absolute URI.");

        HmacClientOptions options = _optionsAccessor();
        string method = request.Method.Method;
        string pathAndQuery = requestUri.PathAndQuery;
        string timestamp = NextTimestamp(request).ToString(CultureInfo.InvariantCulture);

        HttpContent? content = request.Content;
        int bodyLengthHint = content?.Headers.ContentLength is > 0 and long length ? (int)Math.Min(length, MaxInitialBodyBufferSize) : 0;

        string signature;
        using (CanonicalRequestBuffer canonicalRequest = CanonicalRequestBuffer.Create(method, pathAndQuery, timestamp, bodyLengthHint))
        {
            if (content is not null)
            {
                int bodyStart = canonicalRequest.WrittenCount;
                var destination = new BufferWriterStream(canonicalRequest);
                if (async)
                {
                    await content.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    content.CopyTo(destination, context: null, cancellationToken);
                }

                if (!IsReplayable(content))
                {
                    request.Content = new SignedRequestContent(content, canonicalRequest.WrittenSpan[bodyStart..]);
                }
            }

            signature = _signatureService.ComputeSignature(options.Secret, canonicalRequest.WrittenSpan);
        }

        HttpRequestHeaders headers = request.Headers;
        SetHeader(headers, SafetalkHeaderNames.ClientId, options.ClientId);
        SetHeader(headers, SafetalkHeaderNames.Timestamp, timestamp);
        SetHeader(headers, SafetalkHeaderNames.Signature, signature);

        Log.RequestSigned(_logger, method, pathAndQuery, options.ClientId);
    }

    /// <summary>
    /// Returns the current Unix time, or one second after the timestamp last issued for this logical request
    /// (including its retry and hedging clones), whichever is later. Attempts therefore never reuse a signature.
    /// </summary>
    private long NextTimestamp(HttpRequestMessage request)
        => HmacSigningState.GetOrAttach(request).NextTimestamp(_timeProvider.GetUtcNow().ToUnixTimeSeconds());

    /// <summary>
    /// Returns whether the content serializes an in-memory buffer and can therefore be read any number of times.
    /// Exact type checks guard against subclasses with custom serialization.
    /// </summary>
    private static bool IsReplayable(HttpContent content)
    {
        Type contentType = content.GetType();
        return contentType == typeof(ByteArrayContent)
            || contentType == typeof(StringContent)
            || contentType == typeof(FormUrlEncodedContent)
            || contentType == typeof(ReadOnlyMemoryContent)
            || contentType == typeof(SignedRequestContent);
    }

    private static void SetHeader(HttpRequestHeaders headers, string name, string value)
    {
        headers.Remove(name);
        headers.TryAddWithoutValidation(name, value);
    }

    private static Func<HmacClientOptions> CreateStaticAccessor(HmacClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        ValidateOptionsResult result = HmacClientOptionsValidator.Instance.Validate(Options.DefaultName, options);
        if (result.Failed)
        {
            throw new OptionsValidationException(Options.DefaultName, typeof(HmacClientOptions), result.Failures);
        }

        return () => options;
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "Signed {Method} {PathAndQuery} request for client '{ClientId}'.")]
        public static partial void RequestSigned(ILogger logger, string method, string pathAndQuery, string clientId);
    }
}
