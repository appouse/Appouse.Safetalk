using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// Retries send the same <see cref="HttpRequestMessage"/> again; the handler must re-sign it cleanly.
/// </summary>
public sealed class HmacSigningHandlerRetryTests : IDisposable
{
    private readonly SigningPipeline _pipeline = new();

    public void Dispose() => _pipeline.Dispose();

    [Fact]
    public async Task SendAsync_SameRequestSentTwice_ReplacesHeadersAndUsesNewTimestamp()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders")
        {
            Content = new StringContent("{\"id\":1}"),
        };

        CapturedRequest first = await _pipeline.SendAndCaptureAsync(request);
        _pipeline.Time.Advance(TimeSpan.FromSeconds(42));
        CapturedRequest second = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal("1790000000", first.Timestamp);
        Assert.Equal("1790000042", second.Timestamp);
        Assert.Equal(SigningPipeline.DefaultClientId, second.ClientId);
        Assert.NotEqual(first.Signature, second.Signature);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, second), second.Signature);
        Assert.Single(request.Headers.GetValues("X-Signature"));
        Assert.Single(request.Headers.GetValues("X-Timestamp"));
        Assert.Single(request.Headers.GetValues("X-Client-Id"));
    }

    [Fact]
    public async Task SendAsync_NonSeekableStreamContentSentTwice_SendsIntactBodyOnBothAttempts()
    {
        byte[] payload = new byte[5_000];
        payload.AsSpan().Fill(0x5A);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/uploads")
        {
            Content = new StreamContent(new NonSeekableReadStream(payload, maxChunkSize: 700)),
        };

        CapturedRequest first = await _pipeline.SendAndCaptureAsync(request);
        _pipeline.Time.Advance(TimeSpan.FromSeconds(1));
        CapturedRequest second = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(payload, first.Body);
        Assert.Equal(payload, second.Body);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, first), first.Signature);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, second), second.Signature);
    }

    [Fact]
    public async Task SendAsync_RetryHandlerBeforeSigningHandler_ReSignsEveryAttempt()
    {
        var time = new FakeTimeProvider(SigningPipeline.StartTime);
        var transport = new CapturingHandler();
        var signing = new HmacSigningHandler(_pipeline.Options, HmacSha256SignatureService.Instance, time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        using var retry = new RetryOnceHandler(() => time.Advance(TimeSpan.FromSeconds(2))) { InnerHandler = signing };
        using var client = new HttpClient(retry);
        using var content = new StreamContent(new NonSeekableReadStream("{\"order\":1}"u8.ToArray(), maxChunkSize: 3));

        using HttpResponseMessage response = await client.PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Collection(
            transport.Requests,
            first =>
            {
                Assert.Equal("1790000000", first.Timestamp);
                Assert.Equal("{\"order\":1}"u8.ToArray(), first.Body);
                Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, first), first.Signature);
            },
            second =>
            {
                Assert.Equal("1790000002", second.Timestamp);
                Assert.Equal("{\"order\":1}"u8.ToArray(), second.Body);
                Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, second), second.Signature);
            });
    }

    [Fact]
    public async Task SendAsync_SameMessageResentWithinTheSameSecond_UsesStrictlyIncreasingTimestampsAndDistinctSignatures()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders") { Content = new StringContent("{\"id\":1}") };

        CapturedRequest first = await _pipeline.SendAndCaptureAsync(request);
        CapturedRequest second = await _pipeline.SendAndCaptureAsync(request);
        CapturedRequest third = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal(["1790000000", "1790000001", "1790000002"], new[] { first.Timestamp, second.Timestamp, third.Timestamp });
        Assert.Equal(3, new[] { first.Signature, second.Signature, third.Signature }.Distinct(StringComparer.Ordinal).Count());
        Assert.All(new[] { first, second, third }, sent => Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, sent), sent.Signature));
        Assert.Single(request.Headers.GetValues(CapturedRequest.TimestampHeader));

        // The per-message bump now lives in the shared signing state; the former long-valued key is gone.
        Assert.False(request.Options.TryGetValue(new HttpRequestOptionsKey<long>("Appouse.Safetalk.LastSignedTimestamp"), out _));
        Assert.True(request.Options.TryGetValue(new HttpRequestOptionsKey<HmacSigningState>("Appouse.Safetalk.SigningState"), out HmacSigningState? state));
        Assert.Same(state, HmacSigningState.GetOrAttach(request));
        Assert.Equal(1_790_000_003, state.NextTimestamp(1_790_000_000));
    }

    [Fact]
    public void Send_SameMessageResentSynchronouslyWithinTheSameSecond_UsesStrictlyIncreasingTimestamps()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using (_pipeline.Invoker.Send(request, cancellationToken))
        using (_pipeline.Invoker.Send(request, cancellationToken))
        {
        }

        Assert.Equal(["1790000000", "1790000001"], _pipeline.Transport.Requests.Select(r => r.Timestamp));
        Assert.NotEqual(_pipeline.Transport.Requests[0].Signature, _pipeline.Transport.Requests[1].Signature);
    }

    [Fact]
    public async Task SendAsync_ResentWithinSubSecondOfPreviousBump_KeepsIncreasingThenFollowsTheClockOnceItCatchesUp()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        CapturedRequest first = await _pipeline.SendAndCaptureAsync(request);
        _pipeline.Time.Advance(TimeSpan.FromMilliseconds(900));
        CapturedRequest second = await _pipeline.SendAndCaptureAsync(request);
        _pipeline.Time.Advance(TimeSpan.FromMilliseconds(200));
        CapturedRequest third = await _pipeline.SendAndCaptureAsync(request);
        _pipeline.Time.Advance(TimeSpan.FromSeconds(10));
        CapturedRequest fourth = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal("1790000000", first.Timestamp);
        Assert.Equal("1790000001", second.Timestamp);
        Assert.Equal("1790000002", third.Timestamp);
        Assert.Equal("1790000011", fourth.Timestamp);
    }

    [Fact]
    public async Task SendAsync_ClockMovesBackwardsBetweenAttempts_TimestampStillIncreases()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        CapturedRequest first = await _pipeline.SendAndCaptureAsync(request);
        _pipeline.Time.AdjustTime(SigningPipeline.StartTime.AddMinutes(-2));
        CapturedRequest second = await _pipeline.SendAndCaptureAsync(request);

        Assert.Equal("1790000000", first.Timestamp);
        Assert.Equal("1790000001", second.Timestamp);
        Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, second), second.Signature);
    }

    [Fact]
    public async Task SendAsync_DifferentMessagesWithinTheSameSecond_EachUsesTheCurrentTimestamp()
    {
        using var first = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");
        using var second = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/api/orders");

        CapturedRequest firstSent = await _pipeline.SendAndCaptureAsync(first);
        CapturedRequest secondSent = await _pipeline.SendAndCaptureAsync(second);

        // The bump is tracked per message: independent requests are not pushed into the future.
        Assert.Equal("1790000000", firstSent.Timestamp);
        Assert.Equal("1790000000", secondSent.Timestamp);
    }

    [Fact]
    public async Task SendAsync_RetryHandlerBeforeSigningHandlerWithoutClockAdvance_ReSignsEveryAttemptWithDistinctSignatures()
    {
        var transport = new CapturingHandler();
        var signing = new HmacSigningHandler(_pipeline.Options, HmacSha256SignatureService.Instance, _pipeline.Time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        using var retry = new CountingRetryHandler(4) { InnerHandler = signing };
        using var client = new HttpClient(retry);
        using var content = new StreamContent(new NonSeekableReadStream("{\"order\":7}"u8.ToArray(), maxChunkSize: 4));

        using HttpResponseMessage response = await client.PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(4, retry.AttemptCount);
        Assert.Equal(["1790000000", "1790000001", "1790000002", "1790000003"], transport.Requests.Select(r => r.Timestamp));
        Assert.Equal(4, transport.Requests.Select(r => r.Signature).Distinct(StringComparer.Ordinal).Count());
        Assert.All(transport.Requests, attempt =>
        {
            Assert.Equal("{\"order\":7}"u8.ToArray(), attempt.Body);
            Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, attempt), attempt.Signature);
        });
    }

    /// <summary>
    /// A hedging handler (such as the standard one of Microsoft.Extensions.Http.Resilience) sends a clone per attempt.
    /// In a manually composed pipeline, <see cref="HmacSigningStateHandler"/> placed outermost attaches the shared
    /// signing state before the clones are made (they copy the options by reference), so every clone signed within the
    /// same second still gets its own timestamp and signature.
    /// </summary>
    [Fact]
    public async Task SendAsync_HedgingHandlerCloningTheRequestPerAttempt_EachAttemptGetsADistinctSignature()
    {
        var transport = new CapturingHandler();
        var signing = new HmacSigningHandler(_pipeline.Options, HmacSha256SignatureService.Instance, _pipeline.Time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        var hedging = new CloningHedgingHandler(3) { InnerHandler = signing };
        using var state = new HmacSigningStateHandler { InnerHandler = hedging };
        using var client = new HttpClient(state);
        using var content = new StringContent("{\"order\":1}");

        using HttpResponseMessage response = await client.PostAsync(new Uri("https://api.example.com/api/orders"), content, TestContext.Current.CancellationToken);

        Assert.Equal(3, transport.Requests.Count);
        Assert.Equal(["1790000000", "1790000001", "1790000002"], transport.Requests.Select(r => r.Timestamp));
        Assert.Equal(3, transport.Requests.Select(r => r.Signature).Distinct(StringComparer.Ordinal).Count());
        Assert.All(transport.Requests, attempt =>
        {
            Assert.Equal("{\"order\":1}"u8.ToArray(), attempt.Body);
            Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, attempt), attempt.Signature);
        });
    }

    /// <summary>
    /// Documented limitation: when a cloning handler wraps a manually built <see cref="HmacSigningHandler"/> without
    /// <see cref="HmacSigningStateHandler"/> outermost, the state is attached to each clone separately, so clones signed
    /// within the same second carry the same timestamp and signature (the <c>IHttpClientFactory</c> integration, or the
    /// state handler, avoids this).
    /// </summary>
    [Fact]
    public async Task SendAsync_CloningHandlerWrappingAManualPipelineWithoutStateHandler_ClonesWithinTheSameSecondShareTheSignature()
    {
        var transport = new CapturingHandler();
        var signing = new HmacSigningHandler(_pipeline.Options, HmacSha256SignatureService.Instance, _pipeline.Time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        using var hedging = new CloningHedgingHandler(2) { InnerHandler = signing };
        using var client = new HttpClient(hedging);

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(["1790000000", "1790000000"], transport.Requests.Select(r => r.Timestamp));
        Assert.Equal(transport.Requests[0].Signature, transport.Requests[1].Signature);
    }

    [Fact]
    public async Task SendAsync_StateHandlerOutsideARetryHandler_RetriesOfTheSameMessageStillIncrease()
    {
        var transport = new CapturingHandler();
        var signing = new HmacSigningHandler(_pipeline.Options, HmacSha256SignatureService.Instance, _pipeline.Time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        var retry = new CountingRetryHandler(3) { InnerHandler = signing };
        using var state = new HmacSigningStateHandler { InnerHandler = retry };
        using var client = new HttpClient(state);

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(["1790000000", "1790000001", "1790000002"], transport.Requests.Select(r => r.Timestamp));
    }

    [Fact]
    public async Task SendAsync_RetryHandlerAfterSigningHandler_ReusesOriginalSignature()
    {
        var time = new FakeTimeProvider(SigningPipeline.StartTime);
        var transport = new CapturingHandler();
        var retry = new RetryOnceHandler(() => time.Advance(TimeSpan.FromSeconds(2))) { InnerHandler = transport };
        using var signing = new HmacSigningHandler(_pipeline.Options, HmacSha256SignatureService.Instance, time, NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = retry,
        };
        using var client = new HttpClient(signing);

        using HttpResponseMessage response = await client.GetAsync(new Uri("https://api.example.com/api/orders"), TestContext.Current.CancellationToken);

        Assert.Equal(2, transport.Requests.Count);
        Assert.All(transport.Requests, sent => Assert.Equal("1790000000", sent.Timestamp));
        Assert.Equal(transport.Requests[0].Signature, transport.Requests[1].Signature);
    }
}
