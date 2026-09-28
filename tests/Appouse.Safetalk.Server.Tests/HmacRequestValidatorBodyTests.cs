using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRequestValidatorBodyTests
{
    private readonly ValidatorHarness _harness = new();

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ValidateAsync_Success_LeavesBodyRewoundAndFullyReadable()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
        Stream body = context.Request.Body;
        Assert.True(body.CanSeek);
        Assert.Equal(0, body.Position);
        Assert.Equal(request.Body, await ReadToEndAsync(body));

        body.Position = 0;
        Assert.Equal(request.Body, await ReadToEndAsync(body));
    }

    [Fact]
    public async Task ValidateAsync_InvalidSignature_StillLeavesBodyRewound()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build(new string('0', HmacSha256SignatureService.SignatureHexLength));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
        Assert.Equal(0, context.Request.Body.Position);
        Assert.Equal(request.Body, await ReadToEndAsync(context.Request.Body));
    }

    [Fact]
    public async Task ValidateAsync_BodyAlreadyBufferedAndPartiallyRead_VerifiesWholeBodyAndRewinds()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();
        context.Request.EnableBuffering();
        await context.Request.Body.ReadExactlyAsync(new byte[5], CancellationToken);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
        Assert.Equal(0, context.Request.Body.Position);
        Assert.Equal(request.Body, await ReadToEndAsync(context.Request.Body));
    }

    [Fact]
    public async Task ValidateAsync_SeekableBodyPositionedAtEnd_VerifiesWholeBody()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();
        var seekable = new MemoryStream(request.Body);
        seekable.Seek(0, SeekOrigin.End);
        context.Request.Body = seekable;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
        Assert.Same(seekable, context.Request.Body);
        Assert.Equal(0, seekable.Position);
    }

    [Fact]
    public async Task ValidateAsync_EmptyBodyWithZeroContentLength_SucceedsWithoutReadingBody()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = [];
        DefaultHttpContext context = request.Build();
        context.Request.Body = new ThrowingReadStream();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_EmptyBodyWithoutContentLength_Succeeds()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Get;
        request.Body = [];
        request.SendContentLength = false;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_EmptyBodySignedButBodySent_ReturnsInvalidSignature()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        byte[] sentBody = request.Body;
        request.Body = [];
        string signature = request.Signature;
        request.Body = sentBody;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_RequestThatCannotHaveBody_SkipsBodyAndSucceeds()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Get;
        request.Body = [];
        request.SendContentLength = false;
        DefaultHttpContext context = request.Build();
        context.Request.Body = new ThrowingReadStream();
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new BodyDetectionFeature(canHaveBody: false));

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_BinaryBody_Succeeds()
    {
        byte[] body = new byte[1024];
        for (int i = 0; i < body.Length; i++)
        {
            body[i] = (byte)(i * 7);
        }

        body[0] = 0xC3; // Truncated UTF-8 sequence followed by NUL and 0xFF: not valid text.
        body[1] = 0x00;
        body[2] = 0xFF;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = body;
        DefaultHttpContext context = request.Build();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
        Assert.Equal(body, await ReadToEndAsync(context.Request.Body));
    }

    [Fact]
    public async Task ValidateAsync_BinaryBodyWithSingleBitFlipped_ReturnsInvalidSignature()
    {
        byte[] body = [0x00, 0x01, 0xFE, 0xFF, 0x80, 0x7F];
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = body;
        string signature = request.Signature;
        request.Body = [0x00, 0x01, 0xFE, 0xFF, 0x81, 0x7F];

        HmacValidationResult result = await _harness.ValidateAsync(request.Build(signature));

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateAsync_LargeBodyReadInSmallPieces_SucceedsAndRemainsReadable(bool sendContentLength)
    {
        // Larger than the validator's 16 KiB read chunk, its 8 KiB initial buffer and the default 30 KiB threshold of EnableBuffering.
        byte[] body = CreatePayload(256 * 1024);
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = body;
        request.SendContentLength = sendContentLength;
        request.MaxBytesPerRead = 1000;
        DefaultHttpContext context = request.Build();

        try
        {
            HmacValidationResult result = await _harness.ValidateAsync(context);

            Assert.True(result.Succeeded);
            Assert.Equal(0, context.Request.Body.Position);
            Assert.Equal(body, await ReadToEndAsync(context.Request.Body));
        }
        finally
        {
            await context.Request.Body.DisposeAsync();
        }
    }

    [Fact]
    public async Task ValidateAsync_ContentLengthAboveMaxBodySize_ReturnsPayloadTooLargeWithoutReadingBody()
    {
        _harness.Options.MaxBodySize = 1024;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(1025);
        DefaultHttpContext context = request.Build();
        context.Request.Body = new ThrowingReadStream();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.PayloadTooLarge, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
    }

    [Fact]
    public async Task ValidateAsync_ContentLengthEqualToMaxBodySize_Succeeds()
    {
        _harness.Options.MaxBodySize = 1024;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(1024);

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_ChunkedBodyAboveMaxBodySize_ReturnsPayloadTooLarge()
    {
        _harness.Options.MaxBodySize = 1024;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(1025);
        request.SendContentLength = false;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.PayloadTooLarge, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_ChunkedBodyEqualToMaxBodySize_Succeeds()
    {
        _harness.Options.MaxBodySize = 1024;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(1024);
        request.SendContentLength = false;
        request.MaxBytesPerRead = 100;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_ChunkedBodyAboveMaxBodySize_StopsReadingOneByteBeyondLimit()
    {
        _harness.Options.MaxBodySize = 1024;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(1024 * 1024);
        request.SendContentLength = false;
        DefaultHttpContext context = request.Build();
        var body = (NonSeekableReadStream)context.Request.Body;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.PayloadTooLarge, result.Failure);
        Assert.Equal(1025, body.BytesRead);
    }

    [Fact]
    public async Task ValidateAsync_ZeroMaxBodySizeWithEmptyBody_Succeeds()
    {
        _harness.Options.MaxBodySize = 0;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = [];

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateAsync_ZeroMaxBodySizeWithOneByteBody_ReturnsPayloadTooLarge(bool sendContentLength)
    {
        _harness.Options.MaxBodySize = 0;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = [0x42];
        request.SendContentLength = sendContentLength;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.PayloadTooLarge, result.Failure);
    }

    [Theory]
    [InlineData("partner-unknown")]
    [InlineData(TestCredentials.ClientId)]
    public async Task ValidateAsync_OversizedContentLength_ReturnsPayloadTooLargeBeforeSecretLookup(string clientId)
    {
        // The size is checked before the secret lookup, so a 413 does not reveal whether the client exists.
        var secretProvider = RecordingSecretProvider.ForTestCredentials();
        var harness = new ValidatorHarness(secretProvider);
        harness.Options.MaxBodySize = 16;
        SignedRequestBuilder request = harness.NewRequest();
        request.ClientId = clientId;
        request.Body = CreatePayload(1024);
        DefaultHttpContext context = request.Build();
        context.Request.Body = new ThrowingReadStream();

        HmacValidationResult result = await harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.PayloadTooLarge, result.Failure);
        Assert.Equal(clientId, result.ClientId);
        Assert.Empty(secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_UnknownAndKnownClientWithOversizedContentLength_AreIndistinguishable()
    {
        _harness.Options.MaxBodySize = 16;
        SignedRequestBuilder known = _harness.NewRequest();
        known.Body = CreatePayload(17);
        SignedRequestBuilder unknown = _harness.NewRequest();
        unknown.Body = CreatePayload(17);
        unknown.ClientId = "partner-unknown";
        unknown.Secret = "not-registered";

        HmacValidationResult knownResult = await _harness.ValidateAsync(known.Build());
        HmacValidationResult unknownResult = await _harness.ValidateAsync(unknown.Build());

        Assert.Equal(knownResult.Failure, unknownResult.Failure);
        Assert.Equal(HmacValidationFailure.PayloadTooLarge, unknownResult.Failure);
    }

    [Fact]
    public async Task ValidateAsync_UnknownClientWithOversizedChunkedBody_ReturnsUnknownClientWithoutReadingBody()
    {
        // Without Content-Length the size is only known by reading, which happens after the secret lookup.
        _harness.Options.MaxBodySize = 16;
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = "partner-unknown";
        request.Body = CreatePayload(1024);
        request.SendContentLength = false;
        DefaultHttpContext context = request.Build();
        context.Request.Body = new ThrowingReadStream();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_OversizedContentLengthWithExpiredTimestamp_ReportsTimestampFirst()
    {
        _harness.Options.MaxBodySize = 16;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(1024);
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow - 301);

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_OversizedContentLengthWithMissingHeader_ReportsMissingHeaders()
    {
        _harness.Options.MaxBodySize = 16;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(1024);
        DefaultHttpContext context = request.Build();
        context.Request.Headers.Remove(SafetalkHeaderNames.Signature);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_HugeContentLength_ReturnsPayloadTooLarge()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = long.MaxValue;
        context.Request.Body = new ThrowingReadStream();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.PayloadTooLarge, result.Failure);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(64 * 1024)]
    public async Task ValidateAsync_BodyShorterThanContentLength_ReturnsContentLengthMismatch(int missingBytes)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = request.Body.Length + missingBytes;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    public async Task ValidateAsync_BodyLongerThanContentLength_ReturnsContentLengthMismatchAndReadsOneBytePastIt(int extraBytes)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        byte[] declared = request.Body;
        request.Body = [.. declared, .. CreatePayload(extraBytes)];
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = declared.Length;
        var body = (NonSeekableReadStream)context.Request.Body;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
        Assert.Equal(declared.Length + 1, body.BytesRead);
    }

    [Fact]
    public async Task ValidateAsync_SignatureOverDeclaredPrefixButMoreBytesInBody_IsNotAccepted()
    {
        // Only the declared bytes were signed; the extra bytes would reach the application unverified.
        SignedRequestBuilder request = _harness.NewRequest();
        byte[] signedPrefix = request.Body;
        string signature = request.Signature;
        request.Body = [.. signedPrefix, .. ""","injected":true}"""u8.ToArray()];
        DefaultHttpContext context = request.Build(signature);
        context.Request.ContentLength = signedPrefix.Length;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_SignatureOverWholeBodyButSmallerContentLength_ReturnsContentLengthMismatch()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = request.Body.Length - 1;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
    }

    [Theory]
    [InlineData(-3)]
    [InlineData(3)]
    public async Task ValidateAsync_SeekableBodyWithWrongContentLength_ReturnsContentLengthMismatchAndRewinds(int delta)
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();
        var seekable = new MemoryStream(request.Body);
        context.Request.Body = seekable;
        context.Request.ContentLength = request.Body.Length + delta;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
        Assert.Same(seekable, context.Request.Body);
        Assert.Equal(0, seekable.Position);
    }

    [Fact]
    public async Task ValidateAsync_ContentLengthMismatch_LeavesBufferedBodyRewound()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = request.Body.Length + 10;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
        Assert.Equal(0, context.Request.Body.Position);
        Assert.Equal(request.Body, await ReadToEndAsync(context.Request.Body));
    }

    [Fact]
    public async Task ValidateAsync_BodyLargerThanMaxBodySizeButDeclaredWithinIt_ReturnsContentLengthMismatch()
    {
        _harness.Options.MaxBodySize = 64;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(10_000);
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = 32;
        var body = (NonSeekableReadStream)context.Request.Body;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
        Assert.Equal(33, body.BytesRead);
    }

    [Fact]
    public async Task ValidateAsync_ContentLengthMismatch_DoesNotConsumeReplayEntry()
    {
        var replayCache = new RecordingReplayCache();
        var harness = new ValidatorHarness(replayCache: replayCache);
        harness.Options.EnableReplayProtection = true;
        SignedRequestBuilder request = harness.NewRequest();
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = request.Body.Length + 1;

        HmacValidationResult result = await harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
        Assert.Empty(replayCache.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateAsync_OneMebibyteBody_IsBufferedInMemoryAndRewound(bool sendContentLength)
    {
        byte[] body = CreatePayload(1024 * 1024);
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = body;
        request.SendContentLength = sendContentLength;
        request.MaxBytesPerRead = 7_000;
        DefaultHttpContext context = request.Build();

        try
        {
            HmacValidationResult result = await _harness.ValidateAsync(context);

            Assert.True(result.Succeeded);
            FileBufferingReadStream buffered = Assert.IsType<FileBufferingReadStream>(context.Request.Body);
            Assert.True(buffered.InMemory);
            Assert.Null(buffered.TempFileName);
            Assert.Equal(0, buffered.Position);
            Assert.Equal(body, await ReadToEndAsync(buffered));
            Assert.True(buffered.InMemory);
            buffered.Position = 0;
            Assert.Equal(body, await ReadToEndAsync(buffered));
        }
        finally
        {
            await context.Request.Body.DisposeAsync();
        }
    }

    [Fact]
    public async Task ValidateAsync_BodyOfExactlyMaxBodySize_IsBufferedInMemory()
    {
        byte[] body = CreatePayload(HmacServerOptions.DefaultMaxBodySize);
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = body;
        request.SendContentLength = false;
        DefaultHttpContext context = request.Build();

        try
        {
            HmacValidationResult result = await _harness.ValidateAsync(context);

            Assert.True(result.Succeeded);
            FileBufferingReadStream buffered = Assert.IsType<FileBufferingReadStream>(context.Request.Body);
            Assert.True(buffered.InMemory);
            Assert.Equal(0, buffered.Position);
        }
        finally
        {
            await context.Request.Body.DisposeAsync();
        }
    }

    [Theory]
    [InlineData((long)HmacServerOptions.DefaultMaxBodySize, HmacServerOptions.DefaultMaxBodySize)]
    [InlineData(64L * 1024 * 1024, 128 * 1024 * 1024)]
    public async Task ValidateAsync_HugeDeclaredContentLengthWithTinyBody_FailsWithoutAllocatingForDeclaredSize(long declaredLength, int maxBodySize)
    {
        _harness.Options.MaxBodySize = maxBodySize;
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = CreatePayload(10);
        DefaultHttpContext context = request.Build();
        context.Request.ContentLength = declaredLength;

        long before = GC.GetAllocatedBytesForCurrentThread();
        ValueTask<HmacValidationResult> pending = _harness.Validator.ValidateAsync(context, CancellationToken);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(pending.IsCompleted, "The in-memory pipeline is expected to complete synchronously so that allocations are measured on this thread.");
        HmacValidationResult result = await pending;
        Assert.Equal(HmacValidationFailure.ContentLengthMismatch, result.Failure);
        Assert.True(allocated < 1024 * 1024, $"Validation allocated {allocated:N0} bytes for a 10 byte body declared as {declaredLength:N0} bytes.");
    }

    [Fact]
    public async Task ValidateAsync_LargeBody_StillVerifiesWhenInitialBufferMustGrowManyTimes()
    {
        byte[] body = CreatePayload(3 * 1024 * 1024 + 17);
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = body;
        request.MaxBytesPerRead = 65_536;
        DefaultHttpContext context = request.Build();

        try
        {
            HmacValidationResult result = await _harness.ValidateAsync(context);

            Assert.True(result.Succeeded);
        }
        finally
        {
            await context.Request.Body.DisposeAsync();
        }
    }

    [Fact]
    public async Task ValidateAsync_CancelledWhileReadingBody_ThrowsOperationCanceledException()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _harness.Validator.ValidateAsync(_harness.NewRequest().Build(), cancellation.Token).AsTask());
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)('a' + (i % 26));
        }

        return payload;
    }

    private static async Task<byte[]> ReadToEndAsync(Stream stream)
    {
        using var copy = new MemoryStream();
        await stream.CopyToAsync(copy, CancellationToken);
        return copy.ToArray();
    }

    private sealed class BodyDetectionFeature(bool canHaveBody) : IHttpRequestBodyDetectionFeature
    {
        public bool CanHaveBody { get; } = canHaveBody;
    }
}
