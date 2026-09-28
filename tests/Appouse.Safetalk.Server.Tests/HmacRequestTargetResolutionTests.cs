using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRequestTargetResolutionTests
{
    private readonly RecordingSecretProvider _secretProvider = RecordingSecretProvider.ForTestCredentials();
    private readonly ValidatorHarness _harness;

    public HmacRequestTargetResolutionTests()
    {
        _harness = new ValidatorHarness(_secretProvider);
    }

    public static TheoryData<string> NonOriginFormTargets { get; } = new(
        "https://partner.example.com:8443/api/orders?id=5",
        "http://partner.example.com/api/orders",
        "http://partner.example.com",
        "HTTP://PARTNER.EXAMPLE.COM/api/orders",
        "*",
        "partner.example.com:443",
        "api/orders?id=5",
        "?id=5",
        " /api/orders");

    [Theory]
    [InlineData("/api/orders?id=5")]
    [InlineData("/api/orders?id=5&name=a%20b&tags=x%2Cy")]
    [InlineData("/api/%7Euser/./x/../y?q=%41")]
    [InlineData("//double//slashes")]
    [InlineData("/")]
    [InlineData("/api/users/%40me?x=%3A")]
    public void TryResolveRequestTarget_OriginFormRawTarget_ReturnsRawTargetVerbatim(string rawTarget)
    {
        DefaultHttpContext context = CreateContext(rawTarget);
        context.Request.Path = "/rewritten";
        context.Request.QueryString = new QueryString("?rewritten=1");

        bool resolved = HmacRequestValidator.TryResolveRequestTarget(context, new HmacServerOptions(), out string? target);

        Assert.True(resolved);
        Assert.Equal(rawTarget, target);
    }

    [Theory]
    [MemberData(nameof(NonOriginFormTargets))]
    public void TryResolveRequestTarget_NonOriginFormRawTarget_ReturnsFalse(string rawTarget)
    {
        DefaultHttpContext context = CreateContext(rawTarget);
        context.Request.Path = "/api/orders";

        bool resolved = HmacRequestValidator.TryResolveRequestTarget(context, new HmacServerOptions(), out _);

        Assert.False(resolved);
    }

    [Fact]
    public void TryResolveRequestTarget_EmptyRawTarget_FallsBackToEncodedPathBasePathAndQuery()
    {
        DefaultHttpContext context = CreateContext(string.Empty);
        context.Request.PathBase = "/base";
        context.Request.Path = "/api/order items";
        context.Request.QueryString = new QueryString("?id=5&name=a%20b");

        bool resolved = HmacRequestValidator.TryResolveRequestTarget(context, new HmacServerOptions(), out string? target);

        Assert.True(resolved);
        Assert.Equal("/base/api/order%20items?id=5&name=a%20b", target);
    }

    [Fact]
    public void TryResolveRequestTarget_EmptyRawTargetAndNoPath_ReturnsRoot()
    {
        DefaultHttpContext context = CreateContext(string.Empty);

        bool resolved = HmacRequestValidator.TryResolveRequestTarget(context, new HmacServerOptions(), out string? target);

        Assert.True(resolved);
        Assert.Equal("/", target);
    }

    [Fact]
    public void TryResolveRequestTarget_NoRequestFeatureRawTarget_FallsBackToRequestComponents()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/orders";
        context.Request.QueryString = new QueryString("?id=5");

        bool resolved = HmacRequestValidator.TryResolveRequestTarget(context, new HmacServerOptions(), out string? target);

        Assert.True(resolved);
        Assert.Equal("/api/orders?id=5", target);
    }

    [Theory]
    [InlineData("/gateway/api/orders?id=5")]
    [InlineData("/")]
    public void TryResolveRequestTarget_ResolverReturnsOriginForm_ReturnsItEvenWhenRawTargetIsAbsolute(string resolved)
    {
        DefaultHttpContext context = CreateContext("http://partner.example.com/api/orders");
        var options = new HmacServerOptions { RequestTargetResolver = _ => resolved };

        bool success = HmacRequestValidator.TryResolveRequestTarget(context, options, out string? target);

        Assert.True(success);
        Assert.Equal(resolved, target);
    }

    [Theory]
    [MemberData(nameof(NonOriginFormTargets))]
    public void TryResolveRequestTarget_ResolverReturnsNonOriginForm_ReturnsFalse(string resolved)
    {
        DefaultHttpContext context = CreateContext("/api/orders?id=5");
        var options = new HmacServerOptions { RequestTargetResolver = _ => resolved };

        Assert.False(HmacRequestValidator.TryResolveRequestTarget(context, options, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void TryResolveRequestTarget_ResolverReturnsNullOrEmpty_ReturnsFalse(string? resolved)
    {
        DefaultHttpContext context = CreateContext("/api/orders?id=5");
        var options = new HmacServerOptions { RequestTargetResolver = _ => resolved! };

        Assert.False(HmacRequestValidator.TryResolveRequestTarget(context, options, out _));
    }

    [Fact]
    public async Task ValidateAsync_RawTargetDiffersFromRewrittenPath_VerifiesAgainstRawTarget()
    {
        // The client signed what it sent on the wire; the application later rewrote the path (e.g. UsePathBase).
        SignedRequestBuilder request = _harness.NewRequest();
        request.SignedTarget = "/tenant-1/api/orders?id=5";
        request.RawTarget = "/tenant-1/api/orders?id=5";

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_SignatureOverRewrittenPathInsteadOfRawTarget_ReturnsInvalidSignature()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.RawTarget = "/tenant-1/api/orders?id=5";

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
    }

    [Theory]
    [InlineData("https://api.example.com/api/orders?id=5")]
    [InlineData("http://api.example.com/api/orders?id=5")]
    [InlineData("http://api.example.com/api/orders?id=5#fragment")]
    public async Task ValidateAsync_AbsoluteFormRawTarget_ReturnsInvalidRequestTargetWithoutSecretLookup(string rawTarget)
    {
        // Even a signature over the path and query of the absolute URI is refused: the server derives Path and
        // QueryString from absolute-form targets differently from Uri.PathAndQuery.
        SignedRequestBuilder request = _harness.NewRequest();
        request.RawTarget = rawTarget;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_AbsoluteFormRawTargetSignedVerbatim_ReturnsInvalidRequestTarget()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.RawTarget = "https://api.example.com/api/orders?id=5";
        request.SignedTarget = request.RawTarget;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_AsteriskFormRawTarget_ReturnsInvalidRequestTargetWithoutReadingBody()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Method = HttpMethods.Options;
        request.Path = string.Empty;
        request.Query = string.Empty;
        request.RawTarget = "*";
        request.SignedTarget = "*";
        DefaultHttpContext context = request.Build();
        context.Request.Body = new ThrowingReadStream();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, result.Failure);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_InvalidRequestTargetAndExpiredTimestamp_ReportsTimestampFirst()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.RawTarget = "http://api.example.com/api/orders?id=5";
        request.Timestamp = TestCredentials.FormatTimestamp(_harness.UnixNow - 301);

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.TimestampOutOfRange, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_InvalidRequestTargetAndOversizedBody_ReportsPayloadTooLargeFirst()
    {
        _harness.Options.MaxBodySize = 4;
        SignedRequestBuilder request = _harness.NewRequest();
        request.RawTarget = "http://api.example.com/api/orders?id=5";

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.PayloadTooLarge, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_InvalidRequestTargetForUnknownClient_ReportsInvalidRequestTarget()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = "partner-unknown";
        request.RawTarget = "*";

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, result.Failure);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_WithoutRawTarget_VerifiesAgainstEncodedPathAndQuery()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Path = "/api/order items";
        request.Query = "?note=hello%20world";
        request.SignedTarget = "/api/order%20items?note=hello%20world";

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_RequestTargetResolverConfigured_OverridesRawTarget()
    {
        // A reverse proxy stripped "/gateway" before forwarding; the resolver restores it.
        _harness.Options.RequestTargetResolver = context => "/gateway" + context.Request.Path + context.Request.QueryString;
        SignedRequestBuilder request = _harness.NewRequest();
        request.RawTarget = "/api/orders?id=5";
        request.SignedTarget = "/gateway/api/orders?id=5";

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_RequestTargetResolverConfigured_SignatureOverRawTargetIsRejected()
    {
        _harness.Options.RequestTargetResolver = context => "/gateway" + context.Request.Path + context.Request.QueryString;
        SignedRequestBuilder request = _harness.NewRequest();
        request.RawTarget = "/api/orders?id=5";

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.InvalidSignature, result.Failure);
    }

    [Theory]
    [MemberData(nameof(NonOriginFormTargets))]
    public async Task ValidateAsync_RequestTargetResolverReturnsNonOriginForm_ReturnsInvalidRequestTarget(string resolved)
    {
        _harness.Options.RequestTargetResolver = _ => resolved;
        SignedRequestBuilder request = _harness.NewRequest();
        request.SignedTarget = resolved;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, result.Failure);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_RequestTargetResolverReturnsNull_ReturnsInvalidRequestTarget()
    {
        _harness.Options.RequestTargetResolver = _ => null!;

        HmacValidationResult result = await _harness.ValidateAsync(_harness.NewRequest().Build());

        Assert.Equal(HmacValidationFailure.InvalidRequestTarget, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_RequestTargetResolver_ReceivesTheRequestContext()
    {
        HttpContext? observed = null;
        _harness.Options.RequestTargetResolver = context =>
        {
            observed = context;
            return "/api/orders?id=5";
        };
        DefaultHttpContext context = _harness.NewRequest().Build();

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
        Assert.Same(context, observed);
    }

    private static DefaultHttpContext CreateContext(string rawTarget)
    {
        var context = new DefaultHttpContext();
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = rawTarget;
        return context;
    }
}
