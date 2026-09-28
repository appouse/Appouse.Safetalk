using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacRequestValidatorHeaderTests
{
    private readonly RecordingSecretProvider _secretProvider = RecordingSecretProvider.ForTestCredentials();
    private readonly ValidatorHarness _harness;

    public HmacRequestValidatorHeaderTests()
    {
        _harness = new ValidatorHarness(_secretProvider);
    }

    [Fact]
    public async Task ValidateAsync_CorrectlySignedRequest_Succeeds()
    {
        HmacValidationResult result = await _harness.ValidateAsync(_harness.NewRequest().Build());

        Assert.True(result.Succeeded);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Equal(HmacValidationFailure.None, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_NoAuthenticationHeaders_ReturnsMissingHeadersWithoutClientId()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/api/orders";

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure);
        Assert.Null(result.ClientId);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Theory]
    [InlineData(SafetalkHeaderNames.ClientId)]
    [InlineData(SafetalkHeaderNames.Timestamp)]
    [InlineData(SafetalkHeaderNames.Signature)]
    public async Task ValidateAsync_HeaderMissing_ReturnsMissingHeaders(string headerName)
    {
        DefaultHttpContext context = _harness.NewRequest().Build();
        context.Request.Headers.Remove(headerName);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.False(result.Succeeded);
        Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Theory]
    [InlineData(SafetalkHeaderNames.ClientId)]
    [InlineData(SafetalkHeaderNames.Timestamp)]
    [InlineData(SafetalkHeaderNames.Signature)]
    public async Task ValidateAsync_HeaderEmpty_ReturnsMissingHeaders(string headerName)
    {
        DefaultHttpContext context = _harness.NewRequest().Build();
        context.Request.Headers[headerName] = new StringValues(string.Empty);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Theory]
    [InlineData(SafetalkHeaderNames.ClientId)]
    [InlineData(SafetalkHeaderNames.Timestamp)]
    [InlineData(SafetalkHeaderNames.Signature)]
    public async Task ValidateAsync_HeaderRepeatedWithSameValue_ReturnsMissingHeaders(string headerName)
    {
        DefaultHttpContext context = _harness.NewRequest().Build();
        string value = context.Request.Headers[headerName].ToString();
        context.Request.Headers.Append(headerName, value);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure);
        Assert.Empty(_secretProvider.RequestedClientIds);
    }

    [Fact]
    public async Task ValidateAsync_ClientIdRepeatedWithDifferentValues_ReturnsMissingHeaders()
    {
        DefaultHttpContext context = _harness.NewRequest().Build();
        context.Request.Headers[SafetalkHeaderNames.ClientId] = new StringValues([TestCredentials.ClientId, TestCredentials.OtherClientId]);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure);
        Assert.Null(result.ClientId);
    }

    [Theory]
    [InlineData(SafetalkHeaderNames.Timestamp)]
    [InlineData(SafetalkHeaderNames.Signature)]
    public async Task ValidateAsync_OtherHeaderMissing_ReportsClaimedClientId(string headerName)
    {
        DefaultHttpContext context = _harness.NewRequest().Build();
        context.Request.Headers.Remove(headerName);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.MissingHeaders, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
    }

    [Fact]
    public async Task ValidateAsync_HeaderNamesInDifferentCase_Succeeds()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        DefaultHttpContext context = request.Build();
        IHeaderDictionary headers = context.Request.Headers;
        foreach (string name in new[] { SafetalkHeaderNames.ClientId, SafetalkHeaderNames.Timestamp, SafetalkHeaderNames.Signature })
        {
            StringValues value = headers[name];
            headers.Remove(name);
            headers[name.ToLowerInvariant()] = value;
        }

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task ValidateAsync_CommaSeparatedClientIdInSingleHeader_IsLookedUpAsOneUnknownClient()
    {
        string combined = TestCredentials.ClientId + "," + TestCredentials.OtherClientId;
        SignedRequestBuilder request = _harness.NewRequest();
        request.ClientId = combined;

        HmacValidationResult result = await _harness.ValidateAsync(request.Build());

        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
        Assert.Equal([combined], _secretProvider.RequestedClientIds);
    }
}
