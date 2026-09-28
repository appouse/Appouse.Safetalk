using Microsoft.AspNetCore.Http;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacHttpContextExtensionsTests
{
    [Fact]
    public void GetHmacClientId_WithoutClientFeature_ReturnsNull()
    {
        var context = new DefaultHttpContext();

        Assert.Null(context.GetHmacClientId());
    }

    [Fact]
    public void GetHmacClientId_WithClientFeature_ReturnsClientId()
    {
        var context = new DefaultHttpContext();
        context.Features.Set<IHmacClientFeature>(new HmacClientFeature("partner-a"));

        Assert.Equal("partner-a", context.GetHmacClientId());
    }

    [Fact]
    public void GetHmacClientId_ForeignClientFeature_ReturnsItsClientId()
    {
        // The public accessor reports any feature; only the middleware's re-execution guard requires the library's own.
        var context = new DefaultHttpContext();
        context.Features.Set<IHmacClientFeature>(new ForeignFeature());

        Assert.Equal("foreign", context.GetHmacClientId());
    }

    [Fact]
    public void GetHmacClientId_NullContext_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("context", () => HmacHttpContextExtensions.GetHmacClientId(null!));
    }

    [Fact]
    public void AuthenticationDefaults_HaveDocumentedValues()
    {
        Assert.Equal("HMAC", HmacAuthenticationDefaults.AuthenticationScheme);
        Assert.Equal("HMAC", HmacAuthenticationDefaults.AuthenticationType);
        Assert.Equal("HMAC-SHA256", HmacAuthenticationDefaults.ChallengeScheme);
        Assert.Equal("client_id", HmacAuthenticationDefaults.ClientIdClaimType);
    }

    private sealed class ForeignFeature : IHmacClientFeature
    {
        public string ClientId => "foreign";
    }
}
