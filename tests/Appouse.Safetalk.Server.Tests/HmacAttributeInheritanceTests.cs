using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// <see cref="SkipHmacValidationAttribute"/> is not inherited (fail closed): a skip on a base controller or base virtual
/// method never exempts a derived controller or an override. <see cref="RequireHmacValidationAttribute"/> is inherited.
/// </summary>
public sealed class HmacAttributeInheritanceTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("/mvc/inheritance/from-skipped")]
    [InlineData("/mvc/inheritance/from-skipped/status")]
    [InlineData("/mvc/inheritance/skipped-virtual/ping")]
    [InlineData("/mvc/inheritance/from-skipped-required")]
    public async Task AllRequests_SkipDeclaredOnlyOnBaseControllerOrBaseVirtualMethod_UnsignedRequestIsRejected(string path)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests);

        using HttpResponseMessage response = await app.SendAsync(Unsigned(path));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/mvc/inheritance/from-skipped")]
    [InlineData("/mvc/inheritance/from-skipped/status")]
    [InlineData("/mvc/inheritance/skipped-virtual/ping")]
    public async Task AllRequests_SkipDeclaredOnlyOnBase_SignedRequestIsAuthenticated(string path)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, path));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Theory]
    [InlineData("/mvc/inheritance/from-skipped-own-skip")]
    [InlineData("/mvc/inheritance/from-skipped/declared-on-base")]
    public async Task AllRequests_SkipDeclaredOnTheControllerOrActionItself_IsHonoured(string path)
    {
        // A non-virtual base action is the same method on every derived controller: its own attribute applies.
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests);

        using HttpResponseMessage response = await app.SendAsync(Unsigned(path));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Theory]
    [InlineData("/mvc/inheritance/required-virtual/orders")]
    [InlineData("/mvc/inheritance/from-skipped-required")]
    [InlineData("/mvc/inherited")]
    public async Task MarkedEndpointsOnly_RequireDeclaredOnBaseOrOnDerivedBelowSkippedBase_UnsignedRequestIsRejected(string path)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly);

        using HttpResponseMessage response = await app.SendAsync(Unsigned(path));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/mvc/inheritance/required-virtual/other")]
    [InlineData("/mvc/inheritance/from-skipped")]
    [InlineData("/mvc/inheritance/skipped-virtual/ping")]
    public async Task MarkedEndpointsOnly_UnmarkedActions_AreNotValidated(string path)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly);

        using HttpResponseMessage response = await app.SendAsync(Unsigned(path));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task MarkedEndpointsOnly_RequireInheritedFromBaseVirtualMethod_SignedRequestIsAuthenticated()
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly);

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/mvc/inheritance/required-virtual/orders"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Theory]
    [InlineData("/mvc/inheritance/from-skipped")]
    [InlineData("/mvc/inheritance/from-skipped/status")]
    [InlineData("/mvc/inheritance/skipped-virtual/ping")]
    public async Task EndpointMetadata_DerivedFromSkippedBase_CarriesNoSkipAttribute(string path)
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests);

        Endpoint endpoint = FindEndpoint(app, path);

        Assert.DoesNotContain(endpoint.Metadata, metadata => metadata is SkipHmacValidationAttribute);
    }

    [Fact]
    public async Task EndpointMetadata_OverrideOfRequiredVirtualMethod_CarriesTheInheritedRequireAttribute()
    {
        await using TestApplication app = await StartAsync(HmacEnforcementMode.MarkedEndpointsOnly);

        Endpoint endpoint = FindEndpoint(app, "/mvc/inheritance/required-virtual/orders");

        Assert.True(endpoint.Metadata.GetMetadata<IHmacValidationMetadata>()?.RequiresValidation);
        Assert.Contains(endpoint.Metadata, metadata => metadata is RequireHmacValidationAttribute);
    }

    [Theory]
    [InlineData("/mvc/inheritance/own-skip-below-required-base")]
    [InlineData("/mvc/inheritance/required-virtual-own-skip/orders")]
    public async Task SkipDeclaredOnDerivedControllerOrOverrideBelowInheritedRequire_RemainsProtected(string path)
    {
        // Documented limitation (SkipHmacValidationAttribute remarks, README): a class- or override-level skip cannot
        // lift a [RequireHmacValidation] inherited from a base class, because reflection orders the inherited attribute
        // last. It fails closed; an action-level skip is the supported way to exempt such an action.
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests);

        using HttpResponseMessage response = await app.SendAsync(Unsigned(path));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/mvc/inheritance/own-skip-below-required-base")]
    [InlineData("/mvc/inheritance/required-virtual-own-skip/orders")]
    public async Task EndpointMetadata_OwnSkipBelowInheritedRequire_InheritedRequireIsOrderedLast(string path)
    {
        // Documents the root cause: reflection returns a type's (or override's) own attributes before the inherited
        // ones, so the inherited [RequireHmacValidation] becomes the last attribute-kind metadata.
        await using TestApplication app = await StartAsync(HmacEnforcementMode.AllRequests);

        IHmacValidationMetadata[] metadata = [.. FindEndpoint(app, path).Metadata.GetOrderedMetadata<IHmacValidationMetadata>()];

        Assert.IsType<SkipHmacValidationAttribute>(metadata[^2]);
        Assert.IsType<RequireHmacValidationAttribute>(metadata[^1]);
    }

    private static RouteEndpoint FindEndpoint(TestApplication app, string path)
    {
        string template = path.TrimStart('/');
        return Assert.Single(
            app.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>(),
            endpoint => string.Equals(endpoint.RoutePattern.RawText?.TrimStart('/'), template, StringComparison.Ordinal));
    }

    private static HttpRequestMessage Unsigned(string path) => new(HttpMethod.Get, new Uri(path, UriKind.Relative));

    private static Task<TestApplication> StartAsync(HmacEnforcementMode mode) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddControllers().AddApplicationPart(typeof(DerivedFromSkippedBaseController).Assembly);
                builder.Services
                    .AddHmacServer(options => options.EnforcementMode = mode)
                    .AddInMemorySecrets(TestCredentials.Secrets);
            },
            app =>
            {
                app.UseHmacAuthentication();
                app.MapControllers();
            });
}
