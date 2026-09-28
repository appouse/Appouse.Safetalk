using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

public sealed class SkipHmacValidationControllerTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ActionWithSkipAttribute_IsReachableWithoutSignature()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/mvc/probe/public"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task ControllerWithSkipAttribute_IsReachableWithoutSignature()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/mvc/open"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task ActionWithoutSkipAttribute_RejectsUnsignedRequest()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(Unsigned("/mvc/probe/protected"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ActionWithoutSkipAttribute_AcceptsSignedRequestAndSeesClientId()
    {
        await using TestApplication app = await StartAsync();

        using HttpResponseMessage response = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, "/mvc/probe/protected"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(TestCredentials.ClientId, await response.Content.ReadAsStringAsync(CancellationToken));
    }

    private static HttpRequestMessage Unsigned(string path) => new(HttpMethod.Get, new Uri(path, UriKind.Relative));

    private static Task<TestApplication> StartAsync() =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddControllers().AddApplicationPart(typeof(ProbeController).Assembly);
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
            },
            app =>
            {
                app.UseHmacAuthentication();
                app.MapControllers();
            });
}
