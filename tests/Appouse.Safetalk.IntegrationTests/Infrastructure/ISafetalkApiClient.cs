namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Contract of the typed client, used to exercise <c>AddHmacClient&lt;TClient, TImplementation&gt;</c>.
/// </summary>
public interface ISafetalkApiClient
{
    Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken);

    Task<WhoAmIResponse> GetWhoAmIAsync(CancellationToken cancellationToken);
}
