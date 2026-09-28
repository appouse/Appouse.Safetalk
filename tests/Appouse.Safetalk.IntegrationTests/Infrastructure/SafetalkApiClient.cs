using System.Net.Http.Json;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Typed client registered with <c>AddHmacClient&lt;TClient&gt;</c>. Every request it sends is signed by the
/// real <c>HmacSigningHandler</c>.
/// </summary>
public sealed class SafetalkApiClient(HttpClient httpClient) : ISafetalkApiClient
{
    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => httpClient.SendAsync(request, cancellationToken);

    public Task<HttpResponseMessage> GetAsync(string pathAndQuery, CancellationToken cancellationToken)
        => httpClient.GetAsync(Relative(pathAndQuery), cancellationToken);

    public Task<HttpResponseMessage> PostAsync(string pathAndQuery, HttpContent? content, CancellationToken cancellationToken)
        => httpClient.PostAsync(Relative(pathAndQuery), content, cancellationToken);

    public Task<HttpResponseMessage> PutAsync(string pathAndQuery, HttpContent? content, CancellationToken cancellationToken)
        => httpClient.PutAsync(Relative(pathAndQuery), content, cancellationToken);

    public Task<HttpResponseMessage> PostAsJsonAsync<TValue>(string pathAndQuery, TValue value, CancellationToken cancellationToken)
        => httpClient.PostAsJsonAsync(Relative(pathAndQuery), value, cancellationToken);

    public async Task<WhoAmIResponse> GetWhoAmIAsync(CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await GetAsync("/api/whoami", cancellationToken);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<WhoAmIResponse>(cancellationToken))!;
    }

    private static Uri Relative(string pathAndQuery) => new(pathAndQuery, UriKind.Relative);
}
