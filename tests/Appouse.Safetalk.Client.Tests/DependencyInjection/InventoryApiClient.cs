namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

public sealed class InventoryApiClient(HttpClient httpClient) : IInventoryApi
{
    public HttpClient HttpClient { get; } = httpClient;
}
