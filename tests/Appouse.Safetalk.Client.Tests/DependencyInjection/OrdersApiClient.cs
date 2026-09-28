namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// A typed client registered with <c>AddHmacClient&lt;TClient&gt;</c>.
/// </summary>
public sealed class OrdersApiClient(HttpClient httpClient)
{
    public HttpClient HttpClient { get; } = httpClient;
}
