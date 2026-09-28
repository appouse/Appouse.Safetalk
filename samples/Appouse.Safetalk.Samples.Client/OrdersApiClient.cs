using System.Net.Http.Json;

namespace Appouse.Safetalk.Samples.Client;

/// <summary>
/// A typed client. It knows nothing about signing: <c>HmacSigningHandler</c> signs every request transparently.
/// </summary>
public sealed class OrdersApiClient(HttpClient httpClient)
{
    public async Task<OrderResponse?> CreateOrderAsync(CreateOrderRequest request, CancellationToken cancellationToken = default)
    {
        using HttpResponseMessage response = await httpClient.PostAsJsonAsync("api/orders", request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<OrderResponse>(cancellationToken);
    }

    public Task<OrderResponse?> GetOrderAsync(int id, CancellationToken cancellationToken = default)
        => httpClient.GetFromJsonAsync<OrderResponse>($"api/orders/{id}", cancellationToken);
}

public sealed record CreateOrderRequest(string ProductCode, int Quantity);

public sealed record OrderResponse(int Id, string ProductCode, int Quantity, string CreatedBy);
