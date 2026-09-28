using Appouse.Safetalk.Samples.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory, // Finds appsettings.json regardless of the working directory.
});

// ClientId, Secret and BaseAddress come from the "OrdersApi" section; a reload (e.g. a rotated secret) applies
// to the next request.
builder.Services.AddHmacClient<OrdersApiClient>(builder.Configuration.GetSection("OrdersApi"));

using IHost host = builder.Build();
await host.StartAsync(); // Validates HmacClientOptions (ValidateOnStart).

OrdersApiClient orders = host.Services.GetRequiredService<OrdersApiClient>();

OrderResponse? created = await orders.CreateOrderAsync(new CreateOrderRequest("SKU-42", 3));
Console.WriteLine($"Created: {created}");

OrderResponse? fetched = await orders.GetOrderAsync(created!.Id);
Console.WriteLine($"Fetched: {fetched}");

await host.StopAsync();
