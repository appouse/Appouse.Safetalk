namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// A typed client contract registered with <c>AddHmacClient&lt;TClient, TImplementation&gt;</c>.
/// </summary>
public interface IInventoryApi
{
    HttpClient HttpClient { get; }
}
