namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// A second typed client with its own credentials, used to prove named options are isolated.
/// </summary>
public sealed class BillingApiClient(HttpClient httpClient)
{
    public HttpClient HttpClient { get; } = httpClient;
}
