using System.Net;
using System.Net.Http.Json;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

internal static class HttpResponseMessageExtensions
{
    /// <summary>
    /// Asserts <c>200 OK</c> and deserializes the JSON body.
    /// </summary>
    public static async Task<T> ReadOkJsonAsync<T>(this HttpResponseMessage response, CancellationToken cancellationToken)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        T? value = await response.Content.ReadFromJsonAsync<T>(cancellationToken);
        Assert.NotNull(value);
        return value;
    }

    /// <summary>
    /// Asserts <c>401 Unauthorized</c> with the HMAC challenge.
    /// </summary>
    public static void AssertUnauthorized(this HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("HMAC-SHA256", Assert.Single(response.Headers.WwwAuthenticate).Scheme);
    }
}
