using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// Builds a <see cref="DefaultHttpContext"/> carrying a request signed the same way a client would sign it.
/// Every component can be changed before <see cref="Build()"/>; <see cref="Build(string)"/> uses a given signature,
/// which makes it easy to replay a request or to alter it after signing.
/// </summary>
internal sealed class SignedRequestBuilder(long unixTimestamp)
{
    public string Method { get; set; } = HttpMethods.Post;

    public string Path { get; set; } = "/api/orders";

    public string Query { get; set; } = "?id=5";

    public byte[] Body { get; set; } = """{"orderId":5,"amount":42.5}"""u8.ToArray();

    public string ClientId { get; set; } = TestCredentials.ClientId;

    public string Secret { get; set; } = TestCredentials.Secret;

    public string Timestamp { get; set; } = TestCredentials.FormatTimestamp(unixTimestamp);

    /// <summary>
    /// Gets or sets the request target used for signing. Defaults to <see cref="Path"/> + <see cref="Query"/>.
    /// </summary>
    public string? SignedTarget { get; set; }

    /// <summary>
    /// Gets or sets the raw request target exposed through <c>IHttpRequestFeature.RawTarget</c> (empty by default,
    /// like hosts that do not expose it).
    /// </summary>
    public string? RawTarget { get; set; }

    public bool SendContentLength { get; set; } = true;

    public int MaxBytesPerRead { get; set; } = int.MaxValue;

    public string Signature => TestCredentials.Sign(Method, SignedTarget ?? Path + Query, Timestamp, Body, Secret);

    public DefaultHttpContext Build() => Build(Signature);

    public DefaultHttpContext Build(string signature)
    {
        var context = new DefaultHttpContext();
        HttpRequest request = context.Request;
        request.Method = Method;
        request.Path = new PathString(Path);
        request.QueryString = new QueryString(Query);
        request.Body = new NonSeekableReadStream(Body, MaxBytesPerRead);
        if (SendContentLength)
        {
            request.ContentLength = Body.Length;
        }

        if (RawTarget is not null)
        {
            context.Features.Get<IHttpRequestFeature>()!.RawTarget = RawTarget;
        }

        request.Headers[SafetalkHeaderNames.ClientId] = ClientId;
        request.Headers[SafetalkHeaderNames.Timestamp] = Timestamp;
        request.Headers[SafetalkHeaderNames.Signature] = signature;
        return context;
    }
}
