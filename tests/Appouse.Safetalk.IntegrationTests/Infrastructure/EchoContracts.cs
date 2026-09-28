namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>Identity of the caller as seen by the protected application.</summary>
public sealed record WhoAmIResponse(
    string? ClientId,
    bool IsAuthenticated,
    string? UserName,
    string? AuthenticationType,
    string? ClientIdClaim);

/// <summary>A JSON payload posted by the tests.</summary>
public sealed record OrderRequest(string ProductCode, int Quantity, string? Note);

/// <summary>Echo of a JSON payload that was read after the signature was verified.</summary>
public sealed record OrderEchoResponse(string? ClientId, OrderRequest? Order);

/// <summary>Summary of a raw request body read after the signature was verified.</summary>
public sealed record RawBodyResponse(
    string? ClientId,
    string Method,
    long? ContentLength,
    bool IsChunked,
    string? Protocol,
    long Length,
    string Sha256);

/// <summary>Everything the application saw about the request target.</summary>
public sealed record RequestInfoResponse(
    string? ClientId,
    string Method,
    string PathBase,
    string Path,
    string QueryString,
    string RawTarget,
    long BodyLength);

/// <summary>Echo of a form read after the signature was verified.</summary>
public sealed record FormEchoResponse(
    string? ClientId,
    IReadOnlyDictionary<string, string> Fields,
    IReadOnlyList<FormFileEcho> Files);

/// <summary>Summary of an uploaded form file.</summary>
public sealed record FormFileEcho(string Name, string FileName, long Length, string Sha256);

/// <summary>Where the validator buffered the request body, and what the endpoint read from it.</summary>
public sealed record BodyBufferResponse(
    string? ClientId,
    string BodyStreamType,
    bool? InMemory,
    string? TempFileName,
    long Length,
    string Sha256);

/// <summary>The content headers and body the application received.</summary>
public sealed record ContentHeadersResponse(
    string? ClientId,
    long? ContentLength,
    string? ContentType,
    string ContentLanguage,
    string ContentDisposition,
    string CustomContentHeader,
    long Length,
    string Sha256);

/// <summary>Echo of the query of a route with a non-ASCII literal segment.</summary>
public sealed record CustomerQueryResponse(string? ClientId, string Path, string? Q, string? X);
