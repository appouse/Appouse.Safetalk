using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// Sends a hand-written HTTP/1.1 request over a raw TCP connection, so that the exact request line bytes
/// (method casing, absolute-form target, percent-encoding casing) reach Kestrel unmodified by <see cref="HttpClient"/>.
/// </summary>
internal static class RawHttpClient
{
    public static async Task<HttpStatusCode> SendAsync(
        Uri serverAddress,
        string method,
        string requestTarget,
        IEnumerable<KeyValuePair<string, string>> headers,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        RawHttpResponse response = await SendForResponseAsync(serverAddress, method, requestTarget, headers, body, cancellationToken);
        return response.StatusCode;
    }

    /// <summary>
    /// Writes <paramref name="requestBytes"/> verbatim (request line, headers and framing chosen by the caller) and
    /// reads the first response.
    /// </summary>
    public static async Task<RawHttpResponse> SendBytesAsync(Uri serverAddress, byte[] requestBytes, CancellationToken cancellationToken)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(serverAddress.Host, serverAddress.Port, cancellationToken);
        await using NetworkStream stream = tcp.GetStream();
        await stream.WriteAsync(requestBytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);
        return await ReadResponseAsync(stream, cancellationToken);
    }

    /// <summary>
    /// Sends the request and returns the status code and everything after the response head. The body is returned
    /// as received (it may still contain chunked framing), which is enough for substring assertions.
    /// </summary>
    public static async Task<RawHttpResponse> SendForResponseAsync(
        Uri serverAddress,
        string method,
        string requestTarget,
        IEnumerable<KeyValuePair<string, string>> headers,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(serverAddress.Host, serverAddress.Port, cancellationToken);
        await using NetworkStream stream = tcp.GetStream();

        var head = new StringBuilder();
        head.Append(CultureInfo.InvariantCulture, $"{method} {requestTarget} HTTP/1.1\r\n");
        head.Append(CultureInfo.InvariantCulture, $"Host: {serverAddress.Authority}\r\n");
        foreach ((string name, string value) in headers)
        {
            head.Append(CultureInfo.InvariantCulture, $"{name}: {value}\r\n");
        }

        head.Append(CultureInfo.InvariantCulture, $"Content-Length: {body.Length}\r\n");
        head.Append("Connection: close\r\n\r\n");

        await stream.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()), cancellationToken);
        await stream.WriteAsync(body, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        return await ReadResponseAsync(stream, cancellationToken);
    }

    private static async Task<RawHttpResponse> ReadResponseAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(stream, Encoding.Latin1);
        string statusLine = await reader.ReadLineAsync(cancellationToken)
            ?? throw new InvalidOperationException("The server closed the connection without a response.");

        // "HTTP/1.1 200 OK"
        string[] parts = statusLine.Split(' ', 3);
        var statusCode = (HttpStatusCode)int.Parse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture);

        var responseHeaders = new StringBuilder();
        while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 } line)
        {
            responseHeaders.AppendLine(line);
        }

        string responseBody = await reader.ReadToEndAsync(cancellationToken);
        return new RawHttpResponse(statusCode, responseHeaders.ToString(), responseBody);
    }
}

/// <summary>A response read by <see cref="RawHttpClient"/>.</summary>
internal sealed record RawHttpResponse(HttpStatusCode StatusCode, string Headers, string Body);
