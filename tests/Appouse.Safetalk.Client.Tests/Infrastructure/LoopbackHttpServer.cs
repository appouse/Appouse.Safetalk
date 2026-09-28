using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// A minimal HTTP/1.1 server on a loopback port chosen by the OS (port 0). It accepts one connection per call, parses
/// the request exactly as it arrived on the wire (request target, headers, Content-Length or chunked body) and answers
/// <c>200 OK</c> with <c>Connection: close</c>. It lets tests observe what <see cref="SocketsHttpHandler"/> really
/// sends.
/// </summary>
internal sealed class LoopbackHttpServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

    public LoopbackHttpServer()
    {
        _listener.Start();
        BaseAddress = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port.ToString(CultureInfo.InvariantCulture)}/");
    }

    public Uri BaseAddress { get; }

    public async Task<WireRequest> AcceptOneAsync(CancellationToken cancellationToken)
    {
        using TcpClient client = await _listener.AcceptTcpClientAsync(cancellationToken);
        NetworkStream stream = client.GetStream();

        string head = await ReadHeadAsync(stream, cancellationToken);
        string[] lines = head.Split("\r\n");
        string[] requestLine = lines[0].Split(' ');
        var headers = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in lines.Skip(1))
        {
            int colon = line.IndexOf(':', StringComparison.Ordinal);
            string name = line[..colon];
            string value = line[(colon + 1)..].Trim();
            if (!headers.TryGetValue(name, out List<string>? values))
            {
                headers[name] = values = [];
            }

            values.Add(value);
        }

        byte[] body;
        bool chunked = headers.TryGetValue("Transfer-Encoding", out List<string>? encodings)
            && encodings.Exists(e => e.Contains("chunked", StringComparison.OrdinalIgnoreCase));
        if (chunked)
        {
            body = await ReadChunkedBodyAsync(stream, cancellationToken);
        }
        else if (headers.TryGetValue("Content-Length", out List<string>? lengths))
        {
            body = await ReadExactlyAsync(stream, int.Parse(lengths[0], CultureInfo.InvariantCulture), cancellationToken);
        }
        else
        {
            body = [];
        }

        await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), cancellationToken);
        await stream.FlushAsync(cancellationToken);

        return new WireRequest(
            requestLine[0],
            requestLine[1],
            headers.ToDictionary(h => h.Key, h => h.Value.ToArray(), StringComparer.OrdinalIgnoreCase),
            body,
            chunked);
    }

    public void Dispose() => _listener.Stop();

    private static async Task<string> ReadHeadAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var head = new List<byte>();
        byte[] one = new byte[1];
        while (head.Count < 4 || head[^4] != '\r' || head[^3] != '\n' || head[^2] != '\r' || head[^1] != '\n')
        {
            if (await stream.ReadAsync(one, cancellationToken) == 0)
            {
                throw new IOException("The connection closed before the request head was complete.");
            }

            head.Add(one[0]);
        }

        return Encoding.Latin1.GetString(head.ToArray(), 0, head.Count - 4);
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var line = new List<byte>();
        byte[] one = new byte[1];
        while (line.Count < 2 || line[^2] != '\r' || line[^1] != '\n')
        {
            if (await stream.ReadAsync(one, cancellationToken) == 0)
            {
                throw new IOException("The connection closed in the middle of a line.");
            }

            line.Add(one[0]);
        }

        return Encoding.Latin1.GetString(line.ToArray(), 0, line.Count - 2);
    }

    private static async Task<byte[]> ReadChunkedBodyAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        while (true)
        {
            string sizeLine = await ReadLineAsync(stream, cancellationToken);
            int size = int.Parse(sizeLine.Split(';')[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (size == 0)
            {
                while ((await ReadLineAsync(stream, cancellationToken)).Length > 0)
                {
                }

                return body.ToArray();
            }

            body.Write(await ReadExactlyAsync(stream, size, cancellationToken));
            await ReadLineAsync(stream, cancellationToken);
        }
    }

    private static async Task<byte[]> ReadExactlyAsync(NetworkStream stream, int count, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, cancellationToken);
        return buffer;
    }
}

/// <summary>
/// A request as it arrived on the wire.
/// </summary>
internal sealed record WireRequest(string Method, string Target, IReadOnlyDictionary<string, string[]> Headers, byte[] Body, bool Chunked)
{
    public string Header(string name)
    {
        Assert.True(Headers.TryGetValue(name, out string[]? values), $"Header '{name}' was not sent.");
        return Assert.Single(values);
    }
}
