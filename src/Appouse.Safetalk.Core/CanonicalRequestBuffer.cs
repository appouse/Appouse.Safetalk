using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Appouse.Safetalk;

/// <summary>
/// A pooled, growable buffer that holds the UTF-8 encoded canonical request
/// (<c>{METHOD}\n{PATH-AND-QUERY}\n{TIMESTAMP}\n{BODY}</c>) as a single contiguous span.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Create"/> writes the header part of the canonical request; the body is then appended through the
/// <see cref="IBufferWriter{T}"/> implementation, so it is copied exactly once — directly from its source into
/// pooled memory — without intermediate strings or arrays.
/// </para>
/// <para>
/// The rented memory is zeroed in full — including bytes written through <see cref="GetMemory"/> or
/// <see cref="GetSpan"/> but never committed with <see cref="Advance"/> (for example after a failed read) — and
/// returned to <see cref="ArrayPool{T}.Shared"/> on <see cref="Dispose"/> and whenever the buffer grows, so request
/// payloads never leak to other pool renters. Instances are not thread-safe.
/// </para>
/// </remarks>
public sealed class CanonicalRequestBuffer : IBufferWriter<byte>, IDisposable
{
    private const int MinimumBufferSize = 256;

    private byte[] _buffer;
    private int _written;
    private bool _disposed;

    private CanonicalRequestBuffer(int initialCapacity)
    {
        _buffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
    }

    /// <summary>
    /// Gets the number of bytes written to the buffer so far.
    /// </summary>
    public int WrittenCount
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _written;
        }
    }

    /// <summary>
    /// Gets the canonical request bytes written so far.
    /// </summary>
    public ReadOnlySpan<byte> WrittenSpan
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer.AsSpan(0, _written);
        }
    }

    /// <summary>
    /// Creates a buffer that already contains the header part of the canonical request
    /// (<c>{METHOD}\n{PATH-AND-QUERY}\n{TIMESTAMP}\n</c>). The body must be appended afterwards.
    /// </summary>
    /// <param name="method">The HTTP method. It must be ASCII and is upper-cased.</param>
    /// <param name="pathAndQuery">The request path and query string, for example <c>/api/orders?id=5</c>.</param>
    /// <param name="timestamp">The Unix timestamp (seconds) sent in the <c>X-Timestamp</c> header.</param>
    /// <param name="bodyLengthHint">The expected body length, used to size the buffer up front.</param>
    /// <returns>A new buffer that must be disposed by the caller.</returns>
    /// <exception cref="ArgumentException">An argument is empty or <paramref name="method"/> is not ASCII.</exception>
    public static CanonicalRequestBuffer Create(string method, string pathAndQuery, string timestamp, int bodyLengthHint = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentException.ThrowIfNullOrEmpty(pathAndQuery);
        ArgumentException.ThrowIfNullOrEmpty(timestamp);
        ArgumentOutOfRangeException.ThrowIfNegative(bodyLengthHint);

        int headerLength = checked(method.Length
            + Encoding.UTF8.GetByteCount(pathAndQuery)
            + Encoding.UTF8.GetByteCount(timestamp)
            + 3);
        long capacity = Math.Clamp((long)headerLength + bodyLengthHint, MinimumBufferSize, Array.MaxLength);

        var buffer = new CanonicalRequestBuffer((int)capacity);
        try
        {
            buffer.WriteHeader(method, pathAndQuery, timestamp);
            return buffer;
        }
        catch
        {
            buffer.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public void Advance(int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        if (count > _buffer.Length - _written)
        {
            throw new InvalidOperationException("Cannot advance past the end of the buffer.");
        }

        _written += count;
    }

    /// <inheritdoc />
    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        EnsureCapacity(sizeHint);
        return _buffer.AsMemory(_written);
    }

    /// <inheritdoc />
    public Span<byte> GetSpan(int sizeHint = 0)
    {
        EnsureCapacity(sizeHint);
        return _buffer.AsSpan(_written);
    }

    /// <summary>
    /// Zeroes the whole rented array and returns it to the pool.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ReturnToPool(_buffer);
        _buffer = [];
        _written = 0;
    }

    private void WriteHeader(string method, string pathAndQuery, string timestamp)
    {
        Span<byte> span = _buffer;

        if (Ascii.ToUpper(method, span, out int position) != OperationStatus.Done)
        {
            throw new ArgumentException("The HTTP method must consist of ASCII characters only.", nameof(method));
        }

        span[position++] = (byte)CanonicalRequest.Separator;
        position += Encoding.UTF8.GetBytes(pathAndQuery, span[position..]);
        span[position++] = (byte)CanonicalRequest.Separator;
        position += Encoding.UTF8.GetBytes(timestamp, span[position..]);
        span[position++] = (byte)CanonicalRequest.Separator;

        _written = position;
    }

    private void EnsureCapacity(int sizeHint)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(sizeHint);

        int required = Math.Max(sizeHint, 1);
        int available = _buffer.Length - _written;
        if (required <= available)
        {
            return;
        }

        long newSize = Math.Max((long)_written + required, (long)_buffer.Length * 2);
        if ((long)_written + required > Array.MaxLength)
        {
            throw new InsufficientMemoryException("The canonical request exceeds the maximum supported size.");
        }

        byte[] newBuffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(newSize, Array.MaxLength));
        _buffer.AsSpan(0, _written).CopyTo(newBuffer);
        ReturnToPool(_buffer);
        _buffer = newBuffer;
    }

    private static void ReturnToPool(byte[] buffer)
    {
        // The whole array is cleared: callers may have written past the committed length before failing.
        CryptographicOperations.ZeroMemory(buffer);
        ArrayPool<byte>.Shared.Return(buffer);
    }
}
