using System.Buffers;

namespace Appouse.Safetalk.Core.Tests;

public sealed class CanonicalRequestBufferLifetimeTests
{
    private const string Timestamp = "1700000000";

    public static TheoryData<string> MembersThatRequireLiveBuffer => new()
    {
        nameof(CanonicalRequestBuffer.WrittenCount),
        nameof(CanonicalRequestBuffer.WrittenSpan),
        nameof(CanonicalRequestBuffer.GetSpan),
        nameof(CanonicalRequestBuffer.GetMemory),
        nameof(CanonicalRequestBuffer.Advance),
        nameof(BuffersExtensions.Write),
    };

    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        var buffer = CanonicalRequestBuffer.Create("POST", "/api/orders", Timestamp);
        buffer.Dispose();

        Exception? exception = Record.Exception(buffer.Dispose);

        Assert.Null(exception);
    }

    [Fact]
    public void Dispose_AfterGrowth_CanBeCalledRepeatedly()
    {
        var buffer = CanonicalRequestBuffer.Create("POST", "/api/orders", Timestamp);
        BuffersExtensions.Write(buffer, new byte[100_000].AsSpan());

        buffer.Dispose();
        Exception? exception = Record.Exception(buffer.Dispose);

        Assert.Null(exception);
    }

    [Fact]
    public void Dispose_ExplicitlyInsideUsingScope_DoesNotThrowAtScopeExit()
    {
        Exception? exception = Record.Exception(() =>
        {
            using var buffer = CanonicalRequestBuffer.Create("GET", "/", Timestamp);
            buffer.Dispose();
        });

        Assert.Null(exception);
    }

    [Theory]
    [MemberData(nameof(MembersThatRequireLiveBuffer))]
    public void Member_AfterDispose_ThrowsObjectDisposedException(string member)
    {
        var buffer = CanonicalRequestBuffer.Create("POST", "/api/orders", Timestamp);
        buffer.Dispose();

        Action action = member switch
        {
            nameof(CanonicalRequestBuffer.WrittenCount) => () => _ = buffer.WrittenCount,
            nameof(CanonicalRequestBuffer.WrittenSpan) => () => _ = buffer.WrittenSpan.Length,
            nameof(CanonicalRequestBuffer.GetSpan) => () => { buffer.GetSpan(); },
            nameof(CanonicalRequestBuffer.GetMemory) => () => buffer.GetMemory(),
            nameof(CanonicalRequestBuffer.Advance) => () => buffer.Advance(0),
            nameof(BuffersExtensions.Write) => () => BuffersExtensions.Write(buffer, "x"u8),
            _ => throw new ArgumentOutOfRangeException(nameof(member), member, "Unknown member."),
        };

        ObjectDisposedException exception = Assert.Throws<ObjectDisposedException>(action);
        Assert.Equal(typeof(CanonicalRequestBuffer).FullName, exception.ObjectName);
    }

    [Fact]
    public void Advance_AfterDispose_ThrowsObjectDisposedExceptionEvenForInvalidCount()
    {
        var buffer = CanonicalRequestBuffer.Create("POST", "/api/orders", Timestamp);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => buffer.Advance(-1));
    }

    [Fact]
    public void GetSpan_AfterDispose_ThrowsObjectDisposedExceptionEvenForInvalidSizeHint()
    {
        var buffer = CanonicalRequestBuffer.Create("POST", "/api/orders", Timestamp);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { buffer.GetSpan(-1); });
    }

    [Fact]
    public void CanonicalRequestBuffer_Type_IsSealedDisposableBufferWriter()
    {
        Type type = typeof(CanonicalRequestBuffer);

        Assert.True(type.IsSealed);
        Assert.True(typeof(IBufferWriter<byte>).IsAssignableFrom(type));
        Assert.True(typeof(IDisposable).IsAssignableFrom(type));
        Assert.Empty(type.GetConstructors());
    }
}
