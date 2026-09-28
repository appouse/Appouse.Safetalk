using System.Reflection;

namespace Appouse.Safetalk.Core.Tests;

/// <summary>
/// Guards the contracts of the dependency-free Abstractions package and the layering between Abstractions and Core.
/// </summary>
public sealed class AbstractionsLayerTests
{
    private static readonly Assembly AbstractionsAssembly = typeof(IHmacSignatureService).Assembly;
    private static readonly Assembly CoreAssembly = typeof(HmacSha256SignatureService).Assembly;

    [Fact]
    public void SafetalkHeaderNames_HaveWireValues()
    {
        Assert.Equal("X-Signature", SafetalkHeaderNames.Signature);
        Assert.Equal("X-Timestamp", SafetalkHeaderNames.Timestamp);
        Assert.Equal("X-Client-Id", SafetalkHeaderNames.ClientId);
    }

    [Fact]
    public void SafetalkHeaderNames_AreDistinctIgnoringCase()
    {
        string[] names = [SafetalkHeaderNames.Signature, SafetalkHeaderNames.Timestamp, SafetalkHeaderNames.ClientId];

        Assert.Equal(names.Length, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void SafetalkHeaderNames_AreValidHttpRequestHeaderNames()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");

        request.Headers.Add(SafetalkHeaderNames.Signature, "abc");
        request.Headers.Add(SafetalkHeaderNames.Timestamp, "1700000000");
        request.Headers.Add(SafetalkHeaderNames.ClientId, "client");

        Assert.Equal("abc", Assert.Single(request.Headers.GetValues(SafetalkHeaderNames.Signature)));
        Assert.Equal("1700000000", Assert.Single(request.Headers.GetValues(SafetalkHeaderNames.Timestamp)));
        Assert.Equal("client", Assert.Single(request.Headers.GetValues(SafetalkHeaderNames.ClientId)));
    }

    [Fact]
    public void Contracts_LiveInAbstractionsAssemblyUnderRootNamespace()
    {
        Type[] contracts = [typeof(IHmacSignatureService), typeof(IHmacSecretProvider), typeof(IHmacReplayCache), typeof(SafetalkHeaderNames)];

        Assert.All(contracts, contract =>
        {
            Assert.Equal("Appouse.Safetalk.Abstractions", contract.Assembly.GetName().Name);
            Assert.Equal("Appouse.Safetalk", contract.Namespace);
        });
    }

    [Fact]
    public void AbstractionsAssembly_ExportsOnlyTheDocumentedContracts()
    {
        string[] expected =
        [
            "Appouse.Safetalk.IHmacReplayCache",
            "Appouse.Safetalk.IHmacSecretProvider",
            "Appouse.Safetalk.IHmacSignatureService",
            "Appouse.Safetalk.SafetalkHeaderNames",
        ];

        string[] exported = AbstractionsAssembly.GetExportedTypes().Select(t => t.FullName!).Order(StringComparer.Ordinal).ToArray();

        Assert.Equal(expected, exported);
    }

    [Fact]
    public void AbstractionsAssembly_ReferencesOnlyTheBaseClassLibrary()
    {
        string[] references = AbstractionsAssembly.GetReferencedAssemblies().Select(r => r.Name!).ToArray();

        Assert.All(references, name => Assert.True(
            name.StartsWith("System", StringComparison.Ordinal) || name == "netstandard",
            $"Abstractions must be dependency-free but references '{name}'."));
    }

    [Fact]
    public void CoreAssembly_DependsOnAbstractionsButNotOnHostingOrHttpStacks()
    {
        string[] references = CoreAssembly.GetReferencedAssemblies().Select(r => r.Name!).ToArray();

        Assert.Contains("Appouse.Safetalk.Abstractions", references);
        Assert.DoesNotContain(references, name => name.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal));
        Assert.DoesNotContain(references, name => name.StartsWith("Microsoft.Extensions", StringComparison.Ordinal));
        Assert.DoesNotContain(references, name => name.StartsWith("Appouse.Safetalk.Client", StringComparison.Ordinal));
        Assert.DoesNotContain(references, name => name.StartsWith("Appouse.Safetalk.Server", StringComparison.Ordinal));
    }

    [Fact]
    public void IHmacSignatureService_IsImplementedByCoreService()
    {
        Assert.True(typeof(IHmacSignatureService).IsAssignableFrom(typeof(HmacSha256SignatureService)));
        Assert.True(typeof(HmacSha256SignatureService).IsSealed);
    }

    [Fact]
    public void AsyncContracts_AcceptOptionalCancellationToken()
    {
        MethodInfo getSecret = typeof(IHmacSecretProvider).GetMethod(nameof(IHmacSecretProvider.GetSecretAsync))!;
        MethodInfo tryAdd = typeof(IHmacReplayCache).GetMethod(nameof(IHmacReplayCache.TryAddAsync))!;

        Assert.Equal(typeof(ValueTask<string>), getSecret.ReturnType);
        Assert.Equal(typeof(ValueTask<bool>), tryAdd.ReturnType);
        MethodInfo[] methods = [getSecret, tryAdd];
        foreach (MethodInfo method in methods)
        {
            ParameterInfo last = method.GetParameters()[^1];
            Assert.Equal(typeof(CancellationToken), last.ParameterType);
            Assert.True(last.IsOptional, $"{method.Name} should have an optional cancellation token.");
        }
    }

    [Fact]
    public void IHmacReplayCache_TryAddAsync_IsKeyedOnSignatureAndExpiryOnly()
    {
        MethodInfo method = Assert.Single(typeof(IHmacReplayCache).GetMethods());

        Assert.Equal(nameof(IHmacReplayCache.TryAddAsync), method.Name);
        Assert.Equal(typeof(ValueTask<bool>), method.ReturnType);
        ParameterInfo[] parameters = method.GetParameters();
        Assert.Equal(["signature", "expiresAt", "cancellationToken"], parameters.Select(p => p.Name));
        Assert.Equal([typeof(string), typeof(DateTimeOffset), typeof(CancellationToken)], parameters.Select(p => p.ParameterType));
        Assert.False(parameters[0].IsOptional);
        Assert.False(parameters[1].IsOptional);
        Assert.True(parameters[2].HasDefaultValue);
        Assert.DoesNotContain(parameters, p => p.Name!.Contains("client", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(typeof(IHmacReplayCache).GetProperties());
        Assert.Empty(typeof(IHmacReplayCache).GetInterfaces());
    }

    [Fact]
    public void IHmacReplayCache_TryAddAsync_SignatureParameterIsNonNullable()
    {
        var context = new NullabilityInfoContext();
        ParameterInfo signature = typeof(IHmacReplayCache).GetMethod(nameof(IHmacReplayCache.TryAddAsync))!.GetParameters()[0];

        Assert.Equal(NullabilityState.NotNull, context.Create(signature).ReadState);
    }

    [Fact]
    public void IHmacSecretProvider_GetSecretAsync_TakesClientIdAndReturnsNullableSecret()
    {
        var context = new NullabilityInfoContext();
        MethodInfo method = Assert.Single(typeof(IHmacSecretProvider).GetMethods());
        ParameterInfo[] parameters = method.GetParameters();

        Assert.Equal(nameof(IHmacSecretProvider.GetSecretAsync), method.Name);
        Assert.Equal(["clientId", "cancellationToken"], parameters.Select(p => p.Name));
        Assert.Equal([typeof(string), typeof(CancellationToken)], parameters.Select(p => p.ParameterType));
        Assert.Equal(NullabilityState.NotNull, context.Create(parameters[0]).ReadState);
        NullabilityInfo returned = context.Create(method.ReturnParameter);
        Assert.Equal(NullabilityState.Nullable, Assert.Single(returned.GenericTypeArguments).ReadState);
    }

    [Fact]
    public async Task IHmacReplayCache_ImplementationAgainstNewShape_RecordsSignatureOnceAndFailsClosedForPastExpiry()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        var now = new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);
        IHmacReplayCache cache = new ContractReplayCache(() => now);
        const string signature = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

        Assert.True(await cache.TryAddAsync(signature, now.AddMinutes(5), cancellationToken));
        Assert.False(await cache.TryAddAsync(signature, now.AddMinutes(5), cancellationToken));
        Assert.False(await cache.TryAddAsync(signature.Replace('0', '1'), now, cancellationToken));
        Assert.False(await cache.TryAddAsync(signature.Replace('0', '2'), now.AddTicks(-1), cancellationToken));
        Assert.True(await cache.TryAddAsync(signature.Replace('0', '3'), now.AddTicks(1), cancellationToken));
    }

    /// <summary>
    /// A minimal implementation written against the documented contract: keyed on the signature only and fail-closed
    /// when the expiry is not in the future. It exists to keep the contract implementable with exactly this shape.
    /// </summary>
    private sealed class ContractReplayCache(Func<DateTimeOffset> clock) : IHmacReplayCache
    {
        private readonly Dictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);

        public ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (expiresAt <= clock())
            {
                return ValueTask.FromResult(false);
            }

            return ValueTask.FromResult(_entries.TryAdd(signature, expiresAt));
        }
    }
}
