using Appouse.Safetalk.Redis.Tests.Infrastructure;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using StackExchange.Redis;

[assembly: AssemblyFixture(typeof(RedisServers))]

namespace Appouse.Safetalk.Redis.Tests.Infrastructure;

/// <summary>
/// The Redis-compatible servers every server-backed test runs against.
/// </summary>
public enum RedisServerKind
{
    Redis,
    KeyDb,
}

/// <summary>
/// Starts one Redis and one KeyDB container for the whole test assembly.
/// </summary>
/// <remarks>
/// When Docker (with Linux containers) is not available, server-backed tests are skipped — unless the environment
/// variable <c>SAFETALK_REQUIRE_CONTAINERS</c> is <c>true</c> (as in CI on Linux), in which case they fail.
/// </remarks>
public sealed class RedisServers : IAsyncLifetime
{
    private const int Port = 6379;

    private static readonly TimeSpan StartupTimeout = TimeSpan.FromMinutes(2);

    private readonly Dictionary<RedisServerKind, IContainer> _containers = [];
    private string? _unavailableReason;

    public static bool ContainersRequired =>
        string.Equals(Environment.GetEnvironmentVariable("SAFETALK_REQUIRE_CONTAINERS"), "true", StringComparison.OrdinalIgnoreCase);

    public async ValueTask InitializeAsync()
    {
        try
        {
            // Bounded, so that a server that never becomes ready fails the run instead of hanging it.
            using var timeout = new CancellationTokenSource(StartupTimeout);
            await Task.WhenAll(
                StartAsync(RedisServerKind.Redis, "redis:7-alpine", "redis-server", "redis-cli", timeout.Token),
                StartAsync(RedisServerKind.KeyDb, "eqalpha/keydb:latest", "keydb-server", "keydb-cli", timeout.Token));
        }
        catch (Exception exception) when (!ContainersRequired)
        {
            _unavailableReason = $"Docker with Linux containers is not available: {exception.GetType().Name}: {exception.Message}";
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (IContainer container in _containers.Values)
        {
            await container.DisposeAsync();
        }
    }

    /// <summary>
    /// Returns the StackExchange.Redis configuration string of <paramref name="kind"/>, or skips the test.
    /// </summary>
    public string GetConfiguration(RedisServerKind kind, bool allowAdmin = false)
    {
        if (_unavailableReason is not null)
        {
            Assert.Skip(_unavailableReason);
        }

        IContainer container = _containers[kind];
        string configuration = $"{container.Hostname}:{container.GetMappedPublicPort(Port)}";
        return allowAdmin ? configuration + ",allowAdmin=true" : configuration;
    }

    public Task<ConnectionMultiplexer> ConnectAsync(RedisServerKind kind, bool allowAdmin = false)
        => ConnectionMultiplexer.ConnectAsync(GetConfiguration(kind, allowAdmin));

    private async Task StartAsync(RedisServerKind kind, string image, string server, string cli, CancellationToken cancellationToken)
    {
        // Readiness is probed with the server's own CLI: the log lines differ (KeyDB never logs "Ready to accept
        // connections"). Persistence is off so that nothing is written to disk.
        IContainer container = new ContainerBuilder(image)
            .WithCommand(server, "--protected-mode", "no", "--save", "", "--appendonly", "no")
            .WithPortBinding(Port, assignRandomHostPort: true)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilCommandIsCompleted(cli, "ping"))
            .Build();

        lock (_containers)
        {
            _containers[kind] = container;
        }

        await container.StartAsync(cancellationToken);
    }
}
