namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// Records the service instances created by the container.
/// </summary>
public sealed class InstanceTracker
{
    private readonly List<object> _instances = [];
    private readonly object _gate = new();

    public IReadOnlyList<object> Instances
    {
        get
        {
            lock (_gate)
            {
                return [.. _instances];
            }
        }
    }

    public void Register(object instance)
    {
        lock (_gate)
        {
            _instances.Add(instance);
        }
    }
}
