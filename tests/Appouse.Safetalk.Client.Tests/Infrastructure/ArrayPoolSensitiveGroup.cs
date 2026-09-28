namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Tests that observe <see cref="System.Buffers.ArrayPool{T}.Shared"/> through <see cref="ArrayPoolRentListener"/>, or
/// that rent multi-MiB buffers, run alone: the listener sees every rent in the process, so a large body signed by a
/// test running in parallel would otherwise be attributed to the test under observation.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ArrayPoolSensitiveGroup
{
    public const string Name = "ArrayPool-sensitive";
}
