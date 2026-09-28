namespace Appouse.Safetalk.Core.Tests.Infrastructure;

/// <summary>
/// Tests that inspect arrays after they were returned to <see cref="System.Buffers.ArrayPool{T}.Shared"/> run in
/// isolation, so no concurrently running test can rent and overwrite those arrays while they are being inspected.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ArrayPoolInspectionDefinition
{
    public const string Name = "ArrayPool inspection";
}
