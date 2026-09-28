using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacEndpointConventionBuilderExtensionsTests
{
    [Fact]
    public void SkipHmacValidation_AddsSkipMetadataAndReturnsSameBuilder()
    {
        var builder = new RecordingConventionBuilder();

        RecordingConventionBuilder result = builder.SkipHmacValidation();

        Assert.Same(builder, result);
        Endpoint endpoint = Build(builder);
        IHmacValidationMetadata metadata = Assert.Single(endpoint.Metadata.GetOrderedMetadata<IHmacValidationMetadata>());
        Assert.False(metadata.RequiresValidation);
    }

    [Fact]
    public void RequireHmacValidation_AddsRequireMetadataAndReturnsSameBuilder()
    {
        var builder = new RecordingConventionBuilder();

        RecordingConventionBuilder result = builder.RequireHmacValidation();

        Assert.Same(builder, result);
        Endpoint endpoint = Build(builder);
        IHmacValidationMetadata metadata = Assert.Single(endpoint.Metadata.GetOrderedMetadata<IHmacValidationMetadata>());
        Assert.True(metadata.RequiresValidation);
    }

    [Fact]
    public void Conventions_AddConventionMetadataThatIsNotAnAttribute()
    {
        // Conventions must be distinguishable from attributes, otherwise a broad convention such as
        // MapControllers().SkipHmacValidation() would override an explicit [RequireHmacValidation].
        var skip = new RecordingConventionBuilder();
        skip.SkipHmacValidation();
        var require = new RecordingConventionBuilder();
        require.RequireHmacValidation();

        Endpoint skipped = Build(skip);
        Endpoint required = Build(require);

        Assert.IsType<HmacValidationConventionMetadata>(skipped.Metadata.GetMetadata<IHmacValidationMetadata>());
        Assert.IsType<HmacValidationConventionMetadata>(required.Metadata.GetMetadata<IHmacValidationMetadata>());
        Assert.Null(skipped.Metadata.GetMetadata<SkipHmacValidationAttribute>());
        Assert.Null(required.Metadata.GetMetadata<RequireHmacValidationAttribute>());
        Assert.Empty(skipped.Metadata.OfType<Attribute>());
        Assert.Empty(required.Metadata.OfType<Attribute>());
    }

    [Fact]
    public void Conventions_AppliedToManyEndpoints_ShareImmutableMetadataInstances()
    {
        var first = new RecordingConventionBuilder();
        first.SkipHmacValidation().RequireHmacValidation();
        var second = new RecordingConventionBuilder();
        second.SkipHmacValidation().RequireHmacValidation();

        IHmacValidationMetadata[] firstMetadata = [.. Build(first).Metadata.GetOrderedMetadata<IHmacValidationMetadata>()];
        IHmacValidationMetadata[] secondMetadata = [.. Build(second).Metadata.GetOrderedMetadata<IHmacValidationMetadata>()];

        Assert.Equal(2, firstMetadata.Length);
        Assert.Same(HmacValidationConventionMetadata.Skip, firstMetadata[0]);
        Assert.Same(HmacValidationConventionMetadata.Require, firstMetadata[1]);
        Assert.Equal(firstMetadata, secondMetadata);
        Assert.False(HmacValidationConventionMetadata.Skip.RequiresValidation);
        Assert.True(HmacValidationConventionMetadata.Require.RequiresValidation);
    }

    [Fact]
    public void Conventions_AppliedAfterAttributeMetadata_KeepTheAttributeInTheCollection()
    {
        var builder = new RecordingConventionBuilder();
        builder.Add(endpoint => endpoint.Metadata.Add(new RequireHmacValidationAttribute()));
        builder.SkipHmacValidation();

        IHmacValidationMetadata[] metadata = [.. Build(builder).Metadata.GetOrderedMetadata<IHmacValidationMetadata>()];

        Assert.Collection(
            metadata,
            attribute => Assert.IsType<RequireHmacValidationAttribute>(attribute),
            convention => Assert.Same(HmacValidationConventionMetadata.Skip, convention));
    }

    [Fact]
    public void Conventions_AppliedInOrder_LastOneIsTheEffectiveMetadata()
    {
        var requireThenSkip = new RecordingConventionBuilder();
        requireThenSkip.RequireHmacValidation().SkipHmacValidation();
        var skipThenRequire = new RecordingConventionBuilder();
        skipThenRequire.SkipHmacValidation().RequireHmacValidation();

        Assert.False(Build(requireThenSkip).Metadata.GetMetadata<IHmacValidationMetadata>()!.RequiresValidation);
        Assert.True(Build(skipThenRequire).Metadata.GetMetadata<IHmacValidationMetadata>()!.RequiresValidation);
    }

    [Fact]
    public void SkipHmacValidation_NullBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("builder", () => HmacEndpointConventionBuilderExtensions.SkipHmacValidation<RecordingConventionBuilder>(null!));
    }

    [Fact]
    public void RequireHmacValidation_NullBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("builder", () => HmacEndpointConventionBuilderExtensions.RequireHmacValidation<RecordingConventionBuilder>(null!));
    }

    [Theory]
    [InlineData(typeof(SkipHmacValidationAttribute), false)]
    [InlineData(typeof(RequireHmacValidationAttribute), true)]
    public void ValidationAttributes_CanBeAppliedToClassesAndMethodsOnce_OnlyRequireIsInherited(Type attributeType, bool inherited)
    {
        // Fail closed: a skip declared on a base controller or base virtual method never exempts derived types, while a
        // requirement declared on a base controller protects every derived controller.
        AttributeUsageAttribute usage = Assert.Single(
            attributeType.GetCustomAttributes(typeof(AttributeUsageAttribute), inherit: false).Cast<AttributeUsageAttribute>());

        Assert.Equal(AttributeTargets.Class | AttributeTargets.Method, usage.ValidOn);
        Assert.False(usage.AllowMultiple);
        Assert.Equal(inherited, usage.Inherited);
    }

    [Fact]
    public void ValidationAttributes_ImplementValidationMetadata()
    {
        object skip = new SkipHmacValidationAttribute();
        object require = new RequireHmacValidationAttribute();

        Assert.False(Assert.IsAssignableFrom<IHmacValidationMetadata>(skip).RequiresValidation);
        Assert.True(Assert.IsAssignableFrom<IHmacValidationMetadata>(require).RequiresValidation);
    }

    [Fact]
    public void RouteGroup_EndpointConventionIsAppliedAfterGroupConvention()
    {
        using ServiceProvider services = new ServiceCollection().AddLogging().AddRouting().BuildServiceProvider();
        var dataSourceBuilder = new TestEndpointRouteBuilder(services);
        RouteGroupBuilder group = dataSourceBuilder.MapGroup("/b2b").RequireHmacValidation();
        group.MapGet("/ping", () => "pong").SkipHmacValidation();

        Endpoint endpoint = Assert.Single(dataSourceBuilder.DataSources.SelectMany(source => source.Endpoints));

        Assert.False(endpoint.Metadata.GetMetadata<IHmacValidationMetadata>()!.RequiresValidation);
    }

    private static Endpoint Build(RecordingConventionBuilder builder)
    {
        var endpointBuilder = new RouteEndpointBuilder(_ => Task.CompletedTask, RoutePatternFactory.Parse("/health"), order: 0);
        foreach (Action<EndpointBuilder> convention in builder.Conventions)
        {
            convention(endpointBuilder);
        }

        return endpointBuilder.Build();
    }

    private sealed class RecordingConventionBuilder : IEndpointConventionBuilder
    {
        public List<Action<EndpointBuilder>> Conventions { get; } = [];

        public void Add(Action<EndpointBuilder> convention) => Conventions.Add(convention);
    }

    private sealed class TestEndpointRouteBuilder(IServiceProvider services) : IEndpointRouteBuilder
    {
        public IServiceProvider ServiceProvider { get; } = services;

        public ICollection<EndpointDataSource> DataSources { get; } = [];

        public IApplicationBuilder CreateApplicationBuilder() => new ApplicationBuilder(ServiceProvider);
    }
}
