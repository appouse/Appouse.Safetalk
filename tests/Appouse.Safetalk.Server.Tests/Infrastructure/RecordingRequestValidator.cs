using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Appouse.Safetalk.Server.Tests.Infrastructure;

/// <summary>
/// Collects the results of every validation performed in an application, so tests can prove how often (and why)
/// a request was validated.
/// </summary>
public sealed class ValidationRecorder
{
    private readonly List<HmacValidationResult> _results = [];
    private readonly object _gate = new();

    public IReadOnlyList<HmacValidationResult> Results
    {
        get
        {
            lock (_gate)
            {
                return [.. _results];
            }
        }
    }

    public void Add(HmacValidationResult result)
    {
        lock (_gate)
        {
            _results.Add(result);
        }
    }
}

/// <summary>
/// Decorates the default <see cref="HmacRequestValidator"/> and records its results.
/// </summary>
internal sealed class RecordingRequestValidator(IHmacRequestValidator inner, ValidationRecorder recorder) : IHmacRequestValidator
{
    public async ValueTask<HmacValidationResult> ValidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        HmacValidationResult result = await inner.ValidateAsync(context, cancellationToken);
        recorder.Add(result);
        return result;
    }
}

internal static class RecordingRequestValidatorExtensions
{
    /// <summary>
    /// Replaces the registered <see cref="IHmacRequestValidator"/> with a recording decorator over that registration
    /// (the internal <c>DefaultHmacRequestValidator</c> type registered by <c>AddHmacServer()</c>, so the decorated
    /// validator is the one applications get, clock skew cap included) and registers the <see cref="ValidationRecorder"/>.
    /// Call it after <c>AddHmacServer()</c>.
    /// </summary>
    public static IServiceCollection AddValidationRecorder(this IServiceCollection services)
    {
        services.TryAddSingleton<ValidationRecorder>();
        return services.DecorateRequestValidator((provider, inner) => new RecordingRequestValidator(
            inner,
            provider.GetRequiredService<ValidationRecorder>()));
    }

    /// <summary>
    /// Replaces the registered <see cref="IHmacRequestValidator"/> (scoped) with <paramref name="decorate"/> applied to
    /// an instance of that registration, the way an application decorates the validator (for example with Scrutor).
    /// </summary>
    public static IServiceCollection DecorateRequestValidator(
        this IServiceCollection services,
        Func<IServiceProvider, IHmacRequestValidator, IHmacRequestValidator> decorate)
    {
        ServiceDescriptor registration = services.Last(descriptor => descriptor.ServiceType == typeof(IHmacRequestValidator));
        services.RemoveAll<IHmacRequestValidator>();
        services.AddScoped<IHmacRequestValidator>(provider => decorate(provider, CreateInner(registration, provider)));
        return services;
    }

    private static IHmacRequestValidator CreateInner(ServiceDescriptor registration, IServiceProvider provider)
    {
        if (registration.ImplementationFactory is { } factory)
        {
            return (IHmacRequestValidator)factory(provider);
        }

        if (registration.ImplementationInstance is IHmacRequestValidator instance)
        {
            return instance;
        }

        return (IHmacRequestValidator)ActivatorUtilities.CreateInstance(provider, registration.ImplementationType!);
    }
}
