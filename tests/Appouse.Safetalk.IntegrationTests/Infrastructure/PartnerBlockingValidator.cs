using System.Collections.Concurrent;
using Appouse.Safetalk.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Appouse.Safetalk.IntegrationTests.Infrastructure;

/// <summary>
/// An application-defined <see cref="IHmacRequestValidator"/> decorator (like an IP allow-list or a suspended-partner
/// check): it rejects a client whose signature the library verified successfully.
/// </summary>
internal sealed class PartnerBlockingValidator(IHmacRequestValidator inner, string blockedClientId, DecoratorDecisions decisions) : IHmacRequestValidator
{
    public async ValueTask<HmacValidationResult> ValidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        HmacValidationResult result = await inner.ValidateAsync(context, cancellationToken);
        if (result.Succeeded && string.Equals(result.ClientId, blockedClientId, StringComparison.Ordinal))
        {
            result = HmacValidationResult.Fail(HmacValidationFailure.UnknownClient, result.ClientId);
        }

        decisions.Add(new DecoratorDecision(context.Request.Path.Value ?? string.Empty, result));
        return result;
    }

    /// <summary>
    /// Decorates the <see cref="IHmacRequestValidator"/> registered so far (the harness's recording wrapper around the
    /// library's validator), exactly as an application would decorate the library's registration.
    /// </summary>
    public static void Decorate(IServiceCollection services, string blockedClientId, DecoratorDecisions decisions)
    {
        ServiceDescriptor registered = services.Last(descriptor => descriptor.ServiceType == typeof(IHmacRequestValidator));
        Func<IServiceProvider, object> createInner = registered.ImplementationFactory
            ?? throw new InvalidOperationException("The harness registers the validator through a factory.");

        services.RemoveAll<IHmacRequestValidator>();
        services.AddScoped<IHmacRequestValidator>(serviceProvider => new PartnerBlockingValidator(
            (IHmacRequestValidator)createInner(serviceProvider),
            blockedClientId,
            decisions));
    }
}

/// <summary>Every answer given by <see cref="PartnerBlockingValidator"/>, in order.</summary>
internal sealed class DecoratorDecisions
{
    private readonly ConcurrentQueue<DecoratorDecision> _decisions = new();

    public IReadOnlyCollection<DecoratorDecision> All => _decisions;

    public void Add(DecoratorDecision decision) => _decisions.Enqueue(decision);
}

/// <summary>One answer of <see cref="PartnerBlockingValidator"/>.</summary>
internal sealed record DecoratorDecision(string Path, HmacValidationResult Result);
