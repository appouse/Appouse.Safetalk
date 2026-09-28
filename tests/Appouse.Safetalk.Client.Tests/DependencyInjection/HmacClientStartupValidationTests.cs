using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Client.Tests.DependencyInjection;

/// <summary>
/// <c>AddHmacSigning</c> registers <c>ValidateOnStart</c>; the generic host runs <see cref="IStartupValidator"/> when
/// it starts, so misconfigured credentials fail fast instead of on the first request.
/// </summary>
public sealed class HmacClientStartupValidationTests
{
    private readonly ServiceCollection _services = new();

    [Fact]
    public void StartupValidator_ValidOptions_DoesNotThrow()
    {
        _services.AddHmacClient<OrdersApiClient>(options =>
        {
            options.ClientId = "orders-client";
            options.Secret = "orders-secret";
        });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);

        provider.GetRequiredService<IStartupValidator>().Validate();
    }

    [Fact]
    public void StartupValidator_InvalidTypedClientOptions_ThrowsOptionsValidationExceptionForThatClient()
    {
        _services.AddHmacClient<OrdersApiClient>(options =>
        {
            options.ClientId = "orders-client";
            options.Secret = string.Empty;
        });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IStartupValidator validator = provider.GetRequiredService<IStartupValidator>();

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(validator.Validate);

        Assert.Equal(nameof(OrdersApiClient), exception.OptionsName);
        Assert.Equal(typeof(HmacClientOptions), exception.OptionsType);
        Assert.Equal("Secret must be provided.", Assert.Single(exception.Failures));
    }

    [Fact]
    public void StartupValidator_OneOfSeveralClientsInvalid_ReportsOnlyTheInvalidClient()
    {
        _services.AddHmacClient<OrdersApiClient>(options =>
        {
            options.ClientId = "orders-client";
            options.Secret = "orders-secret";
        });
        _services.AddHmacClient<BillingApiClient>(options =>
        {
            options.ClientId = "billing\nclient";
            options.Secret = "billing-secret";
        });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IStartupValidator validator = provider.GetRequiredService<IStartupValidator>();

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(validator.Validate);

        Assert.Equal(nameof(BillingApiClient), exception.OptionsName);
    }

    [Fact]
    public void StartupValidator_SeveralInvalidClients_ReportsEveryClient()
    {
        _services.AddHttpClient("first").AddHmacSigning(_ => { });
        _services.AddHttpClient("second").AddHmacSigning(options => options.ClientId = "second-client");
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IStartupValidator validator = provider.GetRequiredService<IStartupValidator>();

        AggregateException exception = Assert.Throws<AggregateException>(validator.Validate);

        string[] names = [.. exception.InnerExceptions.Cast<OptionsValidationException>().Select(e => e.OptionsName).Order(StringComparer.Ordinal)];
        Assert.Equal(["first", "second"], names);
    }

    [Fact]
    public void StartupValidator_NamedClientWithoutCredentials_Throws()
    {
        _services.AddHttpClient("partner").AddHmacSigning(_ => { });
        using ServiceProvider provider = _services.BuildServiceProvider(validateScopes: true);
        IStartupValidator validator = provider.GetRequiredService<IStartupValidator>();

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(validator.Validate);

        Assert.Equal("partner", exception.OptionsName);
        Assert.Equal(["ClientId must be provided.", "Secret must be provided."], exception.Failures);
    }
}
