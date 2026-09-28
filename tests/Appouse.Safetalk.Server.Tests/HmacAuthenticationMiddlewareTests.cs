using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Appouse.Safetalk.Server.Tests;

public sealed class HmacAuthenticationMiddlewareTests : IDisposable
{
    private readonly ServiceProvider _plainServices = new ServiceCollection().AddLogging().BuildServiceProvider();
    private readonly ServiceProvider _problemDetailsServices = new ServiceCollection().AddLogging().AddProblemDetails().BuildServiceProvider();
    private readonly HmacServerOptions _options = new();
    private readonly HmacAuthenticationMiddleware _middleware;
    private int _nextCalls;

    public HmacAuthenticationMiddlewareTests()
    {
        _middleware = new HmacAuthenticationMiddleware(
            _ =>
            {
                _nextCalls++;
                return Task.CompletedTask;
            },
            new StaticOptionsMonitor<HmacServerOptions>(_options));
    }

    public static TheoryData<HmacValidationFailure> UnauthorizedFailures { get; } = new(
        HmacValidationFailure.None,
        HmacValidationFailure.MissingHeaders,
        HmacValidationFailure.InvalidTimestamp,
        HmacValidationFailure.TimestampOutOfRange,
        HmacValidationFailure.UnknownClient,
        HmacValidationFailure.InvalidRequestTarget,
        HmacValidationFailure.ContentLengthMismatch,
        HmacValidationFailure.InvalidSignature,
        HmacValidationFailure.ReplayDetected,
        HmacValidationFailure.UnsignedMethodOverride,
        HmacValidationFailure.BodyAlreadyConsumed);

    public void Dispose()
    {
        _plainServices.Dispose();
        _problemDetailsServices.Dispose();
    }

    [Theory]
    [MemberData(nameof(UnauthorizedFailures))]
    public async Task InvokeAsync_ValidationFails_Returns401WithChallengeAndDoesNotCallNext(HmacValidationFailure failure)
    {
        DefaultHttpContext context = CreateContext(_plainServices);

        await _middleware.InvokeAsync(context, new StubRequestValidator(CreateFailure(failure)));

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, context.Response.Headers.WWWAuthenticate.ToString());
        Assert.Equal(0, _nextCalls);
        Assert.Null(context.GetHmacClientId());
    }

    [Fact]
    public async Task InvokeAsync_PayloadTooLarge_Returns413WithoutChallenge()
    {
        DefaultHttpContext context = CreateContext(_plainServices);

        await _middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.PayloadTooLarge)));

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("WWW-Authenticate"));
        Assert.Equal(0, _nextCalls);
    }

    [Fact]
    public async Task InvokeAsync_FailureWithoutProblemDetailsService_WritesEmptyBody()
    {
        DefaultHttpContext context = CreateContext(_plainServices);

        await _middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.InvalidSignature)));

        Assert.Equal(0, context.Response.Body.Length);
        Assert.Null(context.Response.ContentType);
    }

    [Fact]
    public async Task InvokeAsync_FailureWithProblemDetailsService_WritesProblemDetailsWithoutRevealingReason()
    {
        DefaultHttpContext context = CreateContext(_problemDetailsServices);

        await _middleware.InvokeAsync(
            context,
            new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.UnknownClient, TestCredentials.ClientId)));

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.StartsWith("application/problem+json", context.Response.ContentType, StringComparison.Ordinal);
        string json = ReadResponseBody(context);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        Assert.Equal(401, root.GetProperty("status").GetInt32());
        Assert.Equal(ReasonPhrases.GetReasonPhrase(401), root.GetProperty("title").GetString());
        Assert.Equal("The request signature could not be verified.", root.GetProperty("detail").GetString());
        Assert.DoesNotContain(nameof(HmacValidationFailure.UnknownClient), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(TestCredentials.ClientId, json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvokeAsync_PayloadTooLargeWithProblemDetailsService_Writes413ProblemDetails()
    {
        DefaultHttpContext context = CreateContext(_problemDetailsServices);

        await _middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.PayloadTooLarge)));

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        using JsonDocument document = JsonDocument.Parse(ReadResponseBody(context));
        JsonElement root = document.RootElement;
        Assert.Equal(413, root.GetProperty("status").GetInt32());
        Assert.Equal(ReasonPhrases.GetReasonPhrase(413), root.GetProperty("title").GetString());
        Assert.False(root.TryGetProperty("detail", out _));
    }

    [Fact]
    public async Task InvokeAsync_ValidationSucceeds_CallsNextOnceAndAttachesClient()
    {
        DefaultHttpContext context = CreateContext(_plainServices);

        await _middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId)));

        Assert.Equal(1, _nextCalls);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal(TestCredentials.ClientId, context.GetHmacClientId());
        Assert.Equal(TestCredentials.ClientId, context.Features.Get<IHmacClientFeature>()?.ClientId);
    }

    [Fact]
    public async Task InvokeAsync_ValidationSucceeds_ReplacesAnonymousUserWithHmacPrincipal()
    {
        DefaultHttpContext context = CreateContext(_plainServices);

        await _middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId)));

        ClaimsPrincipal user = context.User;
        ClaimsIdentity identity = Assert.Single(user.Identities);
        Assert.True(identity.IsAuthenticated);
        Assert.Equal(HmacAuthenticationDefaults.AuthenticationType, identity.AuthenticationType);
        Assert.Equal(TestCredentials.ClientId, identity.Name);
        Assert.Equal(TestCredentials.ClientId, user.FindFirst(ClaimTypes.Name)?.Value);
        Assert.Equal(TestCredentials.ClientId, user.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        Assert.Equal(TestCredentials.ClientId, user.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value);
    }

    [Fact]
    public async Task InvokeAsync_UserAlreadyAuthenticated_KeepsPrimaryIdentityAndAddsHmacIdentity()
    {
        DefaultHttpContext context = CreateContext(_plainServices);
        var existing = new ClaimsIdentity([new Claim(ClaimTypes.Name, "alice")], "Bearer");
        context.User = new ClaimsPrincipal(existing);

        await _middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId)));

        ClaimsPrincipal user = context.User;
        Assert.Same(existing, user.Identity);
        Assert.Equal("alice", user.Identity!.Name);
        Assert.Equal(2, user.Identities.Count());
        ClaimsIdentity hmac = Assert.Single(user.Identities, i => i.AuthenticationType == HmacAuthenticationDefaults.AuthenticationType);
        Assert.True(hmac.IsAuthenticated);
        Assert.Equal(TestCredentials.ClientId, hmac.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value);
        Assert.Equal(TestCredentials.ClientId, user.FindFirst(HmacAuthenticationDefaults.ClientIdClaimType)?.Value);
    }

    [Fact]
    public async Task InvokeAsync_EndpointHasSkipMetadata_CallsNextWithoutValidating()
    {
        DefaultHttpContext context = CreateContext(_plainServices);
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(new SkipHmacValidationAttribute()), "health"));
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(0, validator.CallCount);
        Assert.Equal(1, _nextCalls);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Null(context.GetHmacClientId());
    }

    [Fact]
    public async Task InvokeAsync_EndpointWithoutSkipMetadata_Validates()
    {
        DefaultHttpContext context = CreateContext(_plainServices);
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(new object()), "orders"));
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(0, _nextCalls);
    }

    [Fact]
    public async Task InvokeAsync_PassesRequestAbortedTokenToValidator()
    {
        using var aborted = new CancellationTokenSource();
        DefaultHttpContext context = CreateContext(_plainServices);
        context.RequestAborted = aborted.Token;
        var validator = new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(aborted.Token, validator.LastCancellationToken);
    }

    [Fact]
    public void Constructor_NullArguments_ThrowArgumentNullException()
    {
        var options = new StaticOptionsMonitor<HmacServerOptions>(new HmacServerOptions());

        Assert.Throws<ArgumentNullException>("next", () => new HmacAuthenticationMiddleware(null!, options));
        Assert.Throws<ArgumentNullException>("options", () => new HmacAuthenticationMiddleware(_ => Task.CompletedTask, null!));
    }

    [Fact]
    public async Task InvokeAsync_NullArguments_ThrowArgumentNullException()
    {
        var validator = new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId));

        await Assert.ThrowsAsync<ArgumentNullException>("context", () => _middleware.InvokeAsync(null!, validator));
        await Assert.ThrowsAsync<ArgumentNullException>("validator", () => _middleware.InvokeAsync(CreateContext(_plainServices), null!));
    }

    [Fact]
    public async Task InvokeAsync_MarkedEndpointsOnly_EndpointWithoutMetadata_PassesThroughWithoutValidating()
    {
        _options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly;
        DefaultHttpContext context = CreateContext(_plainServices, new object());
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(0, validator.CallCount);
        Assert.Equal(1, _nextCalls);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Null(context.GetHmacClientId());
    }

    [Fact]
    public async Task InvokeAsync_PublicConstructorMarkedEndpointsOnly_NoEndpoint_ValidatesFailClosed()
    {
        // The public constructor (UseMiddleware<T>) cannot tell whether routing already ran: a missing endpoint may be
        // one that requires validation, so the request is validated in every mode.
        _options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly;
        DefaultHttpContext context = CreateContext(_plainServices);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(0, _nextCalls);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_RoutingBeforeMarkedEndpointsOnly_NoEndpoint_PassesThroughWithoutValidating()
    {
        // Routing is known to have run: no endpoint means no route matched (the request ends as 404).
        _options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly;
        int nextCalls = 0;
        var middleware = new HmacAuthenticationMiddleware(
            _ =>
            {
                nextCalls++;
                return Task.CompletedTask;
            },
            new StaticOptionsMonitor<HmacServerOptions>(_options),
            HmacAuthenticationMiddleware.RoutingOrder.Before,
            logger: null);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await middleware.InvokeAsync(CreateContext(_plainServices), validator);

        Assert.Equal(0, validator.CallCount);
        Assert.Equal(1, nextCalls);
    }

    [Fact]
    public async Task InvokeAsync_MarkedEndpointsOnly_RequireMetadata_ValidatesAndRejects()
    {
        _options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly;
        DefaultHttpContext context = CreateContext(_plainServices, new RequireHmacValidationAttribute());
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.InvalidSignature));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(0, _nextCalls);
    }

    [Fact]
    public async Task InvokeAsync_MarkedEndpointsOnly_RequireMetadata_ValidatesAndSignsIn()
    {
        _options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly;
        DefaultHttpContext context = CreateContext(_plainServices, new RequireHmacValidationAttribute());

        await _middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId)));

        Assert.Equal(1, _nextCalls);
        Assert.Equal(TestCredentials.ClientId, context.GetHmacClientId());
        Assert.Equal(TestCredentials.ClientId, context.User.Identity?.Name);
    }

    [Fact]
    public async Task InvokeAsync_AllRequests_RequireMetadata_Validates()
    {
        DefaultHttpContext context = CreateContext(_plainServices, new RequireHmacValidationAttribute());
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_AllRequests_NoEndpoint_Validates()
    {
        DefaultHttpContext context = CreateContext(_plainServices);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests, "skip,require", true)]
    [InlineData(HmacEnforcementMode.AllRequests, "require,skip", false)]
    [InlineData(HmacEnforcementMode.AllRequests, "skip,require,skip", false)]
    [InlineData(HmacEnforcementMode.AllRequests, "require,skip,require", true)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "skip,require", true)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "require,skip", false)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "require,other", true)]
    [InlineData(HmacEnforcementMode.AllRequests, "skip,other", false)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "custom-require", true)]
    [InlineData(HmacEnforcementMode.AllRequests, "custom-skip", false)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "require,custom-skip", false)]
    public async Task InvokeAsync_SeveralValidationMetadata_LastOneWins(HmacEnforcementMode mode, string metadata, bool expectValidation)
    {
        _options.EnforcementMode = mode;
        object[] items =
        [
            .. metadata.Split(',').Select<string, object>(item => item switch
            {
                "skip" => new SkipHmacValidationAttribute(),
                "require" => new RequireHmacValidationAttribute(),
                "custom-skip" => new CustomValidationMetadata(requiresValidation: false),
                "custom-require" => new CustomValidationMetadata(requiresValidation: true),
                _ => new object(),
            }),
        ];
        DefaultHttpContext context = CreateContext(_plainServices, items);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(expectValidation ? 1 : 0, validator.CallCount);
        Assert.Equal(expectValidation ? 0 : 1, _nextCalls);
    }

    [Fact]
    public async Task InvokeAsync_EnforcementModeChangedAtRuntime_IsReadForEveryRequest()
    {
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(CreateContext(_plainServices, new object()), validator);
        _options.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly;
        await _middleware.InvokeAsync(CreateContext(_plainServices, new object()), validator);
        _options.EnforcementMode = HmacEnforcementMode.AllRequests;
        await _middleware.InvokeAsync(CreateContext(_plainServices, new object()), validator);

        Assert.Equal(2, validator.CallCount);
        Assert.Equal(1, _nextCalls);
    }

    [Fact]
    public async Task InvokeAsync_UndefinedEnforcementMode_FailsClosedAndValidates()
    {
        // An out-of-range value (for example a cast integer) must not silently disable protection.
        _options.EnforcementMode = (HmacEnforcementMode)42;
        DefaultHttpContext context = CreateContext(_plainServices, new object());
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_RequestAlreadyVerifiedByThisLibrary_SkipsValidationEvenWhenRequired()
    {
        DefaultHttpContext context = CreateContext(_plainServices, new RequireHmacValidationAttribute());
        HmacClientIdentity.SetFeature(context, TestCredentials.ClientId);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.ReplayDetected));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(0, validator.CallCount);
        Assert.Equal(1, _nextCalls);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal(TestCredentials.ClientId, context.GetHmacClientId());
    }

    [Fact]
    public async Task InvokeAsync_ClientFeatureSetByOtherCode_IsNotTrustedAndRequestIsValidated()
    {
        DefaultHttpContext context = CreateContext(_plainServices);
        context.Features.Set<IHmacClientFeature>(new ForeignClientFeature(TestCredentials.ClientId));
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(0, _nextCalls);
    }

    [Fact]
    public async Task InvokeAsync_SameContextReExecutedAfterSuccess_ValidatesOnceAndDoesNotDuplicateIdentity()
    {
        DefaultHttpContext context = CreateContext(_plainServices);
        var validator = new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId));

        await _middleware.InvokeAsync(context, validator);
        context.SetEndpoint(null); // What UseExceptionHandler and UseStatusCodePagesWithReExecute do before re-executing.
        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(2, _nextCalls);
        Assert.Single(context.User.Identities);
        Assert.Equal(TestCredentials.ClientId, context.GetHmacClientId());
    }

    [Fact]
    public async Task InvokeAsync_SameContextReExecutedAfterFailure_ValidatesAgain()
    {
        DefaultHttpContext context = CreateContext(_plainServices);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.InvalidSignature));

        await _middleware.InvokeAsync(context, validator);
        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(2, validator.CallCount);
        Assert.Equal(0, _nextCalls);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests, "conv-skip", false)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "conv-require", true)]
    [InlineData(HmacEnforcementMode.AllRequests, "require,conv-skip", true)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "require,conv-skip", true)]
    [InlineData(HmacEnforcementMode.AllRequests, "skip,conv-require", false)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "skip,conv-require", false)]
    [InlineData(HmacEnforcementMode.AllRequests, "conv-skip,require", true)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "conv-require,skip", false)]
    [InlineData(HmacEnforcementMode.AllRequests, "conv-require,conv-skip", false)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "conv-skip,conv-require", true)]
    [InlineData(HmacEnforcementMode.AllRequests, "require,skip,conv-require", false)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "skip,require,conv-skip,conv-skip", true)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "custom-skip,conv-require", false)]
    [InlineData(HmacEnforcementMode.AllRequests, "conv-skip,custom-require,conv-skip", true)]
    [InlineData(HmacEnforcementMode.AllRequests, "conv-skip,other", false)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly, "conv-require,other", true)]
    public async Task InvokeAsync_AttributesAndCustomMetadataBeatConventions(HmacEnforcementMode mode, string metadata, bool expectValidation)
    {
        _options.EnforcementMode = mode;
        object[] items =
        [
            .. metadata.Split(',').Select<string, object>(item => item switch
            {
                "skip" => new SkipHmacValidationAttribute(),
                "require" => new RequireHmacValidationAttribute(),
                "conv-skip" => HmacValidationConventionMetadata.Skip,
                "conv-require" => HmacValidationConventionMetadata.Require,
                "custom-skip" => new CustomValidationMetadata(requiresValidation: false),
                "custom-require" => new CustomValidationMetadata(requiresValidation: true),
                _ => new object(),
            }),
        ];
        DefaultHttpContext context = CreateContext(_plainServices, items);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(expectValidation ? 1 : 0, validator.CallCount);
        Assert.Equal(expectValidation ? 0 : 1, _nextCalls);
    }

    [Theory]
    [InlineData(HmacEnforcementMode.AllRequests)]
    [InlineData(HmacEnforcementMode.MarkedEndpointsOnly)]
    public async Task InvokeAsync_RoutingAfter_ValidatesEveryRequestIgnoringSkipMetadata(HmacEnforcementMode mode)
    {
        _options.EnforcementMode = mode;
        int nextCalls = 0;
        var middleware = new HmacAuthenticationMiddleware(
            _ =>
            {
                nextCalls++;
                return Task.CompletedTask;
            },
            new StaticOptionsMonitor<HmacServerOptions>(_options),
            HmacAuthenticationMiddleware.RoutingOrder.After,
            logger: null);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await middleware.InvokeAsync(CreateContext(_plainServices), validator);
        await middleware.InvokeAsync(CreateContext(_plainServices, new SkipHmacValidationAttribute()), validator);
        await middleware.InvokeAsync(CreateContext(_plainServices, HmacValidationConventionMetadata.Skip), validator);
        await middleware.InvokeAsync(CreateContext(_plainServices, new object()), validator);

        Assert.Equal(4, validator.CallCount);
        Assert.Equal(0, nextCalls);
    }

    [Fact]
    public async Task InvokeAsync_RoutingAfter_SignedRequestIsAuthenticated()
    {
        int nextCalls = 0;
        var middleware = new HmacAuthenticationMiddleware(
            _ =>
            {
                nextCalls++;
                return Task.CompletedTask;
            },
            new StaticOptionsMonitor<HmacServerOptions>(new HmacServerOptions { EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly }),
            HmacAuthenticationMiddleware.RoutingOrder.After,
            logger: null);
        DefaultHttpContext context = CreateContext(_plainServices, new SkipHmacValidationAttribute());

        await middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Success(TestCredentials.ClientId)));

        Assert.Equal(1, nextCalls);
        Assert.Equal(TestCredentials.ClientId, context.User.Identity?.Name);
    }

    [Fact]
    public async Task InvokeAsync_RequestVerifiedEarlierByTheDefaultValidator_RegisteredValidatorReturnsCachedResultAndSignsInOnce()
    {
        // A custom caller ran the default validator: only the result is cached, nobody marked the request verified.
        var harness = new ValidatorHarness();
        DefaultHttpContext context = harness.NewRequest().Build();
        context.RequestServices = _plainServices;
        Assert.True((await harness.ValidateAsync(context)).Succeeded);
        Assert.Null(context.GetHmacClientId());
        context.Request.Body = new ThrowingReadStream(); // The cached result must be used: the body is not read again.

        await _middleware.InvokeAsync(context, harness.Validator);
        await _middleware.InvokeAsync(context, harness.Validator);

        Assert.Equal(2, _nextCalls);
        Assert.Equal(TestCredentials.ClientId, context.GetHmacClientId());
        ClaimsIdentity identity = Assert.Single(context.User.Identities);
        Assert.True(identity.IsAuthenticated);
        Assert.Equal(HmacAuthenticationDefaults.AuthenticationType, identity.AuthenticationType);
        Assert.Equal(TestCredentials.ClientId, identity.Name);
    }

    [Fact]
    public async Task InvokeAsync_RequestVerifiedEarlierByTheDefaultValidator_RegisteredValidatorRejecting_Returns401()
    {
        // An earlier success of the inner (default) validator must not bypass the registered validator, for example a
        // decorator that applies an IP allow-list on top of the signature check.
        var harness = new ValidatorHarness();
        DefaultHttpContext context = harness.NewRequest().Build();
        context.RequestServices = _plainServices;
        Assert.True((await harness.ValidateAsync(context)).Succeeded);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.UnknownClient, TestCredentials.ClientId));

        await _middleware.InvokeAsync(context, validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(0, _nextCalls);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Null(context.GetHmacClientId());
        Assert.False(context.User.Identity?.IsAuthenticated ?? false);
    }

    [Fact]
    public async Task InvokeAsync_RequestRejectedEarlierByTheDefaultValidator_IsRejectedWithTheCachedFailure()
    {
        var harness = new ValidatorHarness();
        DefaultHttpContext context = harness.NewRequest().Build(new string('0', HmacSha256SignatureService.SignatureHexLength));
        context.RequestServices = _plainServices;
        Assert.Equal(HmacValidationFailure.InvalidSignature, (await harness.ValidateAsync(context)).Failure);
        context.Request.Headers[SafetalkHeaderNames.Signature] = harness.NewRequest().Signature;

        await _middleware.InvokeAsync(context, harness.Validator);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(0, _nextCalls);
        Assert.Null(context.GetHmacClientId());
    }

    [Theory]
    [InlineData(HmacValidationFailure.InvalidRequestTarget)]
    [InlineData(HmacValidationFailure.ContentLengthMismatch)]
    [InlineData(HmacValidationFailure.UnsignedMethodOverride)]
    [InlineData(HmacValidationFailure.BodyAlreadyConsumed)]
    public async Task InvokeAsync_NewFailuresWithProblemDetails_Write401WithoutRevealingReason(HmacValidationFailure failure)
    {
        DefaultHttpContext context = CreateContext(_problemDetailsServices);

        await _middleware.InvokeAsync(context, new StubRequestValidator(HmacValidationResult.Fail(failure, TestCredentials.ClientId)));

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, context.Response.Headers.WWWAuthenticate.ToString());
        string json = ReadResponseBody(context);
        Assert.DoesNotContain(failure.ToString(), json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InvokeAsync_OptionsFromMonitorAreReadPerRequest()
    {
        var monitor = new MutableOptionsMonitor(new HmacServerOptions());
        int nextCalls = 0;
        var middleware = new HmacAuthenticationMiddleware(
            _ =>
            {
                nextCalls++;
                return Task.CompletedTask;
            },
            monitor);
        var validator = new StubRequestValidator(HmacValidationResult.Fail(HmacValidationFailure.MissingHeaders));

        await middleware.InvokeAsync(CreateContext(_plainServices, new object()), validator);
        monitor.CurrentValue = new HmacServerOptions { EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly };
        await middleware.InvokeAsync(CreateContext(_plainServices, new object()), validator);

        Assert.Equal(1, validator.CallCount);
        Assert.Equal(1, nextCalls);
    }

    private static HmacValidationResult CreateFailure(HmacValidationFailure failure) =>
        failure == HmacValidationFailure.None ? default : HmacValidationResult.Fail(failure, TestCredentials.ClientId);

    private static DefaultHttpContext CreateContext(IServiceProvider services, params object[] endpointMetadata)
    {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Response.Body = new MemoryStream();
        if (endpointMetadata.Length > 0)
        {
            context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(endpointMetadata), "test"));
        }

        return context;
    }

    private static string ReadResponseBody(HttpContext context) =>
        Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray());

    private sealed class CustomValidationMetadata(bool requiresValidation) : IHmacValidationMetadata
    {
        public bool RequiresValidation { get; } = requiresValidation;
    }

    private sealed class ForeignClientFeature(string clientId) : IHmacClientFeature
    {
        public string ClientId { get; } = clientId;
    }

    private sealed class MutableOptionsMonitor(HmacServerOptions value) : IOptionsMonitor<HmacServerOptions>
    {
        public HmacServerOptions CurrentValue { get; set; } = value;

        public HmacServerOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<HmacServerOptions, string?> listener) => null;
    }
}
