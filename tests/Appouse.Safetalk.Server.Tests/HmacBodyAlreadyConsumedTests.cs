using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// A form read before validation (for example by the form-field variant of <c>UseHttpMethodOverride()</c>) consumes a
/// body that cannot be rewound: the request is rejected with <see cref="HmacValidationFailure.BodyAlreadyConsumed"/>
/// instead of verifying whatever is left of the stream. A body made re-readable earlier still verifies.
/// </summary>
public sealed class HmacBodyAlreadyConsumedTests : IDisposable
{
    private const string FormPath = "/forms/orders";
    private const string AntiforgeryFormPath = "/forms/antiforgery";
    private const string FormContentType = "application/x-www-form-urlencoded";
    private const string MethodField = "_method";

    private readonly RecordingSecretProvider _secretProvider = RecordingSecretProvider.ForTestCredentials();
    private readonly LogCollector _logs = new();
    private readonly ValidatorHarness _harness;

    public HmacBodyAlreadyConsumedTests()
    {
        _harness = new ValidatorHarness(_secretProvider, logger: _logs.CreateLogger<HmacRequestValidator>());
    }

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public void Dispose() => _logs.Dispose();

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateAsync_FormReadFromNonSeekableBody_ReturnsBodyAlreadyConsumedWithoutTouchingTheBody(bool sendContentLength)
    {
        SignedRequestBuilder request = NewFormRequest();
        request.SendContentLength = sendContentLength;
        DefaultHttpContext context = await BuildFormRequestAsync(request, readForm: true);
        var body = (NonSeekableReadStream)context.Request.Body;
        long consumedByTheFormReader = body.BytesRead;

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(request.Body.Length, consumedByTheFormReader);
        Assert.Equal(HmacValidationFailure.BodyAlreadyConsumed, result.Failure);
        Assert.Equal(TestCredentials.ClientId, result.ClientId);
        Assert.Same(body, context.Request.Body); // Not wrapped by EnableBuffering.
        Assert.Equal(consumedByTheFormReader, body.BytesRead);
        Assert.Null(context.GetHmacClientId());
    }

    [Fact]
    public async Task ValidateAsync_FormReadInSmallChunks_IsStillRejected()
    {
        SignedRequestBuilder request = NewFormRequest();
        request.MaxBytesPerRead = 3;
        DefaultHttpContext context = await BuildFormRequestAsync(request, readForm: true);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.BodyAlreadyConsumed, result.Failure);
    }

    [Fact]
    public async Task ValidateAsync_BodyAlreadyConsumed_IsLoggedAndCachedForTheRequest()
    {
        DefaultHttpContext context = await BuildFormRequestAsync(NewFormRequest(), readForm: true);

        HmacValidationResult first = await _harness.ValidateAsync(context);
        context.Features.Set<IFormFeature>(null);
        HmacValidationResult second = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.BodyAlreadyConsumed, first.Failure);
        Assert.Equal(first, second);
        LogRecord log = Assert.Single(_logs.Find<HmacRequestValidator>(2));
        Assert.Equal(LogLevel.Warning, log.Level);
        Assert.Equal(HmacValidationFailure.BodyAlreadyConsumed, log.Properties["Failure"]);
        Assert.Equal(TestCredentials.ClientId, log.Properties["ClientId"]);
    }

    [Fact]
    public async Task ValidateAsync_FormContentTypeButFormNotRead_VerifiesAndTheFormIsStillReadable()
    {
        DefaultHttpContext context = await BuildFormRequestAsync(NewFormRequest(), readForm: false);
        Assert.True(context.Request.HasFormContentType); // Creates the form feature without reading the form.

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
        IFormCollection form = await context.Request.ReadFormAsync(CancellationToken);
        Assert.Equal("5", form["orderId"]);
        Assert.Equal("3", form["quantity"]);
    }

    [Fact]
    public async Task ValidateAsync_FormReadFromSeekableBody_RewindsAndVerifies()
    {
        // EnableBuffering() before the form was read: the stream can be rewound to the bytes that were signed.
        SignedRequestBuilder request = NewFormRequest();
        DefaultHttpContext context = request.Build();
        context.Request.ContentType = FormContentType;
        context.Request.EnableBuffering();
        IFormCollection form = await context.Request.ReadFormAsync(CancellationToken);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
        Assert.Equal(0, context.Request.Body.Position);
        Assert.Equal("5", form["orderId"]);
    }

    [Fact]
    public async Task ValidateAsync_EmptyBodyWithFormRead_VerifiesTheEmptyBody()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = [];
        DefaultHttpContext context = await BuildFormRequestAsync(request, readForm: true);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.True(result.Succeeded, result.Failure.ToString());
    }

    [Fact]
    public async Task ValidateAsync_UnknownClientWithConsumedForm_ReportsTheCheaperFailureFirst()
    {
        SignedRequestBuilder request = NewFormRequest();
        request.ClientId = "partner-z";
        DefaultHttpContext context = await BuildFormRequestAsync(request, readForm: true);

        HmacValidationResult result = await _harness.ValidateAsync(context);

        Assert.Equal(HmacValidationFailure.UnknownClient, result.Failure);
    }

    [Fact]
    public async Task Pipeline_AntiforgeryReadTheFormBeforeHmac_IsRejectedWith401InsteadOfThrowing()
    {
        // UseAntiforgery() placed before UseHmacAuthentication(): for an endpoint with [FromForm] parameters it reads the
        // form to find the token and, a partner sending none, records an invalid IAntiforgeryValidationFeature. The body
        // is consumed, so the request cannot be verified any more: it must be a clean 401, not an unhandled exception.
        await using TestApplication app = await StartAsync(
            pipeline =>
            {
                pipeline.UseAntiforgery();
                pipeline.UseHmacAuthentication();
            },
            services => services.AddAntiforgery());

        HttpRequestMessage request = CreateSignedFormPost(app, "orderId=5&quantity=3", sendContentLength: true, path: AntiforgeryFormPath);
        HttpResponseMessage? response = null;
        Exception? failure = await Record.ExceptionAsync(async () => response = await app.SendAsync(request));

        using (response)
        {
            Assert.Null(failure);
            Assert.Equal(HttpStatusCode.Unauthorized, response!.StatusCode);
            Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pipeline_FormFieldOverrideBeforeHmac_FormPostIsRejectedWithBodyAlreadyConsumed(bool sendContentLength)
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = MethodField });
            pipeline.UseHmacAuthentication();
        });

        using HttpResponseMessage response = await app.SendAsync(CreateSignedFormPost(app, "orderId=5&quantity=3", sendContentLength));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
        Assert.Equal(
            HmacValidationFailure.BodyAlreadyConsumed,
            Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Fact]
    public async Task Pipeline_FormFieldOverrideBeforeHmacAfterImplicitRouting_OverriddenMethodIsRejectedBeforeTheBody()
    {
        // The override is applied after the POST endpoint was selected: the method check fails before any body I/O.
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = MethodField });
            pipeline.UseHmacAuthentication();
        });

        using HttpResponseMessage response = await app.SendAsync(CreateSignedFormPost(app, $"orderId=5&{MethodField}=DELETE", sendContentLength: true, signedMethod: "DELETE"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, app.Services.GetRequiredService<RequestCounter>().Count);
        Assert.Equal(
            HmacValidationFailure.UnsignedMethodOverride,
            Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pipeline_FormFieldOverrideAfterHmac_FormPostVerifiesAndEndpointReadsTheForm(bool sendContentLength)
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHmacAuthentication();
            pipeline.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = MethodField });
        });

        using HttpResponseMessage response = await app.SendAsync(CreateSignedFormPost(app, "orderId=5&quantity=3", sendContentLength));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("POST orderId=5 quantity=3 partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pipeline_BodyBufferedBeforeFormFieldOverride_FormPostStillVerifies(bool sendContentLength)
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.Use(async (HttpContext context, RequestDelegate next) =>
            {
                context.Request.EnableBuffering();
                await next(context);
            });
            pipeline.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = MethodField });
            pipeline.UseHmacAuthentication();
        });

        using HttpResponseMessage response = await app.SendAsync(CreateSignedFormPost(app, "orderId=5&quantity=3", sendContentLength));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("POST orderId=5 quantity=3 partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.True(Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Succeeded);
    }

    [Fact]
    public async Task Pipeline_BodyBufferedAndFormFieldOverrideBeforeExplicitRouting_OverridingMethodIsVerified()
    {
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.Use(async (HttpContext context, RequestDelegate next) =>
            {
                context.Request.EnableBuffering();
                await next(context);
            });
            pipeline.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = MethodField });
            pipeline.UseRouting();
            pipeline.UseHmacAuthentication();
        });

        using HttpResponseMessage signedForDelete = await app.SendAsync(
            CreateSignedFormPost(app, $"orderId=5&{MethodField}=DELETE", sendContentLength: true, signedMethod: "DELETE"));
        using HttpResponseMessage signedForPost = await app.SendAsync(
            CreateSignedFormPost(app, $"orderId=6&{MethodField}=DELETE", sendContentLength: true, signedMethod: "POST"));

        Assert.Equal(HttpStatusCode.OK, signedForDelete.StatusCode);
        Assert.Equal("DELETE orderId=5 partner-a", await signedForDelete.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal(HttpStatusCode.Unauthorized, signedForPost.StatusCode);
        Assert.Equal(
            [HmacValidationFailure.None, HmacValidationFailure.InvalidSignature],
            app.Services.GetRequiredService<ValidationRecorder>().Results.Select(result => result.Failure));
    }

    [Fact]
    public async Task Pipeline_FormFieldOverrideBeforeAuthenticationHandler_ProtectedEndpointReturns401()
    {
        // The AddHmac() scheme uses the same validator: a consumed form fails authentication, and the authorization
        // challenge answers 401.
        await using TestApplication app = await TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
                builder.Services.AddValidationRecorder();
                builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
                builder.Services.AddAuthorization();
            },
            pipeline =>
            {
                pipeline.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = MethodField });
                pipeline.UseAuthentication();
                pipeline.UseAuthorization();
                pipeline.MapPost(FormPath, (HttpContext context) => context.User.Identity?.Name ?? "anonymous").RequireAuthorization();
            });

        using HttpResponseMessage response = await app.SendAsync(CreateSignedFormPost(app, "orderId=5", sendContentLength: true));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HmacAuthenticationDefaults.ChallengeScheme, Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.Equal(
            HmacValidationFailure.BodyAlreadyConsumed,
            Assert.Single(app.Services.GetRequiredService<ValidationRecorder>().Results).Failure);
    }

    [Fact]
    public async Task Pipeline_HeaderVariantOfOverrideBeforeHmac_FormPostWithoutOverrideVerifies()
    {
        // Only the form-field variant reads the body; the header variant leaves it untouched.
        await using TestApplication app = await StartAsync(pipeline =>
        {
            pipeline.UseHttpMethodOverride();
            pipeline.UseHmacAuthentication();
        });

        using HttpResponseMessage response = await app.SendAsync(CreateSignedFormPost(app, "orderId=5&quantity=3", sendContentLength: true));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("POST orderId=5 quantity=3 partner-a", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    private SignedRequestBuilder NewFormRequest()
    {
        SignedRequestBuilder request = _harness.NewRequest();
        request.Body = "orderId=5&quantity=3"u8.ToArray();
        return request;
    }

    private static async Task<DefaultHttpContext> BuildFormRequestAsync(SignedRequestBuilder request, bool readForm)
    {
        DefaultHttpContext context = request.Build();
        context.Request.ContentType = FormContentType;
        if (readForm)
        {
            await context.Request.ReadFormAsync(CancellationToken);
        }

        return context;
    }

    private static HttpRequestMessage CreateSignedFormPost(
        TestApplication app,
        string form,
        bool sendContentLength,
        string signedMethod = "POST",
        string path = FormPath)
    {
        byte[] body = Encoding.ASCII.GetBytes(form);
        HttpContent content = sendContentLength ? new ByteArrayContent(body) : new UnknownLengthContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(FormContentType);
        string timestamp = TestCredentials.FormatTimestamp(app.Time.GetUtcNow().ToUnixTimeSeconds());
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(path, UriKind.Relative)) { Content = content };
        request.Headers.Add(SafetalkHeaderNames.ClientId, TestCredentials.ClientId);
        request.Headers.Add(SafetalkHeaderNames.Timestamp, timestamp);
        request.Headers.Add(SafetalkHeaderNames.Signature, TestCredentials.Sign(signedMethod, path, timestamp, body));
        return request;
    }

    private static string DescribeForm(HttpContext context, IFormCollection form) =>
        string.Join(' ', [context.Request.Method, .. form.Where(field => field.Key != MethodField).Select(field => $"{field.Key}={field.Value}"), context.GetHmacClientId() ?? "anonymous"]);

    private static Task<TestApplication> StartAsync(Action<WebApplication> configurePipeline, Action<IServiceCollection>? configureServices = null) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddHmacServer().AddInMemorySecrets(TestCredentials.Secrets);
                builder.Services.AddValidationRecorder();
                configureServices?.Invoke(builder.Services);
            },
            app =>
            {
                configurePipeline(app);
                RequestCounter counter = app.Services.GetRequiredService<RequestCounter>();
                app.MapPost(FormPath, async (HttpContext context) =>
                {
                    counter.Increment();
                    return DescribeForm(context, await context.Request.ReadFormAsync(context.RequestAborted));
                });
                app.MapDelete(FormPath, async (HttpContext context) =>
                {
                    counter.Increment();
                    return DescribeForm(context, await context.Request.ReadFormAsync(context.RequestAborted));
                });
                app.MapPost(AntiforgeryFormPath, ([FromForm] string orderId, HttpContext context) =>
                {
                    counter.Increment();
                    return $"{orderId} {context.GetHmacClientId()}";
                });
            });
}
