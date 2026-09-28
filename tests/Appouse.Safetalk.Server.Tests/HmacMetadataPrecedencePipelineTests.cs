using System.Net;
using Appouse.Safetalk.Server.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Appouse.Safetalk.Server.Tests;

/// <summary>
/// The documented precedence rule, end to end: attributes and custom <see cref="IHmacValidationMetadata"/> beat the
/// <c>SkipHmacValidation()</c>/<c>RequireHmacValidation()</c> conventions; within each kind the last (most specific)
/// one wins; without any metadata the enforcement mode decides.
/// </summary>
public sealed class HmacMetadataPrecedencePipelineTests
{
    private static readonly (string Path, bool? Expected)[] MinimalApiCases =
    [
        // No metadata: the enforcement mode decides.
        ("/ep/plain", null),

        // One endpoint, several kinds of metadata.
        ("/ep/attr-require-conv-skip", true),
        ("/ep/attr-skip-conv-require", false),
        ("/ep/conv-skip-conv-require", true),
        ("/ep/conv-require-conv-skip", false),
        ("/ep/custom-skip-conv-require", false),
        ("/ep/custom-require-conv-skip", true),
        ("/ep/conv-skip-custom-require", true),

        // Route group conventions are overridden by endpoint conventions and by handler attributes.
        ("/g-req/plain", true),
        ("/g-req/conv-skip", false),
        ("/g-req/attr-skip", false),
        ("/g-req/attr-skip-conv-require", false),
        ("/g-skip/plain", false),
        ("/g-skip/conv-require", true),
        ("/g-skip/attr-require", true),
        ("/g-skip/attr-require-conv-skip", true),

        // Nested groups: the inner group is more specific.
        ("/outer-req/inner-skip/plain", false),
        ("/outer-req/inner-skip/conv-require", true),
        ("/outer-skip/inner-req/plain", true),
        ("/outer-skip/inner-req/conv-skip", false),

        // Attribute metadata added to a group (WithMetadata) is attribute-kind: it beats every convention, and the
        // handler attribute (added after group metadata) beats it.
        ("/g-meta-require/conv-skip", true),
        ("/g-meta-require/attr-skip", false),
        ("/g-meta-skip/conv-require", false),
        ("/g-meta-skip/attr-require", true),
    ];

    private static readonly (string Path, bool UnderSkipConvention, bool UnderRequireConvention)[] ControllerCases =
    [
        ("/mvc/probe/protected", false, true),
        ("/mvc/probe/public", false, false),
        ("/mvc/open", false, false),
        ("/mvc/required/default", true, true),
        ("/mvc/required/skipped", false, false),
        ("/mvc/skipped/default", false, false),
        ("/mvc/skipped/required", true, true),
        ("/mvc/inherited", true, true),
        ("/mvc/inherited/skipped", false, false),
    ];

    public enum ControllerConvention
    {
        Skip,
        Require,
    }

    public static TheoryData<HmacEnforcementMode, string, bool> MinimalApiMatrix
    {
        get
        {
            var data = new TheoryData<HmacEnforcementMode, string, bool>();
            foreach (HmacEnforcementMode mode in Enum.GetValues<HmacEnforcementMode>())
            {
                foreach ((string path, bool? expected) in MinimalApiCases)
                {
                    data.Add(mode, path, expected ?? mode == HmacEnforcementMode.AllRequests);
                }
            }

            return data;
        }
    }

    public static TheoryData<HmacEnforcementMode, ControllerConvention, string, bool> ControllerMatrix
    {
        get
        {
            var data = new TheoryData<HmacEnforcementMode, ControllerConvention, string, bool>();
            foreach (HmacEnforcementMode mode in Enum.GetValues<HmacEnforcementMode>())
            {
                foreach ((string path, bool underSkip, bool underRequire) in ControllerCases)
                {
                    data.Add(mode, ControllerConvention.Skip, path, underSkip);
                    data.Add(mode, ControllerConvention.Require, path, underRequire);
                }
            }

            return data;
        }
    }

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Theory]
    [MemberData(nameof(MinimalApiMatrix))]
    public async Task MinimalApis_MetadataPrecedence(HmacEnforcementMode mode, string path, bool expectValidation)
    {
        await using TestApplication app = await StartAsync(mode, controllers: null);

        await AssertEnforcementAsync(app, path, expectValidation);
    }

    [Theory]
    [MemberData(nameof(ControllerMatrix))]
    public async Task Controllers_AttributesBeatMapControllersConventions(
        HmacEnforcementMode mode,
        ControllerConvention convention,
        string path,
        bool expectValidation)
    {
        await using TestApplication app = await StartAsync(mode, convention);

        await AssertEnforcementAsync(app, path, expectValidation);
    }

    private static async Task AssertEnforcementAsync(TestApplication app, string path, bool expectValidation)
    {
        using HttpResponseMessage unsigned = await app.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri(path, UriKind.Relative)));
        using HttpResponseMessage signed = await app.SendAsync(app.CreateSignedRequest(HttpMethod.Get, path));

        string signedBody = await signed.Content.ReadAsStringAsync(CancellationToken);
        if (expectValidation)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
            Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
            Assert.Equal(TestCredentials.ClientId, signedBody);
        }
        else
        {
            Assert.Equal(HttpStatusCode.OK, unsigned.StatusCode);
            Assert.Equal("anonymous", await unsigned.Content.ReadAsStringAsync(CancellationToken));
            Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
            Assert.Equal("anonymous", signedBody);
        }
    }

    private static string Who(HttpContext context) => context.GetHmacClientId() ?? "anonymous";

    private static Task<TestApplication> StartAsync(HmacEnforcementMode mode, ControllerConvention? controllers) =>
        TestApplication.StartAsync(
            builder =>
            {
                builder.Services.AddControllers().AddApplicationPart(typeof(ProbeController).Assembly);
                builder.Services
                    .AddHmacServer(options => options.EnforcementMode = mode)
                    .AddInMemorySecrets(TestCredentials.Secrets);
            },
            app =>
            {
                app.UseHmacAuthentication();

                if (controllers is null)
                {
                    MapMinimalApis(app);
                }
                else if (controllers == ControllerConvention.Skip)
                {
                    app.MapControllers().SkipHmacValidation();
                }
                else
                {
                    app.MapControllers().RequireHmacValidation();
                }
            });

    private static void MapMinimalApis(IEndpointRouteBuilder app)
    {
        app.MapGet("/ep/plain", Who);
        app.MapGet("/ep/attr-require-conv-skip", [RequireHmacValidation] (HttpContext context) => Who(context)).SkipHmacValidation();
        app.MapGet("/ep/attr-skip-conv-require", [SkipHmacValidation] (HttpContext context) => Who(context)).RequireHmacValidation();
        app.MapGet("/ep/conv-skip-conv-require", Who).SkipHmacValidation().RequireHmacValidation();
        app.MapGet("/ep/conv-require-conv-skip", Who).RequireHmacValidation().SkipHmacValidation();
        app.MapGet("/ep/custom-skip-conv-require", Who).WithMetadata(new CustomMetadata(false)).RequireHmacValidation();
        app.MapGet("/ep/custom-require-conv-skip", Who).WithMetadata(new CustomMetadata(true)).SkipHmacValidation();
        app.MapGet("/ep/conv-skip-custom-require", Who).SkipHmacValidation().WithMetadata(new CustomMetadata(true));

        RouteGroupBuilder required = app.MapGroup("/g-req").RequireHmacValidation();
        required.MapGet("/plain", Who);
        required.MapGet("/conv-skip", Who).SkipHmacValidation();
        required.MapGet("/attr-skip", [SkipHmacValidation] (HttpContext context) => Who(context));
        required.MapGet("/attr-skip-conv-require", [SkipHmacValidation] (HttpContext context) => Who(context)).RequireHmacValidation();

        RouteGroupBuilder skipped = app.MapGroup("/g-skip").SkipHmacValidation();
        skipped.MapGet("/plain", Who);
        skipped.MapGet("/conv-require", Who).RequireHmacValidation();
        skipped.MapGet("/attr-require", [RequireHmacValidation] (HttpContext context) => Who(context));
        skipped.MapGet("/attr-require-conv-skip", [RequireHmacValidation] (HttpContext context) => Who(context)).SkipHmacValidation();

        RouteGroupBuilder innerSkip = app.MapGroup("/outer-req").RequireHmacValidation().MapGroup("/inner-skip").SkipHmacValidation();
        innerSkip.MapGet("/plain", Who);
        innerSkip.MapGet("/conv-require", Who).RequireHmacValidation();

        RouteGroupBuilder innerRequire = app.MapGroup("/outer-skip").SkipHmacValidation().MapGroup("/inner-req").RequireHmacValidation();
        innerRequire.MapGet("/plain", Who);
        innerRequire.MapGet("/conv-skip", Who).SkipHmacValidation();

        RouteGroupBuilder metaRequire = app.MapGroup("/g-meta-require").WithMetadata(new RequireHmacValidationAttribute());
        metaRequire.MapGet("/conv-skip", Who).SkipHmacValidation();
        metaRequire.MapGet("/attr-skip", [SkipHmacValidation] (HttpContext context) => Who(context));

        RouteGroupBuilder metaSkip = app.MapGroup("/g-meta-skip").WithMetadata(new SkipHmacValidationAttribute());
        metaSkip.MapGet("/conv-require", Who).RequireHmacValidation();
        metaSkip.MapGet("/attr-require", [RequireHmacValidation] (HttpContext context) => Who(context));
    }

    private sealed class CustomMetadata(bool requiresValidation) : IHmacValidationMetadata
    {
        public bool RequiresValidation { get; } = requiresValidation;
    }
}
