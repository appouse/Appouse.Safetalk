WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddProblemDetails(); // 401/413 responses are written as RFC 9457 problem details.

// Options and client secrets come from the "Safetalk" section (reloadable, e.g. from Azure Key Vault).
// For a database-backed store use: .AddSecretProvider<DatabaseSecretProvider>()
// For several instances use:       .AddReplayProtection<RedisReplayCache>()
builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));

WebApplication app = builder.Build();

app.UseHmacAuthentication(); // After (implicit) routing, before the endpoints.
app.UseAuthorization();      // Explicit, so that authorization runs after HMAC validation.

app.MapGet("/health", () => TypedResults.Ok("Healthy")).SkipHmacValidation();
app.MapControllers();

app.Run();
