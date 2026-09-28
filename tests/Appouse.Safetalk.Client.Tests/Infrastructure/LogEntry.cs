using Microsoft.Extensions.Logging;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

internal sealed record LogEntry(LogLevel Level, EventId EventId, string Message);
