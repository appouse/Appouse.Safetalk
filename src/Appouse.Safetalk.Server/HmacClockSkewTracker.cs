namespace Appouse.Safetalk.Server;

/// <summary>
/// Caps the clock skew window while replay protection is enabled.
/// </summary>
/// <remarks>
/// Replay entries are kept for the widest window a timestamp can be accepted in. Entries recorded under a narrower
/// window cannot be extended afterwards (a distributed cache has already set their TTL), so widening
/// <see cref="HmacServerOptions.AllowedClockSkew"/> through a configuration reload would let requests accepted before
/// the change be replayed once their entries expire. The window therefore never exceeds the value in effect when the
/// first request was validated: it can be narrowed at runtime, while widening it requires a restart.
/// </remarks>
internal sealed class HmacClockSkewTracker(TimeSpan maxClockSkew)
{
    private int _wideningReported;

    /// <summary>
    /// Gets the widest window that can be in effect, which is also how long replay entries are kept.
    /// </summary>
    public TimeSpan MaxClockSkew { get; } = maxClockSkew;

    /// <summary>
    /// Returns the window to enforce for <paramref name="configuredClockSkew"/>, and whether this is the first time a
    /// configured value above the cap was seen (so that it is reported once).
    /// </summary>
    public TimeSpan GetEffectiveClockSkew(TimeSpan configuredClockSkew, out bool firstWideningAttempt)
    {
        if (configuredClockSkew <= MaxClockSkew)
        {
            firstWideningAttempt = false;
            return configuredClockSkew;
        }

        firstWideningAttempt = Interlocked.Exchange(ref _wideningReported, 1) == 0;
        return MaxClockSkew;
    }
}
