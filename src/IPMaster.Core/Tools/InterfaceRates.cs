namespace IPMaster.Core.Tools;

/// <summary>One IF-MIB counter reading of one interface (D-091). Counters are null when the agent did not return them.</summary>
public sealed record InterfaceCounters
{
    public required int Index { get; init; }

    /// <summary>When the reply arrived (local clock).</summary>
    public required DateTimeOffset At { get; init; }

    /// <summary>sysUpTime.0 in hundredths of a second (the agent's clock); null when not returned.</summary>
    public uint? UpTime { get; init; }

    /// <summary>64-bit ifHC*Octets (true) or 32-bit if*Octets (false).</summary>
    public bool HighCapacity { get; init; }

    public ulong? InOctets { get; init; }

    public ulong? OutOctets { get; init; }

    public ulong? InErrors { get; init; }

    public ulong? OutErrors { get; init; }

    public ulong? InDiscards { get; init; }

    public ulong? OutDiscards { get; init; }

    /// <summary>Interface speed in bit/s (ifHighSpeed × 10^6, else ifSpeed); 0 or null when unknown.</summary>
    public ulong? SpeedBitsPerSecond { get; init; }

    public string OperStatus { get; init; } = "";
}

public enum RateStatus
{
    /// <summary>Rates computed from two readings.</summary>
    Ok,

    /// <summary>The first reading: nothing to compare with yet.</summary>
    First,

    /// <summary>A 32-bit counter wrapped once; the rate accounts for it.</summary>
    Wrapped,

    /// <summary>A counter went backwards (reset, 64-bit counter, or more than one possible wrap): no rate for this interval.</summary>
    Discontinuity,

    /// <summary>sysUpTime went backwards: the device (or its agent) restarted; no rate for this interval.</summary>
    Restarted,
}

public sealed record InterfaceRate(DateTimeOffset At, RateStatus Status, TimeSpan Elapsed, double? InBitsPerSecond, double? OutBitsPerSecond,
    double? InUtilisation, double? OutUtilisation, double? InErrorsPerSecond, double? OutErrorsPerSecond, double? InDiscardsPerSecond,
    double? OutDiscardsPerSecond, string Note);

/// <summary>
/// Bandwidth from two counter readings (D-091). The interval is measured, never assumed: the agent's sysUpTime difference
/// when both readings have it (not affected by polling or network delay), else the local reply times. A 32-bit counter
/// that went backwards is taken as one wrap only when the resulting rate does not exceed the interface speed (or 10 Gbit/s
/// when the speed is unknown); a 64-bit counter going backwards is a reset. sysUpTime going backwards is a restart, except
/// its own wrap after 497 days.
/// </summary>
public static class InterfaceRates
{
    private const double UnknownSpeedLimit = 10e9;

    public static InterfaceRate Compute(InterfaceCounters? previous, InterfaceCounters current)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (previous is null || previous.Index != current.Index)
        {
            return Empty(current.At, RateStatus.First, TimeSpan.Zero, "First reading.");
        }

        if (previous.UpTime is { } u0 && current.UpTime is { } u1 && u1 < u0 && u0 < 0xF000_0000)
        {
            return Empty(current.At, RateStatus.Restarted, current.At - previous.At, "sysUpTime went backwards: the device or its SNMP agent restarted; counters start again.");
        }

        var elapsed = previous.UpTime is { } a && current.UpTime is { } b
            ? TimeSpan.FromMilliseconds(unchecked(b - a) * 10.0) // the agent's clock; unchecked covers the 497-day wrap
            : current.At - previous.At;
        if (elapsed <= TimeSpan.Zero) return Empty(current.At, RateStatus.Discontinuity, elapsed, "No time passed between the readings.");

        var seconds = elapsed.TotalSeconds;
        var limit = current.SpeedBitsPerSecond is > 0 ? current.SpeedBitsPerSecond.Value * 1.05 : UnknownSpeedLimit;
        var wrapped = false;
        var broken = false;

        double? Bits(ulong? p, ulong? c)
        {
            if (p is not { } x || c is not { } y) return null;
            if (y >= x) return (y - x) * 8.0 / seconds;
            if (!current.HighCapacity && previous.HighCapacity == current.HighCapacity && x <= uint.MaxValue)
            {
                var rate = (y + (1UL << 32) - x) * 8.0 / seconds;
                if (rate <= limit)
                {
                    wrapped = true;
                    return rate;
                }
            }

            broken = true;
            return null;
        }

        double? PerSecond(ulong? p, ulong? c)
        {
            if (p is not { } x || c is not { } y) return null;
            if (y >= x) return (y - x) / seconds;
            broken = true; // error counters are 32-bit and rarely wrap; going backwards means a reset
            return null;
        }

        if (previous.HighCapacity != current.HighCapacity) return Empty(current.At, RateStatus.Discontinuity, elapsed, "The agent switched between 64-bit and 32-bit counters.");
        var inBits = Bits(previous.InOctets, current.InOctets);
        var outBits = Bits(previous.OutOctets, current.OutOctets);
        var inErr = PerSecond(previous.InErrors, current.InErrors);
        var outErr = PerSecond(previous.OutErrors, current.OutErrors);
        var inDisc = PerSecond(previous.InDiscards, current.InDiscards);
        var outDisc = PerSecond(previous.OutDiscards, current.OutDiscards);
        if (broken)
        {
            return Empty(current.At, RateStatus.Discontinuity, elapsed,
                "A counter went backwards (counter reset or cleared, or several wraps between readings): this interval is skipped.");
        }

        double? Util(double? bits) => bits is { } v && current.SpeedBitsPerSecond is > 0 ? Math.Min(100, v / current.SpeedBitsPerSecond.Value * 100) : null;
        return new InterfaceRate(current.At, wrapped ? RateStatus.Wrapped : RateStatus.Ok, elapsed, inBits, outBits, Util(inBits), Util(outBits),
            inErr, outErr, inDisc, outDisc, wrapped ? "A 32-bit counter wrapped once (accounted for)." : "");
    }

    /// <summary>"12.3 Mbit/s" style.</summary>
    public static string FormatBits(double? bitsPerSecond) => bitsPerSecond switch
    {
        null => "—",
        >= 1e9 => $"{bitsPerSecond / 1e9:0.00} Gbit/s",
        >= 1e6 => $"{bitsPerSecond / 1e6:0.00} Mbit/s",
        >= 1e3 => $"{bitsPerSecond / 1e3:0.0} kbit/s",
        _ => $"{bitsPerSecond:0} bit/s",
    };

    private static InterfaceRate Empty(DateTimeOffset at, RateStatus s, TimeSpan elapsed, string note) =>
        new(at, s, elapsed, null, null, null, null, null, null, null, null, note);
}
