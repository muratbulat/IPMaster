using IPMaster.Core.Tools;

namespace IPMaster.Tests;

/// <summary>SNMP interface bandwidth math (D-091): measured intervals, wraps, resets and restarts.</summary>
public class InterfaceRatesTests
{
    private static readonly DateTimeOffset T = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);

    private static InterfaceCounters C(double seconds, ulong inOctets, ulong outOctets, uint? upTime = null, bool hc = true, ulong speed = 1_000_000_000,
        ulong inErrors = 0) => new()
        {
            Index = 3, At = T.AddSeconds(seconds), UpTime = upTime, HighCapacity = hc, InOctets = inOctets, OutOctets = outOctets, SpeedBitsPerSecond = speed,
            InErrors = inErrors, OutErrors = 0, InDiscards = 0, OutDiscards = 0,
        };

    [Fact]
    public void First_reading_has_no_rate()
    {
        var r = InterfaceRates.Compute(null, C(0, 100, 100));
        Assert.Equal(RateStatus.First, r.Status);
        Assert.Null(r.InBitsPerSecond);
    }

    [Fact]
    public void Rate_uses_the_agent_uptime_not_the_polling_time()
    {
        // replies 12 s apart locally (slow network), but the agent's clock says 10 s passed
        var r = InterfaceRates.Compute(C(0, 0, 0, upTime: 100_000), C(12, 125_000_000, 12_500_000, upTime: 101_000));
        Assert.Equal(RateStatus.Ok, r.Status);
        Assert.Equal(TimeSpan.FromSeconds(10), r.Elapsed);
        Assert.Equal(100e6, r.InBitsPerSecond!.Value, 3);   // 125 MB in 10 s
        Assert.Equal(10e6, r.OutBitsPerSecond!.Value, 3);
        Assert.Equal(10, r.InUtilisation!.Value, 3);         // of 1 Gbit/s
    }

    [Fact]
    public void Local_time_is_used_without_uptime()
    {
        var r = InterfaceRates.Compute(C(0, 0, 0), C(4, 1_000_000, 0));
        Assert.Equal(2e6, r.InBitsPerSecond!.Value, 3);
    }

    [Fact]
    public void Plausible_32_bit_wrap_is_accounted_for()
    {
        var before = uint.MaxValue - 1_000_000UL;
        var r = InterfaceRates.Compute(C(0, before, 0, upTime: 0, hc: false), C(10, 4_000_000, 0, upTime: 1000, hc: false));
        Assert.Equal(RateStatus.Wrapped, r.Status);
        Assert.Equal((1_000_000 + 1 + 4_000_000) * 8 / 10.0, r.InBitsPerSecond!.Value, 3);
    }

    [Fact]
    public void Implausible_wrap_and_64_bit_counters_going_backwards_are_discontinuities()
    {
        // a "wrap" on a 10 Mbit/s link that would mean > 3 Gbit/s: a reset, not a wrap
        var reset32 = InterfaceRates.Compute(C(0, 4_000_000_000, 0, upTime: 0, hc: false, speed: 10_000_000), C(10, 5, 0, upTime: 1000, hc: false, speed: 10_000_000));
        Assert.Equal(RateStatus.Discontinuity, reset32.Status);
        Assert.Null(reset32.InBitsPerSecond);
        var reset64 = InterfaceRates.Compute(C(0, 9_000_000, 0, upTime: 0), C(10, 10, 0, upTime: 1000)); // e.g. "clear counters"
        Assert.Equal(RateStatus.Discontinuity, reset64.Status);
        var errors = InterfaceRates.Compute(C(0, 0, 0, upTime: 0, inErrors: 50), C(10, 0, 0, upTime: 1000, inErrors: 2));
        Assert.Equal(RateStatus.Discontinuity, errors.Status);
    }

    [Fact]
    public void Uptime_going_backwards_is_a_restart_but_its_own_wrap_is_not()
    {
        var restart = InterfaceRates.Compute(C(0, 1000, 0, upTime: 5_000_000), C(10, 10, 0, upTime: 500));
        Assert.Equal(RateStatus.Restarted, restart.Status);
        Assert.Contains("restarted", restart.Note, StringComparison.Ordinal);

        var wrap = InterfaceRates.Compute(C(0, 0, 0, upTime: uint.MaxValue - 499), C(10, 1_250_000, 0, upTime: 500)); // 497-day wrap, 10 s
        Assert.Equal(RateStatus.Ok, wrap.Status);
        Assert.Equal(TimeSpan.FromSeconds(10), wrap.Elapsed);
        Assert.Equal(1e6, wrap.InBitsPerSecond!.Value, 3);
    }

    [Fact]
    public void Missing_counters_give_no_rate_and_unknown_speed_no_utilisation()
    {
        var a = C(0, 0, 0, upTime: 0, speed: 0) with { OutOctets = null };
        var b = C(10, 1000, 0, upTime: 1000, speed: 0) with { OutOctets = null };
        var r = InterfaceRates.Compute(a, b);
        Assert.Null(r.OutBitsPerSecond);
        Assert.Null(r.InUtilisation);
        Assert.Equal(800, r.InBitsPerSecond!.Value, 3);
    }

    [Fact]
    public void Counter_width_change_is_a_discontinuity()
    {
        var r = InterfaceRates.Compute(C(0, 10, 0, upTime: 0, hc: true), C(10, 20, 0, upTime: 1000, hc: false));
        Assert.Equal(RateStatus.Discontinuity, r.Status);
    }

    [Theory]
    [InlineData(null, "—")]
    [InlineData(999d, "999 bit/s")]
    [InlineData(12_345_678d, "12.35 Mbit/s")]
    [InlineData(2.5e9, "2.50 Gbit/s")]
    public void Bits_are_formatted(double? bits, string text) =>
        Assert.Equal(text, InterfaceRates.FormatBits(bits).Replace(',', '.'));
}
