using System.Globalization;
using System.Numerics;
using IPMaster.Core.Tools;

namespace IPMaster.Tests;

/// <summary>Exact transfer arithmetic (D-102). Results are compared exactly (rationals), not with tolerances, unless stated.</summary>
public class TransferCalculatorTests
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    private static Rational Q(decimal v) => Rational.FromDecimal(v);

    private static Rational Bits(decimal value, string unit) => Q(value) * DataUnits.Get(unit).Factor;

    private static Rational Seconds(decimal size, string sizeUnit, decimal speed, string speedUnit, decimal percent = 100)
    {
        Assert.True(TransferCalculator.TryEfficiency(Q(percent), out var e, out _));
        return TransferCalculator.Time(Bits(size, sizeUnit), Bits(speed, speedUnit), e).Seconds;
    }

    [Theory]
    [InlineData("kB", "8000")]
    [InlineData("KiB", "8192")]
    [InlineData("MB", "8000000")]
    [InlineData("MiB", "8388608")]
    [InlineData("GiB", "8589934592")]
    [InlineData("TiB", "8796093022208")]
    [InlineData("QB", "8000000000000000000000000000000")]
    [InlineData("QiB", "10141204801825835211973625643008")]
    [InlineData("Mbps", "1000000")]
    [InlineData("Mib/s", "1048576")]
    [InlineData("b", "1")]
    [InlineData("B", "8")]
    public void Units_have_their_exact_si_and_iec_sizes_in_bits(string symbol, string bits) =>
        Assert.Equal(BigInteger.Parse(bits, Inv), DataUnits.Get(symbol).Bits);

    [Fact]
    public void Catalogue_covers_every_prefix_and_keeps_bits_and_bytes_apart()
    {
        foreach (var s in new[] { "B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB", "RB", "QB", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB", "RiB", "QiB" })
            Assert.NotNull(DataUnits.TryGet(s));
        foreach (var s in new[] { "bps", "kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps", "Zbps", "Ybps", "Rbps", "Qbps", "B/s", "kB/s", "MB/s", "QB/s", "KiB/s", "QiB/s", "Kib/s", "Qib/s" })
            Assert.NotNull(DataUnits.TryGet(s));
        Assert.NotEqual(DataUnits.Get("MB").Bits, DataUnits.Get("MiB").Bits);
        Assert.Equal(8 * DataUnits.Get("Mb").Bits, DataUnits.Get("MB").Bits);
        Assert.Null(DataUnits.TryGet("mb")); // case matters: no guessing between b and B
        Assert.Equal(DataUnits.Get("GB"), DataUnits.TryGet("GB/s"));
    }

    [Fact]
    public void Rate_conversions()
    {
        Assert.Equal(Q(12.5m), TransferCalculator.In(Bits(100, "Mbps"), DataUnits.Get("MB")));
        Assert.Equal(Q(0.125m), TransferCalculator.In(Bits(1, "Gbps"), DataUnits.Get("GB")));
        Assert.Equal("12.5 MB/s", TransferCalculator.Format(Bits(100, "Mbps"), DataUnits.Get("MB"), Inv, rate: true));
        Assert.Equal(Q(1.5m) * Rational.FromInteger(1024), TransferCalculator.In(Bits(1.5m, "MiB"), DataUnits.Get("KiB")));
    }

    [Fact]
    public void Transfer_times_from_the_brief()
    {
        Assert.Equal(Rational.FromInteger(80), Seconds(1, "GB", 100, "Mbps"));
        Assert.Equal(Q(85.89934592m), Seconds(1, "GiB", 100, "Mbps")); // exact: 2^33 / 10^8
        Assert.Equal(Rational.FromInteger(10), Seconds(1, "GB", 100, "MB/s"));
        Assert.Equal(Rational.FromInteger(800), Seconds(10, "GB", 100, "Mbps"));
        var ninety = Seconds(10, "GB", 100, "Mbps", 90);
        Assert.Equal(new Rational(8000, 9), ninety); // 888.888… exactly
        Assert.Equal("888.888889", ninety.ToFixed(6, Inv));
        Assert.Equal(Rational.FromInteger(100), Seconds(1, "GB", 100, "Mbps", 80));
        Assert.Equal(Rational.Zero, Seconds(0, "GB", 100, "Mbps")); // a zero-sized file takes no time
    }

    [Fact]
    public void Required_speed_is_the_inverse()
    {
        Assert.True(TransferCalculator.TryEfficiency(Q(90), out var e, out _));
        var r = TransferCalculator.Speed(Bits(10, "GB"), Rational.FromInteger(800), e);
        Assert.Equal(Bits(100, "Mbps"), r.EffectiveBitsPerSecond);
        Assert.Equal(Bits(100, "Mbps") / Q(0.9m), r.RateBitsPerSecond); // the link must be faster than the payload rate
    }

    [Fact]
    public void Largest_units_stay_exact_and_overflow_free()
    {
        var s = Seconds(1, "QiB", 1, "bps");
        Assert.Equal(Rational.FromInteger(BigInteger.Pow(2, 103)), s);
        Assert.StartsWith("≈ 3.21 × 10^23 years", TransferCalculator.Duration(s, Inv), StringComparison.Ordinal);
        var tiny = Seconds(1, "B", 1, "Qbps");
        Assert.Equal(new Rational(8, BigInteger.Pow(10, 30)), tiny);
        Assert.Equal("0 sec", TransferCalculator.Duration(Rational.Zero, Inv));
        Assert.EndsWith("µs", TransferCalculator.Duration(tiny, Inv), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(80, "1 min 20 sec")]
    [InlineData(800, "13 min 20 sec")]
    [InlineData(8, "8.0 sec")]
    [InlineData(3.2, "3.2 sec")]
    [InlineData(0.8, "0.8 sec")]
    [InlineData(45, "45 sec")]
    [InlineData(7322, "2 h 2 min 2 sec")]
    [InlineData(40_000, "11 h 6 min")]
    [InlineData(200_000, "2 days 7 h 33 min")]
    public void Durations_read_naturally(double seconds, string expected)
    {
        var text = TransferCalculator.Duration(Rational.FromDecimal((decimal)seconds), Inv);
        Assert.Equal(expected.Replace("8.0 sec", "8 sec", StringComparison.Ordinal), text);
    }

    [Fact]
    public void Rounding_of_the_seconds_is_half_away_from_zero()
    {
        Assert.Equal("14 min 49 sec", TransferCalculator.Duration(new Rational(8000, 9), Inv)); // 888.89 s
        Assert.Equal("1 min 1 sec", TransferCalculator.Duration(Q(60.5m), Inv));
        Assert.Equal(new BigInteger(-3), Q(-2.5m).Round());
    }

    [Theory]
    [InlineData("", "Enter a number.")]
    [InlineData("abc", "is not a number")]
    [InlineData("-5", "cannot be negative")]
    public void Invalid_numbers_are_explained(string text, string message)
    {
        Assert.False(TransferCalculator.TryParse(text, Inv, out _, out var error));
        Assert.Contains(message, error, StringComparison.Ordinal);
    }

    [Fact]
    public void Numbers_follow_the_culture_and_also_accept_a_dot()
    {
        var tr = CultureInfo.GetCultureInfo("tr-TR");
        Assert.True(TransferCalculator.TryParse("10,5", tr, out var v, out _));
        Assert.Equal(Q(10.5m), v);
        Assert.True(TransferCalculator.TryParse("1.000,25", tr, out v, out _));
        Assert.Equal(Q(1000.25m), v);
        Assert.True(TransferCalculator.TryParse("0.000001", Inv, out v, out _));
        Assert.Equal(Q(0.000001m), v);
        Assert.Equal("10,5", Q(10.5m).ToFixed(3, tr));
    }

    [Fact]
    public void Efficiency_must_be_above_zero_and_at_most_100_percent_and_speed_above_zero()
    {
        Assert.False(TransferCalculator.TryEfficiency(Rational.Zero, out _, out var e0));
        Assert.Contains("more than 0", e0, StringComparison.Ordinal);
        Assert.False(TransferCalculator.TryEfficiency(Q(100.5m), out _, out var e1));
        Assert.Contains("cannot exceed 100", e1, StringComparison.Ordinal);
        Assert.True(TransferCalculator.TryEfficiency(Q(100), out var full, out _));
        Assert.Equal(Rational.One, full);
        Assert.Throws<ArgumentOutOfRangeException>(() => TransferCalculator.Time(Rational.One, Rational.Zero, full));
        Assert.Throws<ArgumentOutOfRangeException>(() => TransferCalculator.Speed(Rational.One, Rational.Zero, full));
    }

    [Fact]
    public void Large_numbers_switch_to_scientific_notation()
    {
        Assert.Equal("1.23457 × 10^20", TransferCalculator.FormatNumber(Q(123456789012345678901m), Inv));
        Assert.Equal("1 × 10^3", Q(999.9999m).ToScientific(3, Inv)); // rounding carries into the next power
        Assert.Equal("1,234,567.5", TransferCalculator.FormatNumber(Q(1234567.5m), Inv));
        Assert.Equal("GiB", TransferCalculator.Best(Bits(3, "GiB"), UnitGroup.BinaryBytes).Symbol);
        Assert.Equal("B", TransferCalculator.Best(Bits(10, "B"), UnitGroup.BinaryBytes).Symbol);
    }
}
