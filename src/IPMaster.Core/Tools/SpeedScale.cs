using System.Globalization;
using System.Numerics;

namespace IPMaster.Core.Tools;

/// <summary>
/// The Download Calculator's speed slider (D-112): stops 1 Mbps … 200 Gbps at evenly spaced positions 0 … 9, logarithmic
/// between two stops. A position is only an approximation for the slider; the speed itself stays exact (<see cref="Rational"/>),
/// and a typed value is never rounded to fit the slider.
/// </summary>
public static class SpeedScale
{
    /// <summary>Stops in bits per second.</summary>
    public static readonly IReadOnlyList<Rational> Stops =
    [
        Gbps(0.001m), Gbps(0.01m), Gbps(0.1m), Gbps(1m), Gbps(2.5m), Gbps(10m), Gbps(25m), Gbps(40m), Gbps(100m), Gbps(200m),
    ];

    /// <summary>Tick labels, one per stop.</summary>
    public static readonly IReadOnlyList<string> Labels = ["1M", "10M", "100M", "1G", "2.5G", "10G", "25G", "40G", "100G", "200G"];

    public static double Maximum => Stops.Count - 1;

    private static Rational Gbps(decimal value) => Rational.FromDecimal(value) * Rational.FromInteger(1_000_000_000);

    /// <summary>Slider position of a speed; speeds outside the scale sit at its ends.</summary>
    public static double ToPosition(Rational bitsPerSecond)
    {
        if (bitsPerSecond <= Stops[0]) return 0;
        if (bitsPerSecond >= Stops[^1]) return Maximum;
        var i = 0;
        while (bitsPerSecond >= Stops[i + 1]) i++;
        if (bitsPerSecond == Stops[i]) return i;
        var f = Math.Log((bitsPerSecond / Stops[i]).ToDouble()) / Math.Log((Stops[i + 1] / Stops[i]).ToDouble());
        return i + f;
    }

    /// <summary>
    /// Speed at a slider position, rounded to three significant digits (a dragged value reads "316 Mbps", not "316.2278 Mbps");
    /// within 0.02 of a stop it is the stop exactly.
    /// </summary>
    public static Rational FromPosition(double position)
    {
        if (double.IsNaN(position)) return Stops[0];
        var p = Math.Clamp(position, 0, Maximum);
        var nearest = (int)Math.Round(p);
        if (Math.Abs(p - nearest) < 0.02) return Stops[nearest];
        var i = Math.Min((int)Math.Floor(p), Stops.Count - 2);
        var value = Stops[i].ToDouble() * Math.Pow((Stops[i + 1] / Stops[i]).ToDouble(), p - i);
        return ThreeDigits(value);
    }

    private static Rational ThreeDigits(double value)
    {
        var exp = (int)Math.Floor(Math.Log10(value)) - 2;
        var mantissa = (long)Math.Round(value / Math.Pow(10, exp), MidpointRounding.AwayFromZero);
        return Rational.FromInteger(mantissa) * Rational.Pow10(exp);
    }

    /// <summary>
    /// The duration as the main result (D-112): "0.25 seconds", "25 seconds", "4m 32s", then "1h 15m" (nearest minute) and
    /// "2d 6h" (nearest hour); from a year on, the long form of <see cref="TransferCalculator.Duration"/>. Rounding is half
    /// away from zero. The exact seconds are in the technical details.
    /// </summary>
    public static string CompactDuration(Rational seconds, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        if (seconds < Rational.Pow10(-2) || seconds >= Rational.FromInteger(31_557_600)) return TransferCalculator.Duration(seconds, culture);
        if (seconds < Rational.One) return seconds.ToFixed(2, culture) + " seconds";
        if (seconds < Rational.FromInteger(10)) return seconds.ToFixed(1, culture) + (seconds == Rational.One ? " second" : " seconds");
        string I(BigInteger v) => v.ToString(culture);
        var total = seconds.Round();
        if (total < 60) return I(total) + " seconds";
        if (total < 3600) return $"{I(total / 60)}m {I(total % 60)}s";
        var minutes = (seconds / Rational.FromInteger(60)).Round(); // shown to the nearest minute from an hour on
        if (minutes < 1440) return $"{I(minutes / 60)}h {I(minutes % 60)}m";
        var hours = (seconds / Rational.FromInteger(3600)).Round(); // to the nearest hour from a day on
        return $"{I(hours / 24)}d {I(hours % 24)}h";
    }
}
