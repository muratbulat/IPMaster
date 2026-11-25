using System.Globalization;
using System.Numerics;
using System.Text;

namespace IPMaster.Core.Tools;

/// <summary>
/// Exact non-negative-or-negative rational (BigInteger numerator / positive denominator), always reduced. The transfer
/// calculator's source of truth (D-102): unit factors up to 2^100 bytes and quettabytes do not fit 64-bit integers, and
/// double cannot represent the factors exactly.
/// </summary>
public readonly struct Rational : IEquatable<Rational>, IComparable<Rational>
{
    public Rational(BigInteger numerator, BigInteger denominator)
    {
        if (denominator.IsZero) throw new DivideByZeroException();
        if (denominator.Sign < 0) (numerator, denominator) = (-numerator, -denominator);
        var g = BigInteger.GreatestCommonDivisor(numerator, denominator);
        if (!g.IsOne && !g.IsZero) (numerator, denominator) = (numerator / g, denominator / g);
        Numerator = numerator;
        _denominator = numerator.IsZero ? BigInteger.One : denominator;
    }

    public BigInteger Numerator { get; }

    public BigInteger Denominator => _denominator.IsZero ? BigInteger.One : _denominator;

    private readonly BigInteger _denominator;

    public static Rational Zero => new(0, 1);

    public static Rational One => new(1, 1);

    public int Sign => Numerator.Sign;

    public bool IsZero => Numerator.IsZero;

    public static Rational FromInteger(BigInteger value) => new(value, 1);

    /// <summary>Exact: a decimal is an integer mantissa over a power of ten.</summary>
    public static Rational FromDecimal(decimal value)
    {
        var bits = decimal.GetBits(value);
        var mantissa = new BigInteger((uint)bits[0]) | (new BigInteger((uint)bits[1]) << 32) | (new BigInteger((uint)bits[2]) << 64);
        if (bits[3] < 0) mantissa = -mantissa;
        var scale = (bits[3] >> 16) & 0xFF;
        return new Rational(mantissa, BigInteger.Pow(10, scale));
    }

    public static Rational operator +(Rational a, Rational b) => new((a.Numerator * b.Denominator) + (b.Numerator * a.Denominator), a.Denominator * b.Denominator);

    public static Rational operator -(Rational a, Rational b) => new((a.Numerator * b.Denominator) - (b.Numerator * a.Denominator), a.Denominator * b.Denominator);

    public static Rational operator *(Rational a, Rational b) => new(a.Numerator * b.Numerator, a.Denominator * b.Denominator);

    public static Rational operator /(Rational a, Rational b) => b.IsZero ? throw new DivideByZeroException() : new(a.Numerator * b.Denominator, a.Denominator * b.Numerator);

    public static bool operator <(Rational a, Rational b) => a.CompareTo(b) < 0;

    public static bool operator >(Rational a, Rational b) => a.CompareTo(b) > 0;

    public static bool operator <=(Rational a, Rational b) => a.CompareTo(b) <= 0;

    public static bool operator >=(Rational a, Rational b) => a.CompareTo(b) >= 0;

    public static bool operator ==(Rational a, Rational b) => a.Equals(b);

    public static bool operator !=(Rational a, Rational b) => !a.Equals(b);

    public int CompareTo(Rational other) => (Numerator * other.Denominator).CompareTo(other.Numerator * Denominator);

    public bool Equals(Rational other) => Numerator == other.Numerator && Denominator == other.Denominator;

    public override bool Equals(object? obj) => obj is Rational r && Equals(r);

    public override int GetHashCode() => HashCode.Combine(Numerator, Denominator);

    /// <summary>Nearest integer, halves away from zero (deterministic rounding policy).</summary>
    public BigInteger Round()
    {
        var q = BigInteger.DivRem(BigInteger.Abs(Numerator) * 2 + Denominator, Denominator * 2, out _);
        return Numerator.Sign < 0 ? -q : q;
    }

    /// <summary>Approximation for display and slider positions only (never for exact results).</summary>
    public double ToDouble() => IsZero ? 0 : Sign * Math.Exp(BigInteger.Log(BigInteger.Abs(Numerator)) - BigInteger.Log(Denominator));

    /// <summary>Decimal digits, rounded half away from zero to at most <paramref name="decimals"/> places, zeros trimmed.</summary>
    public string ToFixed(int decimals, CultureInfo culture, bool group = false)
    {
        ArgumentNullException.ThrowIfNull(culture);
        var scaled = (this * FromInteger(BigInteger.Pow(10, decimals))).Round();
        var negative = scaled.Sign < 0;
        var digits = BigInteger.Abs(scaled).ToString(CultureInfo.InvariantCulture).PadLeft(decimals + 1, '0');
        var whole = digits[..^decimals];
        var frac = decimals == 0 ? "" : digits[^decimals..].TrimEnd('0');
        if (group) whole = Group(whole, culture.NumberFormat.NumberGroupSeparator);
        return (negative ? "-" : "") + whole + (frac.Length > 0 ? culture.NumberFormat.NumberDecimalSeparator + frac : "");
    }

    /// <summary>Scientific notation with <paramref name="significant"/> digits: "1.23 × 10^30".</summary>
    public string ToScientific(int significant, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        if (IsZero) return "0";
        var abs = new Rational(BigInteger.Abs(Numerator), Denominator);
        var exp = (int)Math.Floor(BigInteger.Log10(abs.Numerator) - BigInteger.Log10(abs.Denominator));
        var mant = abs / Pow10(exp);
        if (mant >= FromInteger(10)) (mant, exp) = (mant / FromInteger(10), exp + 1);
        if (mant < One) (mant, exp) = (mant * FromInteger(10), exp - 1);
        var digits = (mant * Pow10(significant - 1)).Round(); // an integer with `significant` digits
        if (digits >= BigInteger.Pow(10, significant)) (digits, exp) = (digits / 10, exp + 1); // 9.995 → 10.00: carry
        var text = digits.ToString(CultureInfo.InvariantCulture);
        var frac = text[1..].TrimEnd('0');
        return (Sign < 0 ? "-" : "") + text[0] + (frac.Length > 0 ? culture.NumberFormat.NumberDecimalSeparator + frac : "") + " × 10^" + exp.ToString(CultureInfo.InvariantCulture);
    }

    public static Rational Pow10(int exponent) => exponent >= 0 ? FromInteger(BigInteger.Pow(10, exponent)) : new Rational(1, BigInteger.Pow(10, -exponent));

    private static string Group(string digits, string separator)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < digits.Length; i++)
        {
            if (i > 0 && (digits.Length - i) % 3 == 0) sb.Append(separator);
            sb.Append(digits[i]);
        }

        return sb.ToString();
    }

    public override string ToString() => ToFixed(12, CultureInfo.InvariantCulture);
}

public enum UnitGroup
{
    DecimalBytes,
    BinaryBytes,
    DecimalBits,
    BinaryBits,
}

/// <summary>A data unit: <see cref="Bits"/> is its exact size in bits (1 B = 8 b; SI prefixes 10^3n, IEC 2^10n).</summary>
public sealed record DataUnit(string Symbol, string Name, UnitGroup Group, BigInteger Bits)
{
    public Rational Factor => Rational.FromInteger(Bits);

    /// <summary>The rate unit's symbol ("MB/s", "Mbps", "MiB/s", "Mib/s").</summary>
    public string RateSymbol => Group switch
    {
        UnitGroup.DecimalBits => Symbol == "b" ? "bps" : Symbol[..^1] + "bps",
        UnitGroup.BinaryBits => Symbol + "/s",
        _ => Symbol + "/s",
    };

    public override string ToString() => Symbol;
}

/// <summary>
/// The SI (BIPM) and IEC 80000-13 unit catalogue (D-102): bytes and bits, decimal prefixes k…Q (10^3…10^30) and binary
/// prefixes Ki…Qi (2^10…2^100). MB and MiB, GB and GiB, b and B are distinct units.
/// </summary>
public static class DataUnits
{
    private static readonly (string Prefix, string Name)[] Si =
        [("k", "kilo"), ("M", "mega"), ("G", "giga"), ("T", "tera"), ("P", "peta"), ("E", "exa"), ("Z", "zetta"), ("Y", "yotta"), ("R", "ronna"), ("Q", "quetta")];

    private static readonly (string Prefix, string Name)[] Iec =
        [("Ki", "kibi"), ("Mi", "mebi"), ("Gi", "gibi"), ("Ti", "tebi"), ("Pi", "pebi"), ("Ei", "exbi"), ("Zi", "zebi"), ("Yi", "yobi"), ("Ri", "robi"), ("Qi", "quebi")];

    public static readonly IReadOnlyList<DataUnit> All = Build();

    private static List<DataUnit> Build()
    {
        var list = new List<DataUnit> { new("B", "byte", UnitGroup.DecimalBytes, 8) };
        for (var i = 0; i < Si.Length; i++) list.Add(new(Si[i].Prefix + "B", Si[i].Name + "byte", UnitGroup.DecimalBytes, 8 * BigInteger.Pow(1000, i + 1)));
        for (var i = 0; i < Iec.Length; i++) list.Add(new(Iec[i].Prefix + "B", Iec[i].Name + "byte", UnitGroup.BinaryBytes, 8 * BigInteger.Pow(1024, i + 1)));
        list.Add(new("b", "bit", UnitGroup.DecimalBits, 1));
        for (var i = 0; i < Si.Length; i++) list.Add(new(Si[i].Prefix + "b", Si[i].Name + "bit", UnitGroup.DecimalBits, BigInteger.Pow(1000, i + 1)));
        for (var i = 0; i < Iec.Length; i++) list.Add(new(Iec[i].Prefix + "b", Iec[i].Name + "bit", UnitGroup.BinaryBits, BigInteger.Pow(1024, i + 1)));
        return list;
    }

    public static DataUnit Get(string symbol) => TryGet(symbol) ?? throw new ArgumentException($"Unknown unit '{symbol}'.", nameof(symbol));

    /// <summary>By size symbol ("GiB") or rate symbol ("Mbps", "MB/s", "Kib/s"); case-sensitive (b ≠ B).</summary>
    public static DataUnit? TryGet(string symbol) =>
        All.FirstOrDefault(u => u.Symbol == symbol) ?? All.FirstOrDefault(u => u.RateSymbol == symbol);

    /// <summary>Most used first: offered above the full catalogue.</summary>
    public static readonly string[] CommonSizes = ["MB", "GB", "TB", "MiB", "GiB", "TiB"];

    public static readonly string[] CommonRates = ["Mbps", "Gbps", "MB/s", "GB/s", "MiB/s"];
}

public enum TransferMode
{
    /// <summary>Size and speed → duration.</summary>
    TransferTime,

    /// <summary>Size and duration → required speed.</summary>
    RequiredSpeed,
}

public sealed record TransferResult(
    Rational SizeBits,
    Rational RateBitsPerSecond,
    Rational Efficiency,
    Rational EffectiveBitsPerSecond,
    Rational Seconds,
    Rational TheoreticalSeconds);

/// <summary>
/// Download / transfer arithmetic (D-102), exact: seconds = size in bits ÷ (link bits/s × efficiency). Efficiency is the
/// share of the link the transfer achieves (an assumption, 0 &lt; e ≤ 100 %), not an overhead percentage. No division
/// by zero, NaN or overflow: every value is a reduced BigInteger fraction.
/// </summary>
public static class TransferCalculator
{
    /// <summary>Parses a non-negative number in the given culture (invariant "." also accepted); exact.</summary>
    public static bool TryParse(string? text, CultureInfo culture, out Rational value, out string error)
    {
        ArgumentNullException.ThrowIfNull(culture);
        value = Rational.Zero;
        var t = (text ?? "").Trim().Replace(" ", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal);
        if (t.Length == 0)
        {
            error = "Enter a number.";
            return false;
        }

        const NumberStyles styles = NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint | NumberStyles.AllowThousands | NumberStyles.AllowExponent;
        if (!decimal.TryParse(t, styles, culture, out var d) && !decimal.TryParse(t, styles, CultureInfo.InvariantCulture, out d))
        {
            error = $"'{text}' is not a number.";
            return false;
        }

        if (d < 0)
        {
            error = "The value cannot be negative.";
            return false;
        }

        value = Rational.FromDecimal(d);
        error = "";
        return true;
    }

    /// <summary>Efficiency percentage → fraction; 0 &lt; percent ≤ 100.</summary>
    public static bool TryEfficiency(Rational percent, out Rational fraction, out string error)
    {
        fraction = Rational.Zero;
        if (percent.IsZero || percent.Sign < 0)
        {
            error = "Effective throughput must be more than 0 %.";
            return false;
        }

        if (percent > Rational.FromInteger(100))
        {
            error = "Effective throughput cannot exceed 100 %.";
            return false;
        }

        fraction = percent / Rational.FromInteger(100);
        error = "";
        return true;
    }

    public static TransferResult Time(Rational sizeBits, Rational rateBitsPerSecond, Rational efficiency)
    {
        if (rateBitsPerSecond.Sign <= 0) throw new ArgumentOutOfRangeException(nameof(rateBitsPerSecond), "The speed must be more than zero.");
        if (efficiency.Sign <= 0 || efficiency > Rational.One) throw new ArgumentOutOfRangeException(nameof(efficiency));
        if (sizeBits.Sign < 0) throw new ArgumentOutOfRangeException(nameof(sizeBits));
        var effective = rateBitsPerSecond * efficiency;
        return new TransferResult(sizeBits, rateBitsPerSecond, efficiency, effective, sizeBits / effective, sizeBits / rateBitsPerSecond);
    }

    /// <summary>Link speed needed to move <paramref name="sizeBits"/> in <paramref name="seconds"/> at the given efficiency.</summary>
    public static TransferResult Speed(Rational sizeBits, Rational seconds, Rational efficiency)
    {
        if (seconds.Sign <= 0) throw new ArgumentOutOfRangeException(nameof(seconds), "The duration must be more than zero.");
        if (efficiency.Sign <= 0 || efficiency > Rational.One) throw new ArgumentOutOfRangeException(nameof(efficiency));
        if (sizeBits.Sign < 0) throw new ArgumentOutOfRangeException(nameof(sizeBits));
        var effective = sizeBits / seconds;
        return new TransferResult(sizeBits, effective / efficiency, efficiency, effective, seconds, seconds * efficiency);
    }

    /// <summary>The amount in a unit, e.g. 12.5 for 100 Mbps in MB/s.</summary>
    public static Rational In(Rational bits, DataUnit unit)
    {
        ArgumentNullException.ThrowIfNull(unit);
        return bits / unit.Factor;
    }

    /// <summary>"12.5 MB/s"-style text with up to <paramref name="decimals"/> places.</summary>
    public static string Format(Rational bits, DataUnit unit, CultureInfo culture, bool rate = false, int decimals = 3) =>
        FormatNumber(In(bits, unit), culture, decimals) + " " + (rate ? unit!.RateSymbol : unit!.Symbol);

    /// <summary>A number for display: fixed with grouping below 10^15, scientific above (so the text stays readable).</summary>
    public static string FormatNumber(Rational value, CultureInfo culture, int decimals = 3) =>
        value >= Rational.Pow10(15) ? value.ToScientific(6, culture)
        : !value.IsZero && value < Rational.Pow10(-decimals) ? value.ToScientific(4, culture)
        : value.ToFixed(decimals, culture, group: true);

    /// <summary>The unit that shows a bit amount as 1 ≤ value &lt; 1000 within the given group.</summary>
    public static DataUnit Best(Rational bits, UnitGroup group)
    {
        var units = DataUnits.All.Where(u => u.Group == group || (group == UnitGroup.BinaryBytes && u.Symbol == "B") || (group == UnitGroup.BinaryBits && u.Symbol == "b")).OrderBy(u => u.Bits).ToList();
        var best = units[0];
        foreach (var u in units)
        {
            if (bits >= u.Factor) best = u;
        }

        return best;
    }

    private static readonly Rational Minute = Rational.FromInteger(60);
    private static readonly Rational Hour = Rational.FromInteger(3600);
    private static readonly Rational Day = Rational.FromInteger(86_400);
    private static readonly Rational Year = Rational.FromInteger(31_557_600); // Julian year, 365.25 days

    /// <summary>
    /// Readable duration (precision policy, D-102): under 1 ms in µs, under 10 ms in ms, under 1 s as "0.85 sec"; under a minute in
    /// seconds with one decimal below 10 s; then whole seconds rounded half away from zero as "M min S sec", "H h M min",
    /// "D days H h M min"; from a year on "≈ N years" (Julian year), and scientific above a million years. No calendar
    /// date is ever derived.
    /// </summary>
    public static string Duration(Rational seconds, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        if (seconds.IsZero) return "0 sec";
        if (seconds < Rational.Pow10(-3)) return (seconds * Rational.Pow10(6)).ToFixed(seconds * Rational.Pow10(6) < Rational.FromInteger(10) ? 2 : 1, culture) + " µs";
        if (seconds < Rational.Pow10(-2)) return (seconds * Rational.Pow10(3)).ToFixed(2, culture) + " ms";
        if (seconds < Rational.One) return seconds.ToFixed(2, culture) + " sec";
        if (seconds < Rational.FromInteger(10)) return seconds.ToFixed(1, culture) + " sec";
        if (seconds < Minute) return seconds.ToFixed(0, culture) + " sec";
        if (seconds >= Year)
        {
            var years = seconds / Year;
            return years >= Rational.Pow10(6) ? "≈ " + years.ToScientific(3, culture) + " years" : "≈ " + years.ToFixed(years < Rational.FromInteger(10) ? 2 : 1, culture, group: true) + " years";
        }

        var total = seconds.Round();
        var d = total / 86_400;
        var h = total % 86_400 / 3600;
        var m = total % 3600 / 60;
        var s = total % 60;
        string I(BigInteger v) => v.ToString(culture);
        if (d > 0) return $"{I(d)} day{(d == 1 ? "" : "s")} {I(h)} h {I(m)} min";
        if (h > 0) return $"{I(h)} h {I(m)} min" + (s > 0 && h < 10 ? $" {I(s)} sec" : "");
        return $"{I(m)} min {I(s)} sec";
    }
}
