using System.Collections.ObjectModel;
using System.Globalization;
using System.Numerics;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using IPMaster.Core.Tools;

namespace IPMaster.Desktop.ViewModels;

public sealed record ComparisonRow(string Speed, string Time);

public sealed record DetailRow(string Label, string Value);

/// <summary>
/// Download / Transfer Calculator state (D-102). The exact quantities (bits, bits/s, seconds) are the source of truth;
/// text boxes show them in the chosen unit. Switching a unit converts the shown number (the quantity stays); typing sets
/// the quantity; sliders move on a logarithmic scale and never limit what can be typed. One guard flag stops text,
/// unit and slider updates from feeding back into each other. Offline: nothing is downloaded or measured.
/// </summary>
public sealed partial class TransferCalculatorViewModel : ObservableObject
{
    public const double SizeSliderMin = 6;   // 10^6 bytes = 1 MB
    public const double SizeSliderMax = 15;  // 10^15 bytes = 1 PB
    public const double SpeedSliderMin = 6;  // 10^6 bit/s = 1 Mbps
    public const double SpeedSliderMax = 11.6020599913; // log10(400 Gbps)

    public static readonly string[] QuickSpeeds = ["100 Mbps", "1 Gbps", "2.5 Gbps", "10 Gbps", "25 Gbps", "40 Gbps", "100 Gbps"];

    public static readonly string[] DurationUnits = ["sec", "min", "h", "days"];

    private readonly CultureInfo _culture;
    private bool _syncing;
    private Rational? _sizeBits;
    private Rational? _speedBits;

    public TransferCalculatorViewModel(CultureInfo? culture = null)
    {
        _culture = culture ?? CultureInfo.CurrentCulture;
        Reset();
    }

    [ObservableProperty] public partial TransferMode Mode { get; set; }

    [ObservableProperty] public partial string SizeText { get; set; } = "";

    [ObservableProperty] public partial DataUnit SizeUnit { get; set; } = DataUnits.Get("GB");

    [ObservableProperty] public partial string SpeedText { get; set; } = "";

    [ObservableProperty] public partial DataUnit SpeedUnit { get; set; } = DataUnits.Get("Mb");

    [ObservableProperty] public partial string EfficiencyText { get; set; } = "";

    [ObservableProperty] public partial string DurationText { get; set; } = "";

    [ObservableProperty] public partial string DurationUnit { get; set; } = "min";

    [ObservableProperty] public partial double SizeSlider { get; set; }

    [ObservableProperty] public partial double SpeedSlider { get; set; }

    [ObservableProperty] public partial string ComparisonSpeedsText { get; set; } = "";

    [ObservableProperty] public partial bool ComparisonUsesEfficiency { get; set; } = true;

    // ---- results
    [ObservableProperty] public partial string ResultLabel { get; set; } = "";

    [ObservableProperty] public partial string ResultMain { get; set; } = "";

    [ObservableProperty] public partial string ResultSub { get; set; } = "";

    [ObservableProperty] public partial string Error { get; set; } = "";

    [ObservableProperty] public partial string SpeedConversion { get; set; } = "";

    [ObservableProperty] public partial string Breakdown { get; set; } = "";

    [ObservableProperty] public partial string ComparisonNote { get; set; } = "";

    public ObservableCollection<DetailRow> Details { get; } = [];

    public ObservableCollection<ComparisonRow> Comparison { get; } = [];

    public void Reset()
    {
        _syncing = true;
        Mode = TransferMode.TransferTime;
        SizeUnit = DataUnits.Get("GB");
        SpeedUnit = DataUnits.Get("Mb");
        SizeText = Text(Rational.FromInteger(10));
        SpeedText = Text(Rational.FromInteger(100));
        EfficiencyText = "100";
        DurationText = "10";
        DurationUnit = "min";
        ComparisonSpeedsText = "100 Mbps, 1 Gbps, 10 Gbps, 25 Gbps, 100 Gbps";
        ComparisonUsesEfficiency = true;
        _syncing = false;
        ReadSize();
        ReadSpeed();
        Recalculate();
    }

    public void ApplySpeedPreset(string preset)
    {
        if (!TryQuantity(preset, out var bits, out var unit)) return;
        _syncing = true;
        SpeedUnit = unit;
        SpeedText = Text(TransferCalculator.In(bits, unit));
        _syncing = false;
        ReadSpeed();
        Recalculate();
    }

    public void ApplyEfficiencyPreset(int percent) => EfficiencyText = percent.ToString(_culture);

    /// <summary>A local file's size (metadata only; the content is never read and the path is not kept).</summary>
    public void SetSizeBytes(long bytes)
    {
        var bits = Rational.FromInteger(new BigInteger(bytes) * 8);
        var unit = TransferCalculator.Best(bits, SizeUnit.Group is UnitGroup.BinaryBytes or UnitGroup.BinaryBits ? UnitGroup.BinaryBytes : UnitGroup.DecimalBytes);
        _syncing = true;
        SizeUnit = unit;
        SizeText = Text(TransferCalculator.In(bits, unit));
        _syncing = false;
        ReadSize();
        Recalculate();
    }

    // ---- change handlers
    partial void OnModeChanged(TransferMode value) => Recalculate();

    partial void OnSizeTextChanged(string value)
    {
        if (_syncing) return;
        ReadSize();
        Recalculate();
    }

    partial void OnSpeedTextChanged(string value)
    {
        if (_syncing) return;
        ReadSpeed();
        Recalculate();
    }

    partial void OnSizeUnitChanged(DataUnit oldValue, DataUnit newValue)
    {
        if (_syncing || newValue is null) return;
        if (_sizeBits is { } q) Show(() => SizeText = Text(TransferCalculator.In(q, newValue))); // same quantity, new unit
        Recalculate();
    }

    partial void OnSpeedUnitChanged(DataUnit oldValue, DataUnit newValue)
    {
        if (_syncing || newValue is null) return;
        if (_speedBits is { } q) Show(() => SpeedText = Text(TransferCalculator.In(q, newValue)));
        Recalculate();
    }

    partial void OnEfficiencyTextChanged(string value) => Recalculate();

    partial void OnDurationTextChanged(string value) => Recalculate();

    partial void OnDurationUnitChanged(string value) => Recalculate();

    partial void OnComparisonSpeedsTextChanged(string value) => Recalculate();

    partial void OnComparisonUsesEfficiencyChanged(bool value) => Recalculate();

    partial void OnSizeSliderChanged(double value)
    {
        if (_syncing) return;
        var bytes = Nice(value); // 10^value bytes, two significant digits
        var bits = bytes * Rational.FromInteger(8);
        var unit = SizeUnit.Group is UnitGroup.DecimalBytes or UnitGroup.BinaryBytes ? SizeUnit : DataUnits.Get("GB");
        Show(() =>
        {
            SizeUnit = unit;
            SizeText = Text(TransferCalculator.In(bits, unit));
        });
        _sizeBits = bits;
        Recalculate();
    }

    partial void OnSpeedSliderChanged(double value)
    {
        if (_syncing) return;
        var bits = Nice(value);
        var unit = TransferCalculator.Best(bits, SpeedUnit.Group);
        Show(() =>
        {
            SpeedUnit = unit;
            SpeedText = Text(TransferCalculator.In(bits, unit));
        });
        _speedBits = bits;
        Recalculate();
    }

    private void Show(Action change)
    {
        _syncing = true;
        try
        {
            change();
        }
        finally
        {
            _syncing = false;
        }
    }

    /// <summary>
    /// Text for an editable box: no grouping, the user's decimal separator, six significant digits for small values (up
    /// to 28 decimals, what the parser accepts), so a unit switch never shows a non-zero quantity as "0".
    /// </summary>
    private string Text(Rational value)
    {
        var decimals = 6;
        if (!value.IsZero && value < Rational.One) decimals = Math.Clamp((int)Math.Ceiling(-Math.Log10(value.ToDouble())) + 5, 6, 28);
        return value.ToFixed(decimals, _culture);
    }

    private static Rational Nice(double log10)
    {
        var exp = (int)Math.Floor(log10);
        var mant = Math.Round(Math.Pow(10, log10 - exp), 1, MidpointRounding.AwayFromZero);
        return Rational.FromDecimal((decimal)mant) * Rational.Pow10(exp);
    }

    private void ReadSize()
    {
        _sizeBits = TransferCalculator.TryParse(SizeText, _culture, out var v, out _) ? v * SizeUnit.Factor : null;
        if (_sizeBits is { } bits && bits.Sign > 0) Show(() => SizeSlider = Math.Clamp(Math.Log10((bits / Rational.FromInteger(8)).ToDouble()), SizeSliderMin, SizeSliderMax));
    }

    private void ReadSpeed()
    {
        _speedBits = TransferCalculator.TryParse(SpeedText, _culture, out var v, out _) ? v * SpeedUnit.Factor : null;
        if (_speedBits is { } bits && bits.Sign > 0) Show(() => SpeedSlider = Math.Clamp(Math.Log10(bits.ToDouble()), SpeedSliderMin, SpeedSliderMax));
    }

    /// <summary>"1 Gbps" or "12.5 MB/s" → bits/s and its unit.</summary>
    private bool TryQuantity(string text, out Rational bits, out DataUnit unit)
    {
        bits = Rational.Zero;
        unit = SpeedUnit;
        var parts = text.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || DataUnits.TryGet(parts[1]) is not { } u || !TransferCalculator.TryParse(parts[0], CultureInfo.InvariantCulture, out var n, out _)
            && !TransferCalculator.TryParse(parts[0], _culture, out n, out _)) return false;
        unit = u;
        bits = n * u.Factor;
        return true;
    }

    private Rational DurationSeconds(Rational n) => n * Rational.FromInteger(DurationUnit switch { "min" => 60, "h" => 3600, "days" => 86_400, _ => 1 });

    /// <summary>Recomputes everything; an invalid input shows its reason and clears the results (never NaN or ∞).</summary>
    public void Recalculate()
    {
        if (_syncing) return;
        Details.Clear();
        Comparison.Clear();
        ResultLabel = Mode == TransferMode.TransferTime ? "Estimated transfer time" : "Required link speed";
        var c = _culture;
        string? error = null;
        if (!TransferCalculator.TryParse(SizeText, c, out var size, out var e1)) error = "File size: " + e1;
        Rational speed = default, duration = default, efficiency = default;
        if (error is null && Mode == TransferMode.TransferTime && !TransferCalculator.TryParse(SpeedText, c, out speed, out var e2)) error = "Connection speed: " + e2;
        else if (error is null && Mode == TransferMode.TransferTime && speed.IsZero) error = "Connection speed: must be more than zero.";
        if (error is null && Mode == TransferMode.RequiredSpeed && !TransferCalculator.TryParse(DurationText, c, out duration, out var e3)) error = "Duration: " + e3;
        else if (error is null && Mode == TransferMode.RequiredSpeed && duration.IsZero) error = "Duration: must be more than zero.";
        if (error is null && (!TransferCalculator.TryParse(EfficiencyText, c, out var pct, out var e4) || !TransferCalculator.TryEfficiency(pct, out efficiency, out e4))) error = "Effective throughput: " + e4;
        if (_speedBits is { } sb && sb.Sign > 0)
            SpeedConversion = $"{TransferCalculator.Format(sb, Best(sb, UnitGroup.DecimalBits), c, rate: true)} = {TransferCalculator.Format(sb, Best(sb, UnitGroup.DecimalBytes), c, rate: true)} = {TransferCalculator.Format(sb, Best(sb, UnitGroup.BinaryBytes), c, rate: true)}";
        else SpeedConversion = "";

        Error = error ?? "";
        if (error is not null)
        {
            ResultMain = "—";
            ResultSub = "";
            Breakdown = "";
            ComparisonNote = "";
            return;
        }

        var sizeBits = size * SizeUnit.Factor;
        var r = Mode == TransferMode.TransferTime
            ? TransferCalculator.Time(sizeBits, speed * SpeedUnit.Factor, efficiency)
            : TransferCalculator.Speed(sizeBits, DurationSeconds(duration), efficiency);
        var eff = (efficiency * Rational.FromInteger(100)).ToFixed(2, c) + " %";
        string Rate(Rational bits) => $"{TransferCalculator.Format(bits, Best(bits, UnitGroup.DecimalBits), c, rate: true)} / {TransferCalculator.Format(bits, Best(bits, UnitGroup.DecimalBytes), c, rate: true)}";
        if (Mode == TransferMode.TransferTime)
        {
            ResultMain = TransferCalculator.Duration(r.Seconds, c);
            ResultSub = "Effective throughput: " + Rate(r.EffectiveBitsPerSecond);
            Details.Add(new("File size", TransferCalculator.Format(sizeBits, SizeUnit, c) + $" ({FormatBytes(sizeBits)})"));
            Details.Add(new("Link speed", TransferCalculator.Format(r.RateBitsPerSecond, SpeedUnit, c, rate: true)));
            Details.Add(new("Efficiency", eff + (efficiency == Rational.One ? " (theoretical)" : " (assumption)")));
            Details.Add(new("Effective speed", Rate(r.EffectiveBitsPerSecond)));
            Details.Add(new("Theoretical minimum", TransferCalculator.Duration(r.TheoreticalSeconds, c) + " at 100 %"));
        }
        else
        {
            ResultMain = Rate(r.RateBitsPerSecond);
            ResultSub = efficiency == Rational.One ? "Payload rate equals the link speed at 100 %" : "Payload rate needed: " + Rate(r.EffectiveBitsPerSecond);
            Details.Add(new("File size", TransferCalculator.Format(sizeBits, SizeUnit, c) + $" ({FormatBytes(sizeBits)})"));
            Details.Add(new("Target duration", TransferCalculator.Duration(r.Seconds, c)));
            Details.Add(new("Efficiency", eff + (efficiency == Rational.One ? " (theoretical)" : " (assumption)")));
            Details.Add(new("Link speed needed", Rate(r.RateBitsPerSecond)));
        }

        Breakdown = BreakdownText(r);
        var useEff = ComparisonUsesEfficiency && efficiency != Rational.One;
        ComparisonNote = useEff ? $"At {eff} effective throughput." : "Theoretical (100 %).";
        foreach (var s in ComparisonSpeedsText.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Take(12))
        {
            if (TryQuantity(s, out var bits, out _) && bits.Sign > 0)
                Comparison.Add(new(s, TransferCalculator.Duration(TransferCalculator.Time(sizeBits, bits, useEff ? efficiency : Rational.One).Seconds, c)));
            else Comparison.Add(new(s, "not a speed (e.g. \"10 Gbps\")"));
        }
    }

    private static DataUnit Best(Rational bits, UnitGroup group) => TransferCalculator.Best(bits, group);

    private string FormatBytes(Rational bits) => TransferCalculator.FormatNumber(bits / Rational.FromInteger(8), _culture, 0) + " bytes";

    private string BreakdownText(TransferResult r)
    {
        var c = _culture;
        string N(Rational v, int d = 3) => TransferCalculator.FormatNumber(v, c, d);
        var sb = new StringBuilder();
        sb.AppendLine(c, $"File size        {N(r.SizeBits / Rational.FromInteger(8), 0)} bytes = {N(r.SizeBits, 0)} bits");
        sb.AppendLine(c, $"Link speed       {N(r.RateBitsPerSecond)} bit/s = {N(r.RateBitsPerSecond / Rational.FromInteger(8))} B/s");
        sb.AppendLine(c, $"Efficiency       {N(r.Efficiency * Rational.FromInteger(100), 4)} %");
        sb.AppendLine(c, $"Effective speed  {N(r.EffectiveBitsPerSecond)} bit/s = {N(r.EffectiveBitsPerSecond / Rational.FromInteger(8))} B/s");
        var exact = r.Seconds.Denominator.IsOne ? "" : r.Seconds.Denominator < BigInteger.Pow(10, 6) && r.Seconds.Numerator < BigInteger.Pow(10, 15) ? $" (exactly {r.Seconds.Numerator}/{r.Seconds.Denominator} s)" : "";
        sb.AppendLine(c, $"Duration         {N(r.Seconds, 9)} s{exact}");
        sb.AppendLine(c, $"Readable         {TransferCalculator.Duration(r.Seconds, c)}");
        sb.Append(Mode == TransferMode.TransferTime
            ? "Formula          seconds = size in bits ÷ (link bit/s × efficiency)"
            : "Formula          link bit/s = size in bits ÷ (seconds × efficiency)");
        return sb.ToString();
    }

    /// <summary>The result as plain text for the clipboard.</summary>
    public string CopyText()
    {
        var sb = new StringBuilder();
        sb.AppendLine(ResultLabel + ": " + (Error.Length > 0 ? Error : ResultMain));
        if (Error.Length == 0)
        {
            if (ResultSub.Length > 0) sb.AppendLine(ResultSub);
            foreach (var d in Details) sb.AppendLine(d.Label + ": " + d.Value);
            sb.AppendLine().AppendLine(Breakdown);
        }

        return sb.ToString().TrimEnd();
    }
}
