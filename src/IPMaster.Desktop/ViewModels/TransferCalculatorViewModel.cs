using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using IPMaster.Core.Tools;

namespace IPMaster.Desktop.ViewModels;

/// <summary>
/// Download Calculator: file size, transfer speed and an efficiency assumption in, estimated time and technical figures out,
/// recalculated on every change. Decimal units only (KB = 1,000 bytes … PB = 10^15 bytes; kbps/Mbps/Gbps are bits, MB/s and
/// GB/s bytes per second). The arithmetic is the exact <see cref="TransferCalculator"/>; nothing is downloaded or measured.
/// The speed slider (<see cref="SpeedPosition"/>, D-112) and the speed field update each other without loops: a typed
/// speed moves the slider and is never rounded; a dragged position writes a three-digit speed and is not moved back.
/// </summary>
public sealed partial class TransferCalculatorViewModel : ObservableObject
{
    public static readonly string[] SizeUnits = ["KB", "MB", "GB", "TB", "PB"];

    public static readonly string[] SpeedUnits = ["kbps", "Mbps", "Gbps", "MB/s", "GB/s"];

    public static readonly string[] QuickSpeeds = ["100 Mbps", "1 Gbps", "10 Gbps", "25 Gbps", "100 Gbps"];

    /// <summary>Planning assumptions, not measurements: the share of the link speed the transfer achieves.</summary>
    public static readonly (int Percent, string Label)[] Efficiencies = [(100, "100% — Theoretical"), (95, "95% — Efficient"), (90, "90% — Typical"), (80, "80% — Conservative")];

    public const string UnitsNote = "Decimal (SI) units: 1 KB = 1,000 bytes, 1 MB = 10^6, 1 GB = 10^9, 1 TB = 10^12, 1 PB = 10^15 bytes. "
                                    + "Speeds in bps are bits per second (1 byte = 8 bits), so 1 Gbps = 125 MB/s. Binary units (KiB, MiB, GiB = 2^10, 2^20, 2^30 bytes) are not used.";

    private static readonly Dictionary<string, string> Catalog = new(StringComparer.Ordinal)
    {
        ["KB"] = "kB", ["MB"] = "MB", ["GB"] = "GB", ["TB"] = "TB", ["PB"] = "PB",
        ["kbps"] = "kb", ["Mbps"] = "Mb", ["Gbps"] = "Gb", ["MB/s"] = "MB", ["GB/s"] = "GB",
    };

    private readonly CultureInfo _culture;
    private bool _batch;
    private bool _fromSlider;
    private bool _positionFromSpeed;

    public TransferCalculatorViewModel(CultureInfo? culture = null)
    {
        _culture = culture ?? CultureInfo.CurrentCulture;
        Reset();
    }

    /// <summary>Raised after every recalculation with a valid result (the view's short result emphasis).</summary>
    public event EventHandler? Recalculated;

    [ObservableProperty] public partial string SizeText { get; set; } = "";

    [ObservableProperty] public partial string SizeUnit { get; set; } = "GB";

    [ObservableProperty] public partial string SpeedText { get; set; } = "";

    [ObservableProperty] public partial string SpeedUnit { get; set; } = "Mbps";

    /// <summary>Slider position, 0 (1 Mbps) … 9 (200 Gbps); see <see cref="SpeedScale"/>.</summary>
    [ObservableProperty] public partial double SpeedPosition { get; set; }

    /// <summary>Index into <see cref="Efficiencies"/>.</summary>
    [ObservableProperty] public partial int EfficiencyIndex { get; set; }

    /// <summary>"13m 20s", or "—" while an input is invalid.</summary>
    [ObservableProperty] public partial string Result { get; set; } = "";

    /// <summary>What the result assumes: "Theoretical throughput" or the chosen efficiency.</summary>
    [ObservableProperty] public partial string ResultNote { get; set; } = "";

    /// <summary>The speed in the other notation ("100 Mbps = 12.5 MB/s"): bits and bytes side by side.</summary>
    [ObservableProperty] public partial string SpeedNote { get; set; } = "";

    [ObservableProperty] public partial string Error { get; set; } = "";

    /// <summary>The quick speed that equals the current speed exactly, or "".</summary>
    [ObservableProperty] public partial string ActivePreset { get; set; } = "";

    [ObservableProperty] public partial string Throughput { get; set; } = "";

    [ObservableProperty] public partial string TotalSize { get; set; } = "";

    [ObservableProperty] public partial string TotalData { get; set; } = "";

    [ObservableProperty] public partial string EfficiencyText { get; set; } = "";

    [ObservableProperty] public partial bool IsEstimate { get; set; }

    [ObservableProperty] public partial string BitsPerSecond { get; set; } = "";

    [ObservableProperty] public partial string BytesPerSecond { get; set; } = "";

    [ObservableProperty] public partial string EffectiveSpeed { get; set; } = "";

    [ObservableProperty] public partial string TotalBytes { get; set; } = "";

    [ObservableProperty] public partial string TotalBits { get; set; } = "";

    [ObservableProperty] public partial string Seconds { get; set; } = "";

    [ObservableProperty] public partial string Minutes { get; set; } = "";

    [ObservableProperty] public partial string Hours { get; set; } = "";

    [ObservableProperty] public partial string Days { get; set; } = "";

    [ObservableProperty] public partial string Formula { get; set; } = "";

    partial void OnSizeTextChanged(string value) => Recalculate();

    partial void OnSizeUnitChanged(string value) => Recalculate();

    partial void OnSpeedTextChanged(string value) => Recalculate();

    partial void OnSpeedUnitChanged(string value) => Recalculate();

    partial void OnEfficiencyIndexChanged(int value) => Recalculate();

    partial void OnSpeedPositionChanged(double value)
    {
        if (_positionFromSpeed) return;
        var bps = SpeedScale.FromPosition(value);
        var unit = SpeedUnit is "MB/s" or "GB/s" ? (bps >= Bits("GB") ? "GB/s" : "MB/s") : bps >= Bits("Gb") ? "Gbps" : "Mbps";
        _fromSlider = true;
        try
        {
            Batch(() =>
            {
                SpeedUnit = unit;
                SpeedText = TransferCalculator.FormatNumber(bps / Bits(Catalog[unit]), _culture);
            });
        }
        finally
        {
            _fromSlider = false;
        }
    }

    public void Reset() => Batch(() =>
    {
        SizeText = "10";
        SizeUnit = "GB";
        SpeedText = "100";
        SpeedUnit = "Mbps";
        EfficiencyIndex = 0;
    });

    /// <summary>"1 Gbps" → 1 and Gbps.</summary>
    public void ApplyPreset(string preset)
    {
        ArgumentNullException.ThrowIfNull(preset);
        var parts = preset.Split(' ', 2);
        Batch(() =>
        {
            SpeedUnit = parts[1];
            SpeedText = parts[0];
        });
    }

    public string CopyText() => Error.Length > 0
        ? ""
        : $"{SizeText} {SizeUnit} at {SpeedText} {SpeedUnit}, {EfficiencyText} efficiency: {Result} ({Seconds} s; throughput {Throughput})";

    private static Rational Bits(string symbol) => DataUnits.Get(symbol).Factor;

    private void Batch(Action change)
    {
        _batch = true;
        try
        {
            change();
        }
        finally
        {
            _batch = false;
        }

        Recalculate();
    }

    private string N(Rational v, int decimals = 3) => TransferCalculator.FormatNumber(v, _culture, decimals);

    private void Recalculate()
    {
        if (_batch || !Catalog.TryGetValue(SizeUnit ?? "", out var sizeSymbol) || !Catalog.TryGetValue(SpeedUnit ?? "", out var speedSymbol)) return;
        string? error = null;
        if (!TransferCalculator.TryParse(SizeText, _culture, out var size, out var e1)) error = "File size: " + e1;
        else if (size.IsZero) error = "File size: must be more than zero.";
        if (!TransferCalculator.TryParse(SpeedText, _culture, out var speed, out var e2)) error ??= "Transfer speed: " + e2;
        else if (speed.IsZero) error ??= "Transfer speed: must be more than zero.";
        var index = Math.Clamp(EfficiencyIndex, 0, Efficiencies.Length - 1);
        var percent = Efficiencies[index].Percent;
        EfficiencyText = percent.ToString(_culture) + " %";
        IsEstimate = percent < 100;
        Error = error ?? "";
        var bitsPerSecond = speed * Bits(speedSymbol);
        ActivePreset = speed.Sign > 0 ? QuickSpeeds.FirstOrDefault(p => PresetBits(p) == bitsPerSecond) ?? "" : "";
        if (speed.Sign > 0 && !_fromSlider)
        {
            _positionFromSpeed = true;
            SpeedPosition = SpeedScale.ToPosition(bitsPerSecond);
            _positionFromSpeed = false;
        }

        if (error is not null)
        {
            Result = "—";
            ResultNote = SpeedNote = Throughput = TotalSize = TotalData = BitsPerSecond = BytesPerSecond = EffectiveSpeed = "";
            TotalBytes = TotalBits = Seconds = Minutes = Hours = Days = Formula = "";
            return;
        }

        TransferCalculator.TryEfficiency(Rational.FromInteger(percent), out var efficiency, out _);
        var sizeBits = size * Bits(sizeSymbol);
        var r = TransferCalculator.Time(sizeBits, bitsPerSecond, efficiency);
        Result = SpeedScale.CompactDuration(r.Seconds, _culture);
        ResultNote = percent == 100 ? "Theoretical throughput" : $"At {percent} % of the link speed (planning assumption)";
        var bits = SpeedUnit!.EndsWith("bps", StringComparison.Ordinal);
        var other = TransferCalculator.Best(bitsPerSecond, bits ? UnitGroup.DecimalBytes : UnitGroup.DecimalBits);
        SpeedNote = $"{SpeedText} {SpeedUnit} = {TransferCalculator.Format(bitsPerSecond, other, _culture, rate: true)}";

        var effective = r.EffectiveBitsPerSecond;
        Throughput = TransferCalculator.Format(effective, TransferCalculator.Best(effective, UnitGroup.DecimalBytes), _culture, rate: true);
        TotalSize = TransferCalculator.Format(sizeBits, TransferCalculator.Best(sizeBits, UnitGroup.DecimalBytes), _culture);
        TotalData = TransferCalculator.Format(sizeBits, TransferCalculator.Best(sizeBits, UnitGroup.DecimalBits), _culture);
        BitsPerSecond = N(bitsPerSecond) + " bit/s";
        BytesPerSecond = N(bitsPerSecond / Rational.FromInteger(8)) + " B/s";
        EffectiveSpeed = TransferCalculator.Format(effective, TransferCalculator.Best(effective, UnitGroup.DecimalBits), _culture, rate: true)
                         + " = " + Throughput;
        TotalBytes = N(sizeBits / Rational.FromInteger(8)) + " B";
        TotalBits = N(sizeBits) + " bit";
        Seconds = N(r.Seconds);
        Minutes = N(r.Seconds / Rational.FromInteger(60));
        Hours = N(r.Seconds / Rational.FromInteger(3600), 4);
        Days = N(r.Seconds / Rational.FromInteger(86_400), 5);
        Formula = $"time = total bits ÷ (link bit/s × efficiency) = {TotalBits} ÷ ({BitsPerSecond} × {EfficiencyText}) = {Seconds} s";
        Recalculated?.Invoke(this, EventArgs.Empty);
    }

    private static Rational PresetBits(string preset)
    {
        var parts = preset.Split(' ', 2);
        return Rational.FromInteger(int.Parse(parts[0], CultureInfo.InvariantCulture)) * Bits(Catalog[parts[1]]);
    }
}
