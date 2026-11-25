using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using IPMaster.Core.Tools;

namespace IPMaster.Desktop.ViewModels;

/// <summary>
/// Download Calculator: file size and connection speed in, estimated time out, recalculated on every change. Decimal
/// units only (KB = 1,000 bytes … PB = 10^15 bytes; kbps/Mbps/Gbps are bits, MB/s and GB/s bytes per second). The
/// arithmetic is the exact <see cref="TransferCalculator"/>; nothing is downloaded or measured.
/// </summary>
public sealed partial class TransferCalculatorViewModel : ObservableObject
{
    public static readonly string[] SizeUnits = ["KB", "MB", "GB", "TB", "PB"];

    public static readonly string[] SpeedUnits = ["kbps", "Mbps", "Gbps", "MB/s", "GB/s"];

    public static readonly string[] QuickSpeeds = ["100 Mbps", "1 Gbps", "10 Gbps", "25 Gbps"];

    private static readonly Dictionary<string, string> Catalog = new(StringComparer.Ordinal)
    {
        ["KB"] = "kB", ["MB"] = "MB", ["GB"] = "GB", ["TB"] = "TB", ["PB"] = "PB",
        ["kbps"] = "kb", ["Mbps"] = "Mb", ["Gbps"] = "Gb", ["MB/s"] = "MB", ["GB/s"] = "GB",
    };

    private readonly CultureInfo _culture;

    public TransferCalculatorViewModel(CultureInfo? culture = null)
    {
        _culture = culture ?? CultureInfo.CurrentCulture;
        Reset();
    }

    [ObservableProperty] public partial string SizeText { get; set; } = "";

    [ObservableProperty] public partial string SizeUnit { get; set; } = "GB";

    [ObservableProperty] public partial string SpeedText { get; set; } = "";

    [ObservableProperty] public partial string SpeedUnit { get; set; } = "Mbps";

    /// <summary>"13 min 20 sec", or "—" while an input is invalid.</summary>
    [ObservableProperty] public partial string Result { get; set; } = "";

    /// <summary>The speed in the other notation ("100 Mbps = 12.5 MB/s"): bits and bytes side by side.</summary>
    [ObservableProperty] public partial string SpeedNote { get; set; } = "";

    [ObservableProperty] public partial string Error { get; set; } = "";

    partial void OnSizeTextChanged(string value) => Recalculate();

    partial void OnSizeUnitChanged(string value) => Recalculate();

    partial void OnSpeedTextChanged(string value) => Recalculate();

    partial void OnSpeedUnitChanged(string value) => Recalculate();

    public void Reset()
    {
        SizeText = "10";
        SizeUnit = "GB";
        SpeedText = "100";
        SpeedUnit = "Mbps";
        Recalculate();
    }

    /// <summary>"1 Gbps" → 1 and Gbps.</summary>
    public void ApplyPreset(string preset)
    {
        ArgumentNullException.ThrowIfNull(preset);
        var parts = preset.Split(' ', 2);
        SpeedUnit = parts[1];
        SpeedText = parts[0];
    }

    public string CopyText() => Error.Length > 0 ? "" : $"{SizeText} {SizeUnit} at {SpeedText} {SpeedUnit}: {Result}";

    private void Recalculate()
    {
        if (!Catalog.TryGetValue(SizeUnit ?? "", out var sizeSymbol) || !Catalog.TryGetValue(SpeedUnit ?? "", out var speedSymbol)) return;
        string? error = null;
        if (!TransferCalculator.TryParse(SizeText, _culture, out var size, out var e1)) error = "File size: " + e1;
        if (!TransferCalculator.TryParse(SpeedText, _culture, out var speed, out var e2)) error ??= "Connection speed: " + e2;
        else if (speed.IsZero) error ??= "Connection speed: must be more than zero.";
        Error = error ?? "";
        if (error is not null)
        {
            Result = "—";
            SpeedNote = "";
            return;
        }

        var bitsPerSecond = speed * DataUnits.Get(speedSymbol).Factor;
        var r = TransferCalculator.Time(size * DataUnits.Get(sizeSymbol).Factor, bitsPerSecond, Rational.One);
        Result = TransferCalculator.Duration(r.Seconds, _culture);
        var bits = SpeedUnit!.EndsWith("bps", StringComparison.Ordinal);
        var other = TransferCalculator.Best(bitsPerSecond, bits ? UnitGroup.DecimalBytes : UnitGroup.DecimalBits);
        SpeedNote = $"{SpeedText} {SpeedUnit} = {TransferCalculator.Format(bitsPerSecond, other, _culture, rate: true)}";
    }
}
