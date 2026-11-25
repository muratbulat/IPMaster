using System.Globalization;
using IPMaster.Core.Scanning;

namespace IPMaster.Desktop.ViewModels;

/// <summary>
/// What the status bar says about the interactive scan (D-100). Preparing and AwaitingConfirmation happen before a
/// <see cref="ScanSession"/> exists; every later phase comes from the engine's <see cref="ScanState"/>, so the bar
/// can never contradict the engine.
/// </summary>
public enum ScanPhase
{
    Idle,
    Preparing,
    AwaitingConfirmation,
    Scanning,
    Paused,
    Stopping,
    Completed,
    Stopped,
    Failed,
}

/// <summary>Status text and progress bar for one moment of a scan.</summary>
public sealed record ScanView(string Status, bool ProgressVisible, bool Indeterminate, double Percent);

/// <summary>
/// Maps scan phases to the status bar (D-100). The bar shows only while work is in progress (preparing, scanning,
/// paused, stopping); a finished, stopped or failed scan hides it and says so in words, so a full bar never stays behind
/// looking busy. A percentage is shown only when the total is exact; an estimated or unknown total shows counts.
/// </summary>
public static class ScanPresentation
{
    public static ScanPhase FromEngine(ScanState state) => state switch
    {
        ScanState.Running => ScanPhase.Scanning,
        ScanState.Paused => ScanPhase.Paused,
        ScanState.Stopping => ScanPhase.Stopping,
        ScanState.Completed => ScanPhase.Completed,
        ScanState.Cancelled => ScanPhase.Stopped,
        _ => ScanPhase.Failed,
    };

    /// <summary>Phases in which a scan owns the engine: Start is not offered, Stop is.</summary>
    public static bool IsBusy(ScanPhase phase) => phase is ScanPhase.Preparing or ScanPhase.AwaitingConfirmation or ScanPhase.Scanning or ScanPhase.Paused or ScanPhase.Stopping;

    public static bool IsTerminal(ScanPhase phase) => phase is ScanPhase.Completed or ScanPhase.Stopped or ScanPhase.Failed;

    public static ScanView Before(ScanPhase phase) => phase switch
    {
        ScanPhase.Preparing => new("Preparing scan…", true, true, 0),
        ScanPhase.AwaitingConfirmation => new("Waiting for scan confirmation", false, false, 0),
        _ => new("Ready", false, false, 0),
    };

    public static ScanView During(ScanProgress p)
    {
        var c = CultureInfo.CurrentCulture;
        var exact = p.TotalIsExact && p.Total > 0;
        var percent = exact ? Math.Min(100, 100.0 * p.Processed / p.Total) : 0;
        var counts = p.Total == 0 ? string.Create(c, $"{p.Processed:N0} addresses")
            : exact ? string.Create(c, $"{p.Processed:N0} / {p.Total:N0} addresses")
            : string.Create(c, $"{p.Processed:N0} / ≤{p.Total:N0} addresses");
        return FromEngine(p.State) switch
        {
            ScanPhase.Paused => new("Scan paused · " + counts, true, false, percent),
            ScanPhase.Stopping => new("Stopping scan…", true, false, percent),
            _ => new(string.Create(c, $"Scanning · {counts}{(exact ? $" · {percent:0}%" : "")} · {p.Elapsed.TotalSeconds:0} s"), true, !exact, percent),
        };
    }

    public static ScanView After(ScanSummary s)
    {
        ArgumentNullException.ThrowIfNull(s);
        var c = CultureInfo.CurrentCulture;
        var tail = string.Create(c, $"{s.Online:N0} online · {s.Elapsed.TotalSeconds:0.0} s");
        return FromEngine(s.State) switch
        {
            ScanPhase.Completed => new(string.Create(c, $"Scan completed · {s.Processed:N0} addresses · {tail}"), false, false, 100),
            ScanPhase.Stopped => new(string.Create(c, $"Scan stopped by user · {s.Processed:N0} addresses processed · {tail}"), false, false, 0),
            _ => new("Scan failed · " + (string.IsNullOrWhiteSpace(s.Error) ? "see the log" : s.Error), false, false, 0),
        };
    }
}
