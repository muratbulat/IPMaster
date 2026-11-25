using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure.Monitoring;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Desktop.ViewModels;

/// <summary>What live monitoring is doing (D-100); independent of interactive and background scanning.</summary>
public enum MonitoringPhase
{
    Stopped,
    Running,
    Paused,
    Stopping,
}

/// <summary>Phase 5: live monitoring, background scanning, device history.</summary>
public sealed partial class MainWindowViewModel
{
    private LiveMonitor? _monitor;
    private ContinuousOperations? _ops;

    public LiveMonitor Monitor => _monitor ??= Services.GetRequiredService<LiveMonitor>();

    public ContinuousOperations Ops => _ops ??= Services.GetRequiredService<ContinuousOperations>();

    [ObservableProperty] public partial bool BackgroundRunning { get; set; }

    [ObservableProperty] public partial string BackgroundStatus { get; set; } = "Background scan off";

    [ObservableProperty] public partial string MonitoringTally { get; set; } = "";

    /// <summary>The tally in words (tooltip and screen readers; the bullets alone differ only by colour).</summary>
    [ObservableProperty] public partial string MonitoringTallyText { get; set; } = "";

    /// <summary>Tray-style notification (title, text) for background events; the window shows it.</summary>
    public event EventHandler<(string Title, string Text)>? Notify;

    /// <summary>Events dialog → Test Notification: shows one through the same path as background events.</summary>
    public void TestNotification() => Notify?.Invoke(this, ("IPMaster", "Test notification: background-scan events will appear like this."));

    private bool _continuousReady;

    /// <summary>Wires monitor and background services once (called after settings are available).</summary>
    public void InitContinuous()
    {
        if (_continuousReady) return;
        _continuousReady = true;
        Monitor.Settings = Settings.Monitoring;
        Monitor.Updated += (_, keys) => Dispatcher.UIThread.Post(() => OnMonitorUpdated(keys));
        Ops.Notifier.Balloon = (t, m) => Dispatcher.UIThread.Post(() => Notify?.Invoke(this, (t, m)));
        Ops.RoundFinished += (_, r) => Dispatcher.UIThread.Post(() => OnRoundFinished(r));
        Ops.Stopped += (_, _) => Dispatcher.UIThread.Post(OnBackgroundStopped);
        Results.IsBold = d => Settings.History.Enabled && Ops.HistoryView.IsNewcomer(d);
        if (Settings.History.Enabled)
        {
            var retention = Settings.History.RetentionDays;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Ops.RefreshHistoryAsync().ConfigureAwait(false);
                    Ops.History.Cleanup(retention, DateTimeOffset.UtcNow);
                    Dispatcher.UIThread.Post(() => Results.Rebuild());
                }
                catch (Exception ex) when (ex is not OutOfMemoryException) // was unobserved (D-087)
                {
                    Dispatcher.UIThread.Post(() => StatusText = "Device history not loaded: " + ex.Message);
                }
            });
        }
    }

    /// <summary>Monitoring and history columns (computed live, not persisted in results).</summary>
    public IEnumerable<ResultColumn> RuntimeColumns()
    {
        if (_monitor is { } m && (m.Active.Count > 0 || Settings.Monitoring.MonitorAll || Results.Nodes.Any(n => m.Series(n.Result.Key) is not null)))
        {
            foreach (var c in MonitorColumns.For(m)) yield return c;
        }

        if (Settings.History.Enabled)
        {
            foreach (var c in Ops.HistoryView.Columns(Settings.History, () => DateTimeOffset.UtcNow)) yield return c;
        }
    }

    // ---------------- live monitoring ----------------
    public void StartMonitoring(IEnumerable<DeviceResult> devices)
    {
        var hadColumns = Monitor.Active.Count > 0 || Settings.Monitoring.MonitorAll;
        var refused = 0;
        foreach (var d in devices)
        {
            if (!Monitor.Start(d.Key)) refused++;
        }

        if (refused > 0) StatusText = $"{refused} device(s) not monitored: the limit is {Settings.Monitoring.MaxDevices}.";
        if (!hadColumns) ApplyViewSettings();
        UpdateTally();
    }

    public void StopMonitoring(IEnumerable<DeviceResult> devices)
    {
        foreach (var d in devices) Monitor.Stop(d.Key);
        UpdateTally();
    }

    // ---------------- global monitoring controls (D-100) ----------------
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StopAllMonitoringCommand), nameof(PauseAllMonitoringCommand), nameof(ResumeAllMonitoringCommand))]
    [NotifyPropertyChangedFor(nameof(IsMonitoringRunning), nameof(IsMonitoringPaused))]
    public partial MonitoringPhase MonitoringState { get; set; }

    /// <summary>"Monitoring: Running · 12 devices" and so on: the state in words, not only coloured bullets.</summary>
    [ObservableProperty] public partial string MonitoringStatus { get; set; } = "Monitoring: Stopped · 0 active devices";

    public bool IsMonitoringRunning => MonitoringState == MonitoringPhase.Running;

    public bool IsMonitoringPaused => MonitoringState == MonitoringPhase.Paused;

    /// <summary>True after Stop All while Monitor All is on: arriving devices are not enrolled until Resume Automatic.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ResumeAutomaticMonitoringCommand))]
    public partial bool AutomaticMonitoringSuppressed { get; set; }

    private bool CanStopAllMonitoring() => MonitoringState is MonitoringPhase.Running or MonitoringPhase.Paused;

    private bool CanPauseAllMonitoring() => MonitoringState == MonitoringPhase.Running;

    private bool CanResumeAllMonitoring() => MonitoringState == MonitoringPhase.Paused;

    private bool CanResumeAutomaticMonitoring() => AutomaticMonitoringSuppressed;

    /// <summary>
    /// Stops every monitored device without selecting any (D-100): waits for running probes, keeps history, and keeps
    /// Monitor All from re-enrolling devices from later scan results until Resume Automatic Monitoring. Interactive and
    /// background scans are not touched. Repeated calls while stopping do nothing.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanStopAllMonitoring))]
    private async Task StopAllMonitoringAsync()
    {
        if (MonitoringState == MonitoringPhase.Stopping || _monitor is not { } m) return;
        MonitoringState = MonitoringPhase.Stopping;
        MonitoringStatus = "Monitoring: Stopping…";
        try
        {
            await m.StopAllAsync();
        }
        finally
        {
            MonitoringState = MonitoringPhase.Stopped; // leave Stopping before recomputing
            UpdateTally();
            foreach (var row in Results.Rows) row.Invalidate();
        }
    }

    [RelayCommand(CanExecute = nameof(CanPauseAllMonitoring))]
    private void PauseAllMonitoring()
    {
        _monitor?.Pause();
        UpdateTally();
    }

    [RelayCommand(CanExecute = nameof(CanResumeAllMonitoring))]
    private void ResumeAllMonitoring()
    {
        _monitor?.Resume();
        UpdateTally();
    }

    /// <summary>Lets Monitor All enrol devices again and enrols the online devices now in the results.</summary>
    [RelayCommand(CanExecute = nameof(CanResumeAutomaticMonitoring))]
    private void ResumeAutomaticMonitoring()
    {
        Monitor.ResumeAutomatic();
        foreach (var n in Results.Nodes) OnArrived(n.Result);
        UpdateTally();
    }

    private void UpdateMonitoringState()
    {
        if (MonitoringState == MonitoringPhase.Stopping) return; // Stop All reports its own end
        var active = _monitor?.Active.Count ?? 0;
        MonitoringState = active == 0 ? MonitoringPhase.Stopped : _monitor!.IsPaused ? MonitoringPhase.Paused : MonitoringPhase.Running;
        AutomaticMonitoringSuppressed = _monitor?.AutomaticSuppressed == true && Settings.Monitoring.MonitorAll;
        var devices = active == 1 ? "1 device" : $"{active} devices";
        MonitoringStatus = MonitoringState switch
        {
            MonitoringPhase.Running => $"Monitoring: Running · {devices}",
            MonitoringPhase.Paused => $"Monitoring: Paused · {devices}",
            _ => "Monitoring: Stopped · 0 active devices",
        } + (AutomaticMonitoringSuppressed ? " · automatic monitoring stopped" : "");
    }

    private void OnMonitorUpdated(IReadOnlyList<AddressKey> keys)
    {
        var set = keys.ToHashSet();
        foreach (var row in Results.Rows.Where(r => !r.IsShare && set.Contains(r.Result.Key))) row.Invalidate();
        UpdateTally();
        MonitorTick?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Raised each monitoring round (charts and route views refresh on it).</summary>
    public event EventHandler? MonitorTick;

    private void UpdateTally()
    {
        UpdateMonitoringState();
        if (Monitor.Active.Count == 0)
        {
            MonitoringTally = "";
            MonitoringTallyText = "";
            return;
        }

        var q = Monitor.Active.Select(k => Monitor.Snapshot(k)?.Quality ?? LinkQuality.Unknown).GroupBy(x => x).ToDictionary(g => g.Key, g => g.Count());
        MonitoringTally = $"{MonitorColumns.Bullet(LinkQuality.Good)} {q.GetValueOrDefault(LinkQuality.Good)}  {MonitorColumns.Bullet(LinkQuality.Degraded)} {q.GetValueOrDefault(LinkQuality.Degraded)}  "
                          + $"{MonitorColumns.Bullet(LinkQuality.Critical)} {q.GetValueOrDefault(LinkQuality.Critical)}";
        MonitoringTallyText = $"Monitored devices: {q.GetValueOrDefault(LinkQuality.Good)} good, {q.GetValueOrDefault(LinkQuality.Degraded)} degraded, {q.GetValueOrDefault(LinkQuality.Critical)} critical";
        if (Monitor.LaggingCount() is > 0 and var lagging)
        {
            // D-087: the interval is a target; say when probes (timeouts, 64 at once) cannot keep up with it
            var note = $"{lagging} sampled slower than every {Settings.Monitoring.IntervalMs / 1000.0:0.#} s";
            MonitoringTally += "  ⏱ " + lagging;
            MonitoringTallyText += "; " + note + " (ping timeout longer than the interval, or too many devices)";
        }
    }

    /// <summary>Monitor-all and history hooks for devices arriving from scans.</summary>
    private bool OnArrived(DeviceResult r) =>
        Settings.Monitoring.MonitorAll && r.Status == DeviceStatus.Online && !Monitor.IsMonitored(r.Key) && Monitor.StartAutomatic(r.Key);

    // ---------------- background scanning ----------------
    private bool _backgroundBusy;

    public async Task SetBackgroundAsync(bool on)
    {
        InitContinuous();
        if (_backgroundBusy || (on && (Ops.IsRunning || _shuttingDown))) return; // a start or stop is in progress, or the app is closing
        _backgroundBusy = true;
        try
        {
            if (on)
            {
                await Ops.StopAsync(); // waits for a session that is still being torn down
                await PersistAsync();
                Ops.Start(() => Settings, Results.Nodes.Select(n => n.Result).ToList(), new BackgroundSink(this));
                BackgroundStatus = $"Background scan: round 1 running ({Settings.Background.Mode})";
            }
            else
            {
                // Always stop: a loop that already ended by itself still owns a session until it is torn down.
                BackgroundStatus = "Stopping background scan…";
                await Ops.StopAsync();
                BackgroundStatus = "Background scan off";
            }
        }
        finally
        {
            _backgroundBusy = false;
            BackgroundRunning = Ops.IsRunning;
        }
    }

    private void OnBackgroundStopped()
    {
        if (_backgroundBusy) return; // SetBackgroundAsync reports its own stop
        BackgroundRunning = Ops.IsRunning;
        if (!Ops.IsRunning) BackgroundStatus = "Background scan ended (see Background Scan Log)";
    }

    private void OnRoundFinished(BackgroundRound r)
    {
        // LEAVE: show the device offline (cleared per the Browsing tab) with a newer revision.
        var current = Ops.Current.ToDictionary(d => d.Key);
        foreach (var e in r.Events.Where(e => e.Type == BackgroundEventType.Leave))
        {
            if (current.TryGetValue(e.Address, out var d) && Results.Find(e.Address) is { } node) OnDevice(d with { Revision = node.Result.Revision + 1 });
        }

        var next = Ops.NextRoundAt is { } t ? $" · next round {t.ToLocalTime():HH:mm:ss}" : "";
        BackgroundStatus = $"Background scan ({Settings.Background.Mode}): round {r.Number} {(r.Complete ? "done" : "incomplete")}, " +
                           $"{r.Results.Count(x => x.Status == DeviceStatus.Online)} online, {r.Events.Count} event(s){next}";
        if (Settings.History.Enabled) Results.Rebuild();
    }

    /// <summary>History after an interactive scan (only complete scans count toward availability).</summary>
    private async Task RecordInteractiveHistoryAsync(DateTimeOffset started, bool complete, TargetPlan plan, int generation)
    {
        if (!Settings.History.Enabled) return;
        InitContinuous();
        var devices = Results.Nodes.Select(n => n.Result).ToList();
        await Task.Run(() => Ops.RecordHistoryAsync(Settings, devices, started, DateTimeOffset.Now, complete, plan));
        // only onto this scan's summary: a scan started meanwhile owns the status bar (D-100)
        if (Ops.HistoryView.Newcomers.Count > 0 && generation == _scanGeneration && ScanPresentation.IsTerminal(ScanPhase)) StatusText += $" · {Ops.HistoryView.Newcomers.Count} new device(s) on {Ops.HistoryView.Network?.Name}";
        ApplyViewSettings();
    }
}
