using IPMaster.Core.Configuration;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IPMaster.Tests;

/// <summary>Status-bar text and progress for each scan phase (D-100), without a UI.</summary>
public class ScanPresentationTests
{
    private static ScanProgress P(ScanState s, ulong total, bool exact, ulong done) => new(s, total, exact, done, 0, 3, 0, TimeSpan.FromSeconds(4));

    [Fact]
    public void Idle_and_waiting_for_confirmation_show_no_bar()
    {
        Assert.Equal(new ScanView("Ready", false, false, 0), ScanPresentation.Before(ScanPhase.Idle));
        Assert.False(ScanPresentation.Before(ScanPhase.AwaitingConfirmation).ProgressVisible);
        Assert.True(ScanPresentation.Before(ScanPhase.Preparing).Indeterminate);
    }

    [Fact]
    public void Exact_totals_show_counts_and_percent_estimated_and_unknown_totals_show_no_percent()
    {
        var exact = ScanPresentation.During(P(ScanState.Running, 254, true, 172));
        Assert.StartsWith("Scanning · 172 / 254 addresses · 68%", exact.Status, StringComparison.Ordinal);
        Assert.False(exact.Indeterminate);
        Assert.Equal(67.7, exact.Percent, 1);
        var estimate = ScanPresentation.During(P(ScanState.Running, 1000, false, 10));
        Assert.Contains("10 / ≤1,000 addresses", estimate.Status.Replace('.', ','), StringComparison.Ordinal);
        Assert.DoesNotContain("%", estimate.Status, StringComparison.Ordinal);
        Assert.True(estimate.Indeterminate);
        Assert.StartsWith("Scanning · 5 addresses", ScanPresentation.During(P(ScanState.Running, 0, false, 5)).Status, StringComparison.Ordinal);
    }

    [Fact]
    public void Paused_and_stopping_keep_the_last_percent_without_animation()
    {
        var paused = ScanPresentation.During(P(ScanState.Paused, 254, true, 172));
        Assert.StartsWith("Scan paused · 172 / 254", paused.Status, StringComparison.Ordinal);
        Assert.False(paused.Indeterminate);
        Assert.True(paused.ProgressVisible);
        Assert.Equal("Stopping scan…", ScanPresentation.During(P(ScanState.Stopping, 254, true, 172)).Status);
    }

    [Fact]
    public void Terminal_states_hide_the_bar_and_never_call_a_stopped_or_failed_scan_completed()
    {
        var done = ScanPresentation.After(new ScanSummary(ScanState.Completed, 254, 18, TimeSpan.FromSeconds(2.4), null));
        Assert.Equal("Scan completed · 254 addresses · 18 online · 2.4 s", done.Status.Replace(',', '.'));
        Assert.False(done.ProgressVisible);
        var stopped = ScanPresentation.After(new ScanSummary(ScanState.Cancelled, 172, 9, TimeSpan.FromSeconds(1), null));
        Assert.StartsWith("Scan stopped by user · 172 addresses processed", stopped.Status, StringComparison.Ordinal);
        Assert.DoesNotContain("completed", stopped.Status, StringComparison.OrdinalIgnoreCase);
        Assert.False(stopped.ProgressVisible);
        var failed = ScanPresentation.After(new ScanSummary(ScanState.Faulted, 3, 0, TimeSpan.Zero, "socket error"));
        Assert.Equal("Scan failed · socket error", failed.Status);
        Assert.False(failed.ProgressVisible);
        Assert.All(Enum.GetValues<ScanState>(), s => Assert.True(ScanPresentation.IsTerminal(ScanPresentation.FromEngine(s)) == s is ScanState.Completed or ScanState.Cancelled or ScanState.Faulted));
    }
}

/// <summary>Confirmation dialog that stays open until the test answers.</summary>
internal sealed class HeldDialogs : IDialogs
{
    public TaskCompletionSource<bool> Answer { get; } = new();

    public int Confirms;

    public Task<bool> ConfirmAsync(string title, string message)
    {
        Confirms++;
        return Answer.Task;
    }

    public Task ShowMessageAsync(string title, string message) => Task.CompletedTask;
}

/// <summary>
/// The main view model end to end (D-100) with fake ICMP/ARP/DNS and loopback targets (nothing reaches the network):
/// scan phases, duplicate starts, Stop All Monitoring and its independence from scans.
/// </summary>
[Collection("Headless UI")]
public class ScanAndMonitoringWorkflowTests
{
    private static readonly TimeSpan Cap = TimeSpan.FromSeconds(60);

    private static MainWindowViewModel NewVm(FakeIcmp icmp, Action<AppSettings>? configure = null)
    {
        var previous = Environment.GetEnvironmentVariable("IPMASTER_CONFIG_DIR");
        Environment.SetEnvironmentVariable("IPMASTER_CONFIG_DIR", Path.Combine(Path.GetTempPath(), "ipmaster-workflow-" + Guid.NewGuid().ToString("N")));
        try
        {
            var vm = new ServiceCollection().AddLogging(b => b.SetMinimumLevel(LogLevel.Warning)).AddIPMaster()
                .AddSingleton<IIcmpProbe>(icmp).AddSingleton<IArpProbe>(new FakeArp()).AddSingleton<IHostNameResolver>(new FakeDns())
                .AddSingleton<MainWindowViewModel>().BuildServiceProvider().GetRequiredService<MainWindowViewModel>();
            vm.Settings.Monitoring.IntervalMs = 200;
            vm.Settings.Monitoring.PingTimeoutMs = 300;
            vm.Settings.Scan.PingTimeoutMs = 300;
            configure?.Invoke(vm.Settings);
            vm.InitContinuous();
            return vm;
        }
        finally
        {
            Environment.SetEnvironmentVariable("IPMASTER_CONFIG_DIR", previous);
        }
    }

    private static FakeIcmp Alive(int count)
    {
        var icmp = new FakeIcmp();
        for (var i = 1; i <= count; i++) icmp.Alive.Add($"127.0.0.{i}");
        return icmp;
    }

    private static void Range(MainWindowViewModel vm, string target) => vm.SetRanges([RangeEntryViewModel.From(new RangeEntry { Target = target })], append: false);

    private static async Task Until(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow + Cap;
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException(what);
            await Task.Delay(20);
        }
    }

    [Fact]
    public Task A_completed_scan_hides_the_bar_resets_workers_and_says_completed() => HeadlessUi.RunAsync(async () =>
    {
        var vm = NewVm(Alive(5));
        Assert.Equal(ScanPhase.Idle, vm.ScanPhase);
        Assert.False(vm.ProgressVisible);
        Range(vm, "127.0.0.1-127.0.0.8");
        await vm.StartStopCommand.ExecuteAsync(null).WaitAsync(Cap);
        Assert.Equal(ScanPhase.Completed, vm.ScanPhase);
        Assert.False(vm.ProgressVisible);
        Assert.False(vm.IsScanning);
        Assert.Equal("Workers 0", vm.WorkersText);
        Assert.StartsWith("Scan completed · 8 addresses · 5 online", vm.StatusText, StringComparison.Ordinal);
        Assert.True(vm.StartStopCommand.CanExecute(null));
        await Task.Delay(400); // queued timer ticks must not bring the bar back
        Assert.False(vm.ProgressVisible);
        Assert.Equal(ScanPhase.Completed, vm.ScanPhase);

        // a second scan starts from a clean bar and ends the same way
        var second = vm.StartStopCommand.ExecuteAsync(null);
        await Until(() => vm.ScanPhase is ScanPhase.Scanning or ScanPhase.Completed, "second scan running");
        await second.WaitAsync(Cap);
        Assert.Equal(ScanPhase.Completed, vm.ScanPhase);
        Assert.False(vm.ProgressVisible);
        await vm.ShutdownAsync(null);
    });

    [Fact]
    public Task A_stopped_scan_is_not_shown_as_completed() => HeadlessUi.RunAsync(async () =>
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromSeconds(1) }; // every address waits: the scan is still running when stopped
        var vm = NewVm(icmp);
        Range(vm, "127.0.0.1-127.0.3.254");
        var run = vm.StartStopCommand.ExecuteAsync(null);
        await Until(() => vm.ScanPhase == ScanPhase.Scanning && vm.ProgressVisible, "scanning");
        Assert.Equal("Stop", vm.StartButtonText);
        Assert.True(vm.StartStopCommand.CanExecute(null)); // the Stop button and Ctrl+Enter must be usable while scanning
        await vm.StartStopCommand.ExecuteAsync(null); // Stop
        await run.WaitAsync(Cap);
        Assert.Equal(ScanPhase.Stopped, vm.ScanPhase);
        Assert.StartsWith("Scan stopped by user", vm.StatusText, StringComparison.Ordinal);
        Assert.False(vm.ProgressVisible);
        Assert.Equal("Workers 0", vm.WorkersText);
        await vm.ShutdownAsync(null);
    });

    [Fact]
    public Task No_second_scan_while_the_large_scan_confirmation_is_open() => HeadlessUi.RunAsync(async () =>
    {
        var vm = NewVm(Alive(2), s => s.ConfirmationThreshold = 4);
        var dialogs = new HeldDialogs();
        vm.Dialogs = dialogs;
        Range(vm, "127.0.0.1-127.0.0.10");
        var run = vm.StartStopCommand.ExecuteAsync(null);
        await Until(() => vm.ScanPhase == ScanPhase.AwaitingConfirmation, "confirmation shown");
        Assert.False(vm.ProgressVisible);
        Assert.Equal("Waiting for scan confirmation", vm.StatusText);
        Assert.False(vm.StartStopCommand.CanExecute(null));
        await vm.RescanAsync(RescanMode.Both); // ignored while preparing
        Assert.Equal(1, dialogs.Confirms);
        dialogs.Answer.SetResult(false);
        await run.WaitAsync(Cap);
        Assert.Equal(ScanPhase.Idle, vm.ScanPhase);
        Assert.Equal("Scan not started (large scan cancelled).", vm.StatusText);
        Assert.True(vm.StartStopCommand.CanExecute(null));
        await vm.ShutdownAsync(null);
    });

    [Fact]
    public Task Stop_all_monitoring_stops_every_device_keeps_history_and_monitor_all_does_not_restart_it() => HeadlessUi.RunAsync(async () =>
    {
        var vm = NewVm(Alive(4), s => s.Monitoring.MonitorAll = true);
        Assert.False(vm.StopAllMonitoringCommand.CanExecute(null)); // nothing monitored yet
        Range(vm, "127.0.0.1-127.0.0.6");
        await vm.StartStopCommand.ExecuteAsync(null).WaitAsync(Cap);
        await Until(() => vm.Monitor.Active.Count == 4, "monitor all enrolled the online devices");
        Assert.Equal(MonitoringPhase.Running, vm.MonitoringState);
        Assert.Equal("Monitoring: Running · 4 devices", vm.MonitoringStatus);
        Assert.True(vm.StopAllMonitoringCommand.CanExecute(null));
        var key = AddressKey.From(System.Net.IPAddress.Parse("127.0.0.1"));
        await Until(() => vm.Monitor.Series(key)?.Count > 0, "samples recorded");

        await vm.StopAllMonitoringCommand.ExecuteAsync(null).WaitAsync(Cap);
        Assert.Empty(vm.Monitor.Active);
        Assert.Equal(MonitoringPhase.Stopped, vm.MonitoringState);
        Assert.True(vm.AutomaticMonitoringSuppressed);
        Assert.StartsWith("Monitoring: Stopped · 0 active devices", vm.MonitoringStatus, StringComparison.Ordinal);
        Assert.False(vm.StopAllMonitoringCommand.CanExecute(null));
        Assert.NotNull(vm.Monitor.Series(key)); // history kept
        Assert.Equal(4, vm.Results.Count); // scan results untouched (online devices are listed)

        await vm.StartStopCommand.ExecuteAsync(null).WaitAsync(Cap); // later results do not re-enrol anything
        await Task.Delay(400);
        Assert.Empty(vm.Monitor.Active);

        vm.StartMonitoring([vm.Results.Nodes.First().Result]); // a manual start still works
        Assert.Equal(MonitoringPhase.Running, vm.MonitoringState);
        vm.ResumeAutomaticMonitoringCommand.Execute(null);
        Assert.Equal(4, vm.Monitor.Active.Count);
        Assert.False(vm.AutomaticMonitoringSuppressed);
        await vm.ShutdownAsync(null);
    });

    [Fact]
    public Task Pause_and_resume_all_keep_the_devices() => HeadlessUi.RunAsync(async () =>
    {
        var vm = NewVm(Alive(2));
        Range(vm, "127.0.0.1-127.0.0.2");
        await vm.StartStopCommand.ExecuteAsync(null).WaitAsync(Cap);
        vm.StartMonitoring(vm.Results.Nodes.Select(n => n.Result));
        Assert.True(vm.PauseAllMonitoringCommand.CanExecute(null));
        vm.PauseAllMonitoringCommand.Execute(null);
        Assert.Equal(MonitoringPhase.Paused, vm.MonitoringState);
        Assert.Equal("Monitoring: Paused · 2 devices", vm.MonitoringStatus);
        Assert.True(vm.ResumeAllMonitoringCommand.CanExecute(null));
        Assert.Equal(2, vm.Monitor.Active.Count);
        vm.ResumeAllMonitoringCommand.Execute(null);
        Assert.Equal(MonitoringPhase.Running, vm.MonitoringState);
        await vm.StopAllMonitoringCommand.ExecuteAsync(null).WaitAsync(Cap);
        Assert.Equal(MonitoringPhase.Stopped, vm.MonitoringState);
        await vm.ShutdownAsync(null);
    });

    [Fact]
    public Task Stop_all_during_an_interactive_scan_and_a_background_scan_leaves_both_running() => HeadlessUi.RunAsync(async () =>
    {
        var icmp = Alive(3);
        icmp.SilentDelay = TimeSpan.FromMilliseconds(300);
        var vm = NewVm(icmp);
        Range(vm, "127.0.0.1-127.0.0.3");
        await vm.StartStopCommand.ExecuteAsync(null).WaitAsync(Cap);
        vm.StartMonitoring(vm.Results.Nodes.Select(n => n.Result));
        await vm.SetBackgroundAsync(true);
        Assert.True(vm.BackgroundRunning);
        Range(vm, "127.0.0.1-127.0.0.60");
        var run = vm.StartStopCommand.ExecuteAsync(null);
        await Until(() => vm.ScanPhase == ScanPhase.Scanning, "interactive scan running");
        await vm.StopAllMonitoringCommand.ExecuteAsync(null).WaitAsync(Cap);
        Assert.Empty(vm.Monitor.Active);
        Assert.Equal(ScanPhase.Scanning, vm.ScanPhase); // the interactive scan keeps going
        Assert.True(vm.ProgressVisible);
        Assert.True(vm.BackgroundRunning); // and so does the background scan
        await run.WaitAsync(Cap);
        Assert.Equal(ScanPhase.Completed, vm.ScanPhase);
        Assert.Equal(MonitoringPhase.Stopped, vm.MonitoringState); // a finished scan does not touch monitoring
        await vm.SetBackgroundAsync(false);
        await vm.ShutdownAsync(null);
    });
}
