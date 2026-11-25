using System.Net;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Targets;

namespace IPMaster.Tests;

/// <summary>Stop All, Pause and Resume of live monitoring (D-100), on the engine with a fake ICMP probe.</summary>
public class StopAllMonitoringTests
{
    private static readonly TimeSpan Cap = TimeSpan.FromSeconds(30);

    private static AddressKey Key(int i) => AddressKey.From(IPAddress.Parse($"10.1.0.{i}"));

    private static LiveMonitor Monitor(FakeIcmp icmp) => new(icmp) { Settings = new MonitoringSettings { IntervalMs = 200, PingTimeoutMs = 300 } };

    [Fact]
    public async Task Stop_all_with_no_devices_completes_and_suppresses_automatic_enrolment()
    {
        using var m = Monitor(new FakeIcmp());
        await m.StopAllAsync().WaitAsync(Cap);
        Assert.Empty(m.Active);
        Assert.True(m.AutomaticSuppressed);
        Assert.False(m.StartAutomatic(Key(1)));
    }

    [Fact]
    public async Task Stop_all_during_running_probes_leaves_no_probe_and_keeps_history()
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromMilliseconds(250) };
        for (var i = 1; i <= 40; i++) icmp.Alive.Add($"10.1.0.{i}");
        using var m = Monitor(icmp);
        for (var i = 1; i <= 80; i++) Assert.True(m.Start(Key(i))); // half answer, half are silent (probes in flight)
        await Task.Delay(600, TestContext.Current.CancellationToken);
        await m.StopAllAsync().WaitAsync(Cap);
        Assert.Equal(0, icmp.Current); // no orphaned probe
        Assert.Empty(m.Active);
        var calls = icmp.Calls;
        var samples = m.Series(Key(1))!.Count;
        Assert.True(samples > 0);
        await Task.Delay(600, TestContext.Current.CancellationToken);
        Assert.Equal(calls, icmp.Calls); // nothing is probed afterwards
        Assert.Equal(samples, m.Series(Key(1))!.Count); // history kept
    }

    [Fact]
    public async Task Repeated_and_concurrent_stop_all_is_safe()
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromMilliseconds(200) };
        using var m = Monitor(icmp);
        m.Start(Key(1));
        m.Start(Key(2));
        await Task.Delay(100, TestContext.Current.CancellationToken);
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => m.StopAllAsync())).WaitAsync(Cap);
        await m.StopAllAsync().WaitAsync(Cap);
        Assert.Equal(0, icmp.Current);
        Assert.Empty(m.Active);
    }

    [Fact]
    public async Task Start_while_stop_all_finishes_runs_normally_and_manual_start_still_works()
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromMilliseconds(250) };
        icmp.Alive.Add("10.1.0.9");
        using var m = Monitor(icmp);
        m.Start(Key(1));
        await Task.Delay(100, TestContext.Current.CancellationToken);
        var stopping = m.StopAllAsync();
        Assert.True(m.Start(Key(9))); // a manual start is allowed while the stop finishes
        await stopping.WaitAsync(Cap);
        var sampled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        m.Updated += (_, keys) =>
        {
            if (keys.Contains(Key(9))) sampled.TrySetResult();
        };
        await sampled.Task.WaitAsync(Cap);
        Assert.True(m.IsMonitored(Key(9)));
        Assert.False(m.StartAutomatic(Key(2))); // automatic enrolment stays stopped
        await m.StopAsync().WaitAsync(Cap);
    }

    [Fact]
    public async Task Resume_automatic_lets_monitor_all_enrol_again()
    {
        using var m = Monitor(new FakeIcmp());
        m.StartAutomatic(Key(1));
        await m.StopAllAsync().WaitAsync(Cap);
        Assert.False(m.StartAutomatic(Key(1)));
        m.ResumeAutomatic();
        Assert.False(m.AutomaticSuppressed);
        Assert.True(m.StartAutomatic(Key(1)));
        await m.StopAsync().WaitAsync(Cap);
    }

    [Fact]
    public async Task Pause_sends_no_probes_keeps_devices_and_resume_continues()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.1.0.1");
        using var m = Monitor(icmp);
        m.Start(Key(1));
        await Task.Delay(500, TestContext.Current.CancellationToken);
        m.Pause();
        await Task.Delay(300, TestContext.Current.CancellationToken); // let a probe already sent finish
        var calls = icmp.Calls;
        await Task.Delay(700, TestContext.Current.CancellationToken);
        Assert.Equal(calls, icmp.Calls);
        Assert.True(m.IsMonitored(Key(1)));
        Assert.True(m.IsPaused);
        m.Resume();
        await Task.Delay(700, TestContext.Current.CancellationToken);
        Assert.True(icmp.Calls > calls);
        await m.StopAllAsync().WaitAsync(Cap);
        Assert.False(m.IsPaused); // stop all ends a pause too
    }
}

/// <summary>Found while timing the D-100 workflow tests: a missing settings folder made every save wait ~5 s and fail.</summary>
public class SettingsFolderTests
{
    [Fact]
    public async Task Shared_save_creates_a_missing_settings_folder_without_waiting()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ipmaster-newprofile-" + Guid.NewGuid().ToString("N"), "IPMaster");
        try
        {
            var store = new IPMaster.Infrastructure.Configuration.SettingsStore(dir);
            store.Load();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await store.SaveSharedAsync(new IPMaster.Core.Configuration.AppSettings(), TestContext.Current.CancellationToken);
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"save took {sw.Elapsed.TotalSeconds:0.0} s");
            Assert.True(File.Exists(Path.Combine(dir, IPMaster.Infrastructure.Configuration.SettingsStore.FileName)));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(dir)!, recursive: true);
        }
    }
}
