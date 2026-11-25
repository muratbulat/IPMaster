using System.Net;
using IPMaster.Core.Configuration;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Network;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure;
using IPMaster.Infrastructure.Monitoring;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Tests;

/// <summary>Start/stop lifecycle of background scanning and live monitoring (D-081).</summary>
public class MonitoringLifecycleTests
{
    private static readonly TimeSpan Cap = TimeSpan.FromSeconds(30);

    private static AppSettings Settings(params string[] ranges) => new()
    {
        Scan = new ScanSettings { PingTimeoutMs = 50, PingAttempts = 1, ResolveHostNames = false },
        Background = new BackgroundSettings { RoundDelayMinutes = 0 },
        Ranges = ranges.Select(r => new RangeEntry { Target = r }).ToList(),
    };

    private static ContinuousOperations Ops(FakeIcmp icmp)
    {
        var services = new ServiceCollection().AddIPMaster(Directory.CreateTempSubdirectory("ipm-life-").FullName);
        services.AddSingleton(new ScanProbes(icmp, new FakeArp(), new FakeDns()));
        services.AddSingleton<INetworkAdapterProvider>(new FakeAdapters());
        return services.BuildServiceProvider().GetRequiredService<ContinuousOperations>();
    }

    private static Task LogLine(ContinuousOperations ops, string text)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Check()
        {
            if (ops.Log.Items.Any(i => i.Text.Contains(text, StringComparison.Ordinal))) tcs.TrySetResult();
        }

        ops.Log.Changed += (_, _) => Check();
        Check();
        return tcs.Task.WaitAsync(Cap);
    }

    [Fact]
    public async Task Loop_that_ends_by_itself_releases_the_session_and_reports_stopped()
    {
        // No ranges: the round cannot start, so the loop ends without a Stop request.
        using var ops = Ops(new FakeIcmp());
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ops.Stopped += (_, _) => stopped.TrySetResult();
        ops.Start(() => Settings(), null, null);
        await stopped.Task.WaitAsync(Cap);
        Assert.False(ops.IsRunning);
        Assert.Contains(ops.Log.Items, i => i.Text == "Background scanning stopped.");
        await ops.StopAsync(); // nothing left to stop
    }

    [Fact]
    public async Task Faulted_loop_is_logged_cleaned_up_and_stop_does_not_throw()
    {
        using var ops = Ops(new FakeIcmp());
        var calls = 0;
        var s = Settings("10.0.0.1");
        ops.Start(() => Interlocked.Increment(ref calls) > 1 ? throw new InvalidOperationException("settings unavailable") : s, null, null);
        await LogLine(ops, "Background scanning stopped.");
        Assert.Contains(ops.Log.Items, i => i.Text.Contains("Background scanning failed: settings unavailable", StringComparison.Ordinal));
        Assert.False(ops.IsRunning);
        await ops.StopAsync();
    }

    [Fact]
    public async Task Concurrent_stops_are_safe_and_restart_cycles_start_one_fresh_session_each()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        using var ops = Ops(icmp);
        var s = Settings("10.0.0.1-10.0.0.2");
        for (var cycle = 1; cycle <= 5; cycle++)
        {
            var round = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            void OnRound(object? sender, BackgroundRound r) => round.TrySetResult();
            ops.RoundFinished += OnRound;
            ops.Start(() => s, null, null);
            ops.Start(() => s, null, null); // duplicate start while running: ignored
            await round.Task.WaitAsync(Cap);
            ops.RoundFinished -= OnRound;
            await Task.WhenAll(ops.StopAsync(), ops.StopAsync(), ops.StopAsync()).WaitAsync(Cap);
            Assert.False(ops.IsRunning);
            Assert.Equal(0, ops.Round);
        }

        Assert.Equal(5, ops.Log.Items.Count(i => i.Text.StartsWith("Background scanning started", StringComparison.Ordinal)));
        Assert.Equal(5, ops.Log.Items.Count(i => i.Text == "Background scanning stopped."));
    }

    [Fact]
    public async Task Start_right_after_stop_waits_for_nothing_and_runs_normally()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        using var ops = Ops(icmp);
        var s = Settings("10.0.0.1");
        ops.Start(() => s, null, null);
        var stopping = ops.StopAsync();
        if (!stopping.IsCompleted)
        {
            ops.Start(() => s, null, null); // while the previous session is still tearing down: refused, not mixed in
            await stopping.WaitAsync(Cap);
            Assert.False(ops.IsRunning);
        }

        var round = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ops.RoundFinished += (_, _) => round.TrySetResult();
        ops.Start(() => s, null, null);
        await round.Task.WaitAsync(Cap);
        Assert.True(ops.IsRunning);
        await ops.StopAsync().WaitAsync(Cap);
    }

    [Fact]
    public async Task Silent_device_does_not_slow_sampling_of_the_others()
    {
        // D-087: one silent device whose probe takes 1 s must not stretch a 200 ms interval for a responsive one.
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromSeconds(1) };
        icmp.Alive.Add("10.0.0.1");
        using var m = new LiveMonitor(icmp) { Settings = new MonitoringSettings { IntervalMs = 200, PingTimeoutMs = 1000 } };
        var fast = AddressKey.From(IPAddress.Parse("10.0.0.1"));
        var silent = AddressKey.From(IPAddress.Parse("10.0.0.2"));
        m.Start(fast);
        m.Start(silent);
        await Task.Delay(1500, TestContext.Current.CancellationToken);
        await m.StopAsync().WaitAsync(Cap);
        Assert.True(m.Series(fast)!.Count >= 5, $"responsive device sampled {m.Series(fast)!.Count}x in 1.5 s");
        Assert.InRange(m.Series(silent)!.Count, 1, 2);
    }

    [Fact]
    public async Task Stop_async_waits_for_running_probes_and_allows_a_restart()
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromMilliseconds(300) };
        using var m = new LiveMonitor(icmp) { Settings = new MonitoringSettings { IntervalMs = 200, PingTimeoutMs = 300 } };
        var a = AddressKey.From(IPAddress.Parse("10.0.0.3"));
        m.Start(a);
        await Task.Delay(100, TestContext.Current.CancellationToken); // a probe is running
        await m.StopAsync().WaitAsync(Cap);
        Assert.Equal(0, icmp.Current); // stopped means no probe is left running
        var count = m.Series(a)!.Count;
        await Task.Delay(500, TestContext.Current.CancellationToken);
        Assert.Equal(count, m.Series(a)!.Count);
        Assert.False(m.IsMonitored(a));

        var sampled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        m.Updated += (_, _) => sampled.TrySetResult();
        Assert.True(m.Start(a));
        await sampled.Task.WaitAsync(Cap); // the loop runs again after a stop
    }

    [Fact]
    public async Task Devices_sampled_slower_than_the_interval_are_reported_as_lagging()
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromMilliseconds(700) };
        using var m = new LiveMonitor(icmp) { Settings = new MonitoringSettings { IntervalMs = 200, PingTimeoutMs = 700 } };
        m.Start(AddressKey.From(IPAddress.Parse("10.0.0.4")));
        await Task.Delay(1800, TestContext.Current.CancellationToken);
        Assert.Equal(1, m.LaggingCount());
        await m.StopAsync().WaitAsync(Cap);
    }

    [Fact]
    public void Monitor_all_does_not_restart_a_device_the_user_stopped()
    {
        using var m = new LiveMonitor(new FakeIcmp());
        var a = AddressKey.From(IPAddress.Parse("10.0.0.8"));
        Assert.True(m.StartAutomatic(a));
        m.Stop(a);
        Assert.False(m.StartAutomatic(a)); // next scan with Monitor All on
        Assert.False(m.IsMonitored(a));
        Assert.True(m.Start(a)); // a manual start undoes the stop
        m.Stop(a);
        m.Forget(a); // results cleared: the address starts fresh
        Assert.True(m.StartAutomatic(a));
    }

    [Fact]
    public async Task Unsupported_probe_reply_is_not_packet_loss()
    {
        var icmp = new FakeIcmp { Override = _ => new ProbeReply(ObservationState.Unsupported, Detail: "no ICMP privilege") };
        using var m = new LiveMonitor(icmp) { Settings = new MonitoringSettings { IntervalMs = 200, PingTimeoutMs = 100 } };
        var round = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        m.Updated += (_, _) => round.TrySetResult();
        var a = AddressKey.From(IPAddress.Parse("10.0.0.7"));
        m.Start(a);
        await round.Task.WaitAsync(Cap);
        Assert.Equal(0, m.Series(a)!.Count);
        Assert.Equal("no ICMP privilege", m.Series(a)!.LastError);
    }

    [Fact]
    public async Task Live_monitor_survives_an_unexpected_probe_failure()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        icmp.Override = ip => ip.ToString() == "10.0.0.2" ? throw new NotSupportedException("probe broke") : null;
        using var m = new LiveMonitor(icmp) { Settings = new MonitoringSettings { IntervalMs = 200, PingTimeoutMs = 100 } };
        var rounds = 0;
        var three = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        m.Updated += (_, _) =>
        {
            if (Interlocked.Increment(ref rounds) == 3) three.TrySetResult();
        };
        var a = AddressKey.From(IPAddress.Parse("10.0.0.1"));
        var b = AddressKey.From(IPAddress.Parse("10.0.0.2"));
        m.Start(a);
        m.Start(b);
        await three.Task.WaitAsync(Cap);
        Assert.True(m.Series(a)!.Count >= 3);
        // a local probe failure is neither a dead loop nor packet loss: it is counted apart with its reason
        Assert.Equal(0, m.Series(b)!.Count);
        Assert.True(m.Series(b)!.ProbeErrors >= 3);
        Assert.Equal("probe broke", m.Series(b)!.LastError);
    }
}
