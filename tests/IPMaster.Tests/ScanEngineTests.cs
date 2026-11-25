using System.Diagnostics;
using System.Net;
using IPMaster.Core.Scanning;

namespace IPMaster.Tests;

public class ScanEngineTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);

    private static ScanSettings Fast(int concurrency = 16) => new()
    {
        MaxConcurrency = concurrency,
        PingTimeoutMs = 50,
        PingAttempts = 1,
        DnsTimeoutMs = 200,
        DeviceDeadlineSeconds = 0,
        ShowTimestamps = true,
    };

    private static async Task<(ScanSummary Summary, ListSink Sink)> Run(FakeIcmp icmp, FakeDns dns, ScanSettings settings,
        params string[] targets)
    {
        var engine = new ScanEngine(icmp, new FakeArp(), dns);
        var sink = new ListSink();
        using var session = engine.Start(new ScanRequest { Plan = TestPlans.Plan(targets), Settings = settings }, sink);
        var summary = await session.Completion.WaitAsync(TestTimeout);
        return (summary, sink);
    }

    [Fact]
    public async Task Online_hosts_published_with_rtt_ttl_and_host_name()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        var dns = new FakeDns();
        dns.Names["10.0.0.2"] = "printer.corp.example.";
        var (summary, sink) = await Run(icmp, dns, Fast(), "10.0.0.1-10.0.0.3");

        Assert.Equal(ScanState.Completed, summary.State);
        Assert.Equal(3UL, summary.Processed);
        Assert.Equal(1UL, summary.Online);
        Assert.Equal(1, sink.Count); // inactive devices hidden by default
        var d = sink.Get("10.0.0.2");
        Assert.Equal(DeviceStatus.Online, d.Status);
        Assert.Equal(PingMethod.Icmp, d.RespondedTo);
        Assert.Equal(64, d.Ttl.Value);
        Assert.Equal("printer.corp.example", d.HostName.Value!.Name);
        Assert.True(d.IsComplete);
        Assert.NotNull(d.LastSeen);
    }

    [Fact]
    public async Task Short_host_name_mode()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        var dns = new FakeDns();
        dns.Names["10.0.0.2"] = "printer.corp.example";
        var (_, sink) = await Run(icmp, dns, Fast() with { HostNameMode = HostNameMode.ShortName }, "10.0.0.2");
        Assert.Equal("printer", sink.Get("10.0.0.2").HostName.Value!.Name);
    }

    [Fact]
    public async Task No_ptr_record_is_empty_not_failure()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        var (_, sink) = await Run(icmp, new FakeDns(), Fast(), "10.0.0.2");
        Assert.Equal(ObservationState.Empty, sink.Get("10.0.0.2").HostName.State);
    }

    [Fact]
    public async Task Display_inactive_devices_shows_offline_rows()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        var (_, sink) = await Run(icmp, new FakeDns(), Fast() with { DisplayInactiveDevices = true, ResolveHostNames = false }, "10.0.0.1-10.0.0.4");
        Assert.Equal(4, sink.Count);
        Assert.Equal(DeviceStatus.Offline, sink.Get("10.0.0.3").Status);
        Assert.Null(sink.Get("10.0.0.3").LastSeen);
        Assert.Equal(ObservationState.NotRequested, sink.Get("10.0.0.3").HostName.State);
    }

    [Fact]
    public async Task Concurrency_never_exceeds_limit()
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromMilliseconds(20) };
        var (summary, _) = await Run(icmp, new FakeDns(), Fast(concurrency: 8) with { ResolveHostNames = false }, "10.0.0.0/24");
        Assert.Equal(254UL, summary.Processed);
        Assert.InRange(icmp.Peak, 2, 8);
    }

    [Fact]
    public async Task Retries_attempts()
    {
        var icmp = new FakeIcmp();
        var (_, _) = await Run(icmp, new FakeDns(), Fast() with { PingAttempts = 3, ResolveHostNames = false }, "10.0.0.1");
        Assert.Equal(3, icmp.Calls);
    }

    [Fact]
    public async Task Slow_dns_does_not_block_liveness()
    {
        var icmp = new FakeIcmp();
        for (var i = 1; i <= 50; i++) icmp.Alive.Add($"10.0.0.{i}");
        var dns = new FakeDns { Hang = true }; // resolver never answers
        var settings = Fast(concurrency: 4) with { DnsTimeoutMs = 2000, DnsConcurrency = 2, MaxAbandonedDnsLookups = 4 };
        var engine = new ScanEngine(icmp, new FakeArp(), dns);
        var sink = new ListSink();
        var sw = Stopwatch.StartNew();
        using var session = engine.Start(new ScanRequest { Plan = TestPlans.Plan("10.0.0.1-10.0.0.50"), Settings = settings }, sink);

        // All 50 liveness results must arrive long before a single DNS timeout (2 s) elapses.
        while (sink.Count < 50 && sw.Elapsed < TimeSpan.FromSeconds(10)) await Task.Delay(10);
        Assert.Equal(50, sink.Count);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1.5), $"liveness took {sw.Elapsed}");

        var summary = await session.Completion.WaitAsync(TestTimeout);
        Assert.Equal(ScanState.Completed, summary.State);
        // Abandoned-lookup cap: once 4 lookups are stuck, the rest fail fast instead of each waiting 2 s.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"scan took {sw.Elapsed}");
        Assert.InRange(dns.Started, 1, 6);
        Assert.All(Enumerable.Range(1, 50), i => Assert.Equal(ObservationState.Timeout, sink.Get($"10.0.0.{i}").HostName.State));
    }

    [Fact]
    public async Task Pause_blocks_new_work_and_resume_continues()
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromMilliseconds(10) };
        var engine = new ScanEngine(icmp, new FakeArp(), new FakeDns());
        var sink = new ListSink();
        using var session = engine.Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.0/22"),
            Settings = Fast(concurrency: 4) with { ResolveHostNames = false },
        }, sink);

        while (session.Progress.Processed < 20) await Task.Delay(5);
        session.Pause();
        await Task.Delay(100); // let in-flight work drain
        var callsAtPause = icmp.Calls;
        await Task.Delay(300);
        Assert.Equal(ScanState.Paused, session.Progress.State);
        Assert.Equal(callsAtPause, icmp.Calls);

        session.Resume();
        var summary = await session.Completion.WaitAsync(TestTimeout);
        Assert.Equal(ScanState.Completed, summary.State);
        Assert.Equal(1022UL, summary.Processed);
    }

    [Fact]
    public async Task Cancel_stops_promptly()
    {
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromSeconds(30) }; // every probe would take 30 s
        var engine = new ScanEngine(icmp, new FakeArp(), new FakeDns());
        using var session = engine.Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.0/16"),
            Settings = Fast(concurrency: 32) with { PingTimeoutMs = 30_000 },
        }, new ListSink());

        await Task.Delay(100);
        var sw = Stopwatch.StartNew();
        session.Stop();
        var summary = await session.Completion.WaitAsync(TestTimeout);
        Assert.Equal(ScanState.Cancelled, summary.State);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"stop took {sw.Elapsed}");
        Assert.True(icmp.Calls <= 64, $"{icmp.Calls} probes started");
    }

    [Fact]
    public async Task Cancel_while_paused_completes()
    {
        var icmp = new FakeIcmp();
        var engine = new ScanEngine(icmp, new FakeArp(), new FakeDns());
        using var session = engine.Start(new ScanRequest { Plan = TestPlans.Plan("10.0.0.0/20"), Settings = Fast() }, new ListSink());
        session.Pause();
        session.Stop();
        var summary = await session.Completion.WaitAsync(TestTimeout);
        Assert.Equal(ScanState.Cancelled, summary.State);
    }

    [Fact]
    public async Task Pending_enrichment_is_finalised_on_cancel()
    {
        var icmp = new FakeIcmp();
        for (var i = 1; i <= 20; i++) icmp.Alive.Add($"10.0.0.{i}");
        var dns = new FakeDns { Delay = TimeSpan.FromSeconds(30) };
        var engine = new ScanEngine(icmp, new FakeArp(), dns);
        var sink = new ListSink();
        using var session = engine.Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.1-10.0.0.20"),
            Settings = Fast() with { DnsTimeoutMs = 60_000, DnsConcurrency = 2 },
        }, sink);
        while (sink.Count < 20) await Task.Delay(5);
        session.Stop();
        await session.Completion.WaitAsync(TestTimeout);
        Assert.All(Enumerable.Range(1, 20), i =>
        {
            var d = sink.Get($"10.0.0.{i}");
            Assert.True(d.IsComplete);
            Assert.Equal(ObservationState.Cancelled, d.HostName.State);
        });
    }

    [Fact]
    public async Task Device_deadline_marks_timeout()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        var dns = new FakeDns { Delay = TimeSpan.FromSeconds(30) };
        var (summary, sink) = await Run(icmp, dns, Fast() with { DeviceDeadlineSeconds = 1, DnsTimeoutMs = 60_000 }, "10.0.0.1");
        Assert.Equal(ScanState.Completed, summary.State);
        Assert.Equal(ObservationState.Timeout, sink.Get("10.0.0.1").HostName.State);
        Assert.True(summary.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Analyse_unresponsive_when_enabled()
    {
        var icmp = new FakeIcmp(); // nothing answers ping
        var dns = new FakeDns();
        dns.Names["10.0.0.7"] = "icmp-blocked.example";
        var (_, sink) = await Run(icmp, dns, Fast() with { AnalyseUnresponsive = true }, "10.0.0.5-10.0.0.8");
        // only the device where enrichment found something is shown (inactive devices hidden)
        Assert.Equal(1, sink.Count);
        var d = sink.Get("10.0.0.7");
        Assert.Equal(DeviceStatus.Offline, d.Status);
        Assert.Equal("icmp-blocked.example", d.HostName.Value!.Name);

        var (_, without) = await Run(new FakeIcmp(), dns, Fast(), "10.0.0.5-10.0.0.8");
        Assert.Equal(0, without.Count);
    }

    [Fact]
    public async Task Double_reverse_mismatch_reported()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        icmp.Alive.Add("10.0.0.3");
        var dns = new FakeDns();
        dns.Names["10.0.0.2"] = "good.example";
        dns.Names["10.0.0.3"] = "spoofed.example";
        dns.Forward["good.example"] = [IPAddress.Parse("10.0.0.2")];
        dns.Forward["spoofed.example"] = [IPAddress.Parse("192.0.2.1")];
        var (_, sink) = await Run(icmp, dns, Fast() with { DoubleReverseLookup = true }, "10.0.0.2-10.0.0.3");
        Assert.True(sink.Get("10.0.0.2").HostName.Value!.ForwardConfirmed);
        Assert.False(sink.Get("10.0.0.3").HostName.Value!.ForwardConfirmed);
    }

    [Fact]
    public async Task Loss_and_jitter_measured()
    {
        var replies = new Queue<int>([10, 20, -1, 10, 30]);
        var icmp = new FakeIcmp
        {
            Override = _ =>
            {
                lock (replies)
                {
                    var v = replies.Count > 0 ? replies.Dequeue() : 10;
                    return v < 0 ? new ProbeReply(ObservationState.NoResponse) : new ProbeReply(ObservationState.Success, TimeSpan.FromMilliseconds(v), 64);
                }
            },
        };
        // first reply (10) is the liveness ping; then 4 statistics probes: 20, lost, 10, 30
        var (_, sink) = await Run(icmp, new FakeDns(), Fast() with
        {
            ResolveHostNames = false,
            DeterminePacketLossAndJitter = true,
            LossProbeCount = 4,
            LossProbeIntervalMs = 0,
        }, "10.0.0.1");
        var stats = sink.Get("10.0.0.1").PingStats.Value!;
        Assert.Equal(4, stats.Sent);
        Assert.Equal(3, stats.Received);
        Assert.Equal(25.0, stats.LossPercent);
        Assert.Equal(TimeSpan.FromMilliseconds(15), stats.Jitter); // |10-20|=10, |30-10|=20 → 15
    }

    [Fact]
    public async Task Arp_outside_local_subnet_is_unsupported_without_option()
    {
        var arp = new FakeArp { Capability = CapabilityStatus.Yes("fake") };
        arp.Alive.Add("10.0.0.5");
        var engine = new ScanEngine(new FakeIcmp(), arp, new FakeDns());
        var sink = new ListSink();
        using var s = engine.Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.5"),
            Settings = Fast() with { PingMethod = PingMethodSetting.Arp, DisplayInactiveDevices = true },
        }, sink);
        await s.Completion.WaitAsync(TestTimeout);
        Assert.Equal(DeviceStatus.Unsupported, sink.Get("10.0.0.5").Status);

        var sink2 = new ListSink();
        using var s2 = engine.Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.5"),
            Settings = Fast() with { PingMethod = PingMethodSetting.Both, ResolveHostNames = false },
            LocalSubnets = [new Core.Targets.LocalSubnet(Core.Targets.AddressKey.From(IPAddress.Parse("10.0.0.1")), 24)],
        }, sink2);
        await s2.Completion.WaitAsync(TestTimeout);
        var d = sink2.Get("10.0.0.5");
        Assert.Equal(PingMethod.Arp, d.RespondedTo);
        Assert.Equal("00-11-22-33-44-55", Core.Results.Formats.Mac(d.Mac.Value!));
    }

    [Fact]
    public async Task Both_runs_icmp_and_arp_side_by_side()
    {
        // Offline host, ICMP and ARP each take 600 ms: sequential probing took 1.2 s per attempt (D-084).
        var icmp = new FakeIcmp { SilentDelay = TimeSpan.FromMilliseconds(600) };
        var arp = new FakeArp { Capability = CapabilityStatus.Yes("fake"), SilentDelay = TimeSpan.FromMilliseconds(600) };
        var engine = new ScanEngine(icmp, arp, new FakeDns());
        var sink = new ListSink();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var s = engine.Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.5"),
            Settings = Fast() with { PingMethod = PingMethodSetting.Both, ResolveHostNames = false, DisplayInactiveDevices = true },
            LocalSubnets = [new Core.Targets.LocalSubnet(Core.Targets.AddressKey.From(IPAddress.Parse("10.0.0.1")), 24)],
        }, sink);
        await s.Completion.WaitAsync(TestTimeout);
        Assert.Equal(DeviceStatus.Offline, sink.Get("10.0.0.5").Status);
        Assert.True(sw.Elapsed < TimeSpan.FromMilliseconds(1100), $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task Probe_exception_does_not_kill_scan()
    {
        var icmp = new FakeIcmp { Override = a => a.ToString() == "10.0.0.3" ? throw new InvalidOperationException("boom") : null };
        icmp.Alive.Add("10.0.0.4");
        var (summary, sink) = await Run(icmp, new FakeDns(), Fast() with { ResolveHostNames = false }, "10.0.0.1-10.0.0.5");
        Assert.Equal(ScanState.Completed, summary.State);
        Assert.Equal(5UL, summary.Processed);
        Assert.True(sink.Has("10.0.0.4"));
    }

    [Fact]
    public async Task Ipv6_scoped_address_keeps_scope()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("fe80::1%5");
        var (_, sink) = await Run(icmp, new FakeDns(), Fast() with { ResolveHostNames = false }, "fe80::1%5");
        Assert.Equal(5, sink.Get("fe80::1%5").Address.ScopeId);
    }
}

public class PingStatisticsTests
{
    [Fact]
    public void Formulas()
    {
        var s = PingStatisticsCalculator.Compute(10, [TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(7), TimeSpan.FromMilliseconds(4)]);
        Assert.Equal(70.0, s.LossPercent);
        Assert.Equal(TimeSpan.FromMilliseconds(2.5), s.Jitter);
        Assert.Equal(TimeSpan.FromTicks(TimeSpan.FromMilliseconds(16).Ticks / 3), s.AverageRoundTrip);
    }

    [Fact]
    public void Jitter_undefined_with_fewer_than_two_replies()
    {
        Assert.Null(PingStatisticsCalculator.Compute(5, [TimeSpan.FromMilliseconds(5)]).Jitter);
        var none = PingStatisticsCalculator.Compute(5, []);
        Assert.Equal(100.0, none.LossPercent);
        Assert.Null(none.AverageRoundTrip);
    }
}

public class HostNameFormatterTests
{
    [Theory]
    [InlineData("host.corp.example.", HostNameMode.Fqdn, "host.corp.example")]
    [InlineData("host.corp.example", HostNameMode.ShortName, "host")]
    [InlineData("host", HostNameMode.ShortName, "host")]
    [InlineData("10.0.0.1", HostNameMode.ShortName, "10.0.0.1")]
    public void Formats(string input, HostNameMode mode, string expected) => Assert.Equal(expected, HostNameFormatter.Format(input, mode));
}
