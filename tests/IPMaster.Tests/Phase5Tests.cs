using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using IPMaster.Cli;
using IPMaster.Core.Configuration;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure;
using IPMaster.Infrastructure.Configuration;
using IPMaster.Infrastructure.Monitoring;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Tests;

public class MonitoringTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 16, 12, 0, 0, TimeSpan.Zero);

    private static List<MonitorSample> Seq(params double?[] rtts) => rtts.Select((r, i) => new MonitorSample(T0.AddSeconds(i), r)).ToList();

    [Fact]
    public void Ring_buffer_keeps_the_newest_samples_in_order()
    {
        var s = new MonitorSeries(4);
        for (var i = 1; i <= 6; i++) s.Add(new MonitorSample(T0.AddSeconds(i), i));
        Assert.Equal(4, s.Count);
        Assert.Equal([3.0, 4, 5, 6], s.Last(10).Select(x => x.RttMs!.Value));
        Assert.Equal([5.0, 6], s.Last(2).Select(x => x.RttMs!.Value));
        Assert.Equal(2, s.Since(T0.AddSeconds(5)).Count);
        Assert.Equal(3600, new MonitorSeries().Capacity);
    }

    [Fact]
    public void Metric_formulas_and_quality()
    {
        var cfg = new MonitoringSettings { GoodLatencyMs = 50, CriticalLatencyMs = 200, GoodLossPercent = 1, CriticalLossPercent = 10, DownAfterLost = 3 };
        var good = MonitorMetrics.Compute(Seq(10, 12, 11, 15), cfg);
        Assert.Equal(15, good.LatencyMs);
        Assert.Equal(0, good.LossPercent);
        Assert.Equal((2 + 1 + 4) / 3.0, good.JitterMs!.Value, 6); // mean |Δ| of consecutive received samples
        Assert.Equal(LinkQuality.Good, good.Quality);

        var lossy = MonitorMetrics.Compute(Seq(10, null, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10), cfg);
        Assert.Equal(5, lossy.LossPercent);
        Assert.Equal(LinkQuality.Degraded, lossy.Quality); // 1 % < 5 % < 10 %
        Assert.Equal(0, lossy.JitterMs); // pairs across the lost sample are skipped

        Assert.Equal(LinkQuality.Critical, MonitorMetrics.Compute(Seq(10, 300), cfg).Quality);
        Assert.Equal(LinkQuality.Degraded, MonitorMetrics.Compute(Seq(10, 120), cfg).Quality);
        var down = MonitorMetrics.Compute(Seq(Enumerable.Repeat<double?>(10, 97).Concat([null, null, null]).ToArray()), cfg);
        Assert.Equal(3, down.LossPercent);
        Assert.Equal(LinkQuality.Critical, down.Quality); // 3 consecutive losses = down
        Assert.Null(down.LatencyMs);
        Assert.Equal(LinkQuality.Unknown, MonitorMetrics.Compute([], cfg).Quality);
    }

    [Fact]
    public async Task Live_monitor_samples_monitored_addresses_only()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        using var m = new LiveMonitor(icmp) { Settings = new MonitoringSettings { IntervalMs = 200, PingTimeoutMs = 100 } };
        var a = AddressKey.From(IPAddress.Parse("10.0.0.1"));
        var b = AddressKey.From(IPAddress.Parse("10.0.0.2"));
        Assert.True(m.Start(a));
        Assert.True(m.Start(b));
        await Task.Delay(1100);
        m.Stop(b);
        var countB = m.Series(b)!.Count;
        await Task.Delay(500);
        Assert.True(m.Series(a)!.Count >= 3);
        Assert.InRange(m.Series(b)!.Count, countB, countB + 1); // stopped: at most the in-flight ping lands; history kept (MON-05)
        Assert.Equal(100, m.Snapshot(b)!.LossPercent);
        Assert.Equal(LinkQuality.Good, m.Snapshot(a)!.Quality);
        Assert.False(m.IsMonitored(b));

        var cols = MonitorColumns.For(m).ToList();
        Assert.Equal(["Latency", "History", "Loss", "Jitter", "Quality"], cols.Select(c => c.Header));
        var d = Samples.Device("10.0.0.1");
        Assert.Contains("Good", cols[4].Text(d), StringComparison.Ordinal);
        Assert.Equal("", cols[0].Text(Samples.Device("10.0.0.9")));

        using var limited = new LiveMonitor(icmp) { Settings = new MonitoringSettings { MaxDevices = 1 } };
        Assert.True(limited.Start(a));
        Assert.False(limited.Start(b));
    }
}

public class ChangeDetectorTests
{
    private static readonly DateTimeOffset T = new(2026, 11, 16, 12, 0, 0, TimeSpan.Zero);

    private static DeviceResult Online(string ip, string? mac = null) => Samples.Device(ip) with
    {
        Status = DeviceStatus.Online,
        Mac = mac is null ? Observation<PhysicalAddress>.Of(ObservationState.Empty, T) : Observation<PhysicalAddress>.Ok(PhysicalAddress.Parse(mac), T),
    };

    [Fact]
    public void Baseline_join_debounced_leave_new_mac_and_ip_change()
    {
        var d = new ChangeDetector(leaveAfterMisses: 2);
        static bool All(AddressKey _) => true;
        Assert.Empty(d.ApplyRound([Online("10.0.0.1", "00-00-00-00-00-01"), Online("10.0.0.2", "00-00-00-00-00-02")], All, true, T)); // baseline
        var r2 = d.ApplyRound([Online("10.0.0.1", "00-00-00-00-00-01"), Online("10.0.0.3", "00-00-00-00-00-03")], All, true, T);
        Assert.Equal([BackgroundEventType.Join, BackgroundEventType.NewMac], r2.Select(e => e.Type)); // .2 missed once: no LEAVE yet
        var r3 = d.ApplyRound([Online("10.0.0.1", "00-00-00-00-00-01"), Online("10.0.0.3", "00-00-00-00-00-03")], All, false, T);
        Assert.Empty(r3); // incomplete round: misses are not counted
        var r4 = d.ApplyRound([Online("10.0.0.1", "00-00-00-00-00-01"), Online("10.0.0.3", "00-00-00-00-00-03")], All, true, T);
        var leave = Assert.Single(r4);
        Assert.Equal(BackgroundEventType.Leave, leave.Type);
        Assert.Equal("10.0.0.2", leave.Address.ToString());
        var r5 = d.ApplyRound([Online("10.0.0.1", "00-00-00-00-00-01"), Online("10.0.0.3", "00-00-00-00-00-03"), Online("10.0.0.9", "00-00-00-00-00-02")], All, true, T);
        Assert.Equal([BackgroundEventType.Join, BackgroundEventType.IpChange], r5.Select(e => e.Type));
        Assert.Contains("moved from 10.0.0.2 to 10.0.0.9", r5[1].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Leave_of_a_seeded_device_keeps_its_mac()
    {
        var d = new ChangeDetector(1);
        d.Seed([Online("10.0.0.2", "00-00-00-00-00-02")]);
        var offline = Samples.Device("10.0.0.2") with { Status = DeviceStatus.Offline }; // offline results carry no MAC
        var leave = Assert.Single(d.ApplyRound([offline], _ => true, true, T));
        Assert.Equal(BackgroundEventType.Leave, leave.Type);
        Assert.Equal(PhysicalAddress.Parse("00-00-00-00-00-02"), leave.Mac);
    }

    [Fact]
    public void Ineligible_addresses_never_leave_and_seed_sets_baseline()
    {
        var d = new ChangeDetector(1);
        d.Seed([Online("10.0.0.1"), Online("10.0.0.2")]);
        Assert.True(d.HasBaseline);
        var r = d.ApplyRound([Online("10.0.0.1")], k => k.ToString() == "10.0.0.1", true, T); // .2 not covered by this round
        Assert.Empty(r);
        var r2 = d.ApplyRound([Online("10.0.0.5")], _ => true, true, T);
        Assert.Equal(3, r2.Count); // JOIN .5, LEAVE .1, LEAVE .2
    }

    [Fact]
    public void Clearing_offline_keeps_identity_and_selected_fields()
    {
        var full = RichSamples.Full("10.0.0.2");
        var cleared = OfflineClearer.Clear(full, ["hostName"]);
        Assert.Equal(full.Key, cleared.Key);
        Assert.Equal(full.Mac, cleared.Mac);
        Assert.Equal(full.RoundTrip, cleared.RoundTrip);
        Assert.Equal(full.HostName, cleared.HostName);
        Assert.Equal(ObservationState.NotRequested, cleared.Shares.State);
        Assert.Equal(ObservationState.NotRequested, cleared.Workgroup.State);

        var e = new BackgroundEvent(BackgroundEventType.Leave, T, full.Key, null, "gone", full);
        Assert.Equal($"notify LEAVE {full.Key} [nope]", OfflineClearer.Expand("notify [event] [IP Address] [nope]", e, ColumnCatalog.All, ColumnFormat.Default));
    }
}

public class HistoryTests
{
    private static readonly NetworkIdentity Net = new("gateway-mac:BC:24:11:EB:C4:2D", "Lab");
    private static readonly DateTimeOffset T = new(2026, 11, 16, 12, 0, 0, TimeSpan.Zero);

    private static DeviceResult Dev(string ip, string? mac, double rtt = 1) => Samples.Device(ip) with
    {
        Status = DeviceStatus.Online,
        RoundTrip = TimeSpan.FromMilliseconds(rtt),
        LastSeen = T,
        Mac = mac is null ? Observation<PhysicalAddress>.Of(ObservationState.Empty, T) : Observation<PhysicalAddress>.Ok(PhysicalAddress.Parse(mac), T),
    };

    private static NetworkIdentity ByMac(string mac) => new("gateway-mac:" + mac, "Lab") { Gateway = "gateway:10.0.0.254" };

    private static readonly NetworkIdentity ByAddress = new("gateway:10.0.0.254", "Lab") { Gateway = "gateway:10.0.0.254" };

    [Fact]
    public void Gateway_mac_missing_for_one_session_keeps_one_network()
    {
        // D-088: the neighbour cache lacked the gateway once; the LAN must not split into two history networks
        var store = new HistoryStore(Directory.CreateTempSubdirectory("ipm-hist-").FullName);
        store.RecordSession(ByMac("AA"), T, T, true, [Dev("10.0.0.1", "00-00-00-00-00-01")], _ => true);
        store.RecordSession(ByAddress, T.AddMinutes(10), T.AddMinutes(10), true, [Dev("10.0.0.1", "00-00-00-00-00-01")], _ => true);
        Assert.Single(store.Networks());
        Assert.Equal((2, 2), (store.Devices(ByAddress)["00:00:00:00:00:01"].Eligible, store.Devices(ByMac("AA"))["00:00:00:00:00:01"].Online));
    }

    [Fact]
    public void Gateway_mac_learned_later_adopts_the_address_network()
    {
        var store = new HistoryStore(Directory.CreateTempSubdirectory("ipm-hist-").FullName);
        store.RecordSession(ByAddress, T, T, true, [Dev("10.0.0.1", "00-00-00-00-00-01")], _ => true);
        store.RecordSession(ByMac("AA"), T.AddMinutes(10), T.AddMinutes(10), true, [Dev("10.0.0.1", "00-00-00-00-00-01")], _ => true);
        Assert.Equal("gateway-mac:AA", Assert.Single(store.Networks()).Fingerprint);
        Assert.Equal(2, store.Devices(ByMac("AA"))["00:00:00:00:00:01"].Eligible);
    }

    [Fact]
    public void Two_lans_behind_the_same_gateway_address_stay_apart()
    {
        // home and office both use 10.0.0.254: different gateway MACs are different networks, and without a MAC the
        // address alone is ambiguous, so it stays a network of its own
        var store = new HistoryStore(Directory.CreateTempSubdirectory("ipm-hist-").FullName);
        store.RecordSession(ByMac("AA"), T, T, true, [Dev("10.0.0.1", "00-00-00-00-00-01")], _ => true);
        store.RecordSession(ByMac("BB"), T, T, true, [Dev("10.0.0.1", "00-00-00-00-00-02")], _ => true);
        store.RecordSession(ByAddress, T, T, true, [Dev("10.0.0.1", "00-00-00-00-00-03")], _ => true);
        Assert.Equal(3, store.Networks().Count);
        Assert.Single(store.Devices(ByMac("AA")));
        Assert.Equal(["00:00:00:00:00:03"], store.Devices(ByAddress).Keys);
    }

    [Fact]
    public void Store_records_sessions_newcomers_availability_timeline_and_cleanup()
    {
        var store = new HistoryStore(Directory.CreateTempSubdirectory("ipm-hist-").FullName);
        static bool Covered(string ip) => ip.StartsWith("10.0.0.", StringComparison.Ordinal);
        var first = store.RecordSession(Net, T, T.AddSeconds(5), true, [Dev("10.0.0.1", "00-00-00-00-00-01"), Dev("10.0.0.2", "00-00-00-00-00-02"), Dev("10.0.0.9", null)], Covered);
        Assert.Empty(first); // the network's first session is the baseline
        var second = store.RecordSession(Net, T.AddMinutes(10), T.AddMinutes(10).AddSeconds(5), true, [Dev("10.0.0.1", "00-00-00-00-00-01", 5), Dev("10.0.0.3", "00-00-00-00-00-03")], Covered);
        Assert.Equal(["00:00:00:00:00:03"], second);
        store.RecordSession(Net, T.AddMinutes(20), T.AddMinutes(20), false, [Dev("10.0.0.1", "00-00-00-00-00-01")], Covered); // incomplete: not counted

        var devices = store.Devices(Net);
        Assert.Equal(3, devices.Count); // the device without a MAC is never recorded (HIS-06)
        var one = devices["00:00:00:00:00:01"];
        Assert.Equal((2, 2), (one.Eligible, one.Online));
        var two = devices["00:00:00:00:00:02"];
        Assert.Equal((2, 1), (two.Eligible, two.Online)); // missed in the second (complete, covering) session
        Assert.Equal(50, two.Availability);
        Assert.Equal(3, one.RecentRtt.Count);

        var timeline = store.Timeline(Net, "00:00:00:00:00:02", null);
        Assert.Equal([false, true], timeline.Select(s => s.Online));
        Assert.Empty(store.Devices(new NetworkIdentity("other", "Other")));
        Assert.Equal("Lab", Assert.Single(store.Networks()).Name);

        Assert.True(store.Cleanup(1, T.AddDays(3)) > 0);
        Assert.Empty(store.Devices(Net));
    }

    [Fact]
    public void Relative_time_filters_and_sparkline()
    {
        Assert.Equal("just now", HistoryText.Relative(T, T.AddSeconds(30)));
        Assert.Equal("5 min ago", HistoryText.Relative(T, T.AddMinutes(5)));
        Assert.Equal("3 h ago", HistoryText.Relative(T, T.AddHours(3)));
        Assert.Equal("2 days ago", HistoryText.Relative(T, T.AddDays(2)));
        var devices = new[]
        {
            new HistoryDevice("A", T.AddDays(-40), T, "", "", 0, 0, []),          // long-time, seen recently
            new HistoryDevice("B", T.AddDays(-2), T, "", "", 0, 0, []),           // new in the last week
            new HistoryDevice("C", T.AddDays(-40), T.AddDays(-20), "", "", 0, 0, []), // disappeared
        };
        var from = HistoryText.From(InventoryPeriod.Week, T);
        Assert.Equal(["A", "B"], HistoryText.Filter(devices, from, InventoryShow.All).Select(d => d.Mac));
        Assert.Equal(["B"], HistoryText.Filter(devices, from, InventoryShow.NewInPeriod).Select(d => d.Mac));
        Assert.Equal(["C"], HistoryText.Filter(devices, from, InventoryShow.Disappeared).Select(d => d.Mac));
        Assert.Equal(3, HistoryText.Filter(devices, null, InventoryShow.NewInPeriod).Count());
        Assert.Equal("▂ █", HistoryText.Sparkline([1, null, 8])); // bars scale to the maximum: 1/8 of 7 steps rounds to the second bar
        Assert.Equal("", HistoryText.Sparkline([null]));
    }

    [Fact]
    public void History_columns_and_newcomer_flag()
    {
        var view = new HistoryView
        {
            Devices = new Dictionary<string, HistoryDevice> { ["00:00:00:00:00:01"] = new("00:00:00:00:00:01", T.AddDays(-1), T, "10.0.0.1", "", 4, 3, []) },
            Newcomers = new HashSet<string> { "00:00:00:00:00:01" },
        };
        var cols = view.Columns(new HistorySettings { Enabled = true }, () => T.AddMinutes(2)).ToList();
        var d = Dev("10.0.0.1", "00-00-00-00-00-01");
        Assert.Equal(["1 days ago", "2 min ago", "75 % (3/4)"], cols.Select(c => c.Text(d)));
        Assert.True(view.IsNewcomer(d));
        Assert.Empty(view.Columns(new HistorySettings(), () => T));
    }

    [Fact]
    public void Ssid_parsing() =>
        Assert.Equal("Office WiFi", NetworkIdentifier.ParseSsid("    Name                   : Wi-Fi\r\n    SSID                   : Office WiFi\r\n    BSSID                  : aa:bb:cc:dd:ee:ff\r\n"));
}

public class NotificationTests
{
    [Fact]
    public async Task Log_file_and_webhook_payload()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var received = new TaskCompletionSource<string>();
        _ = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            var s = c.GetStream();
            var buf = new byte[16384];
            var sb = new StringBuilder();
            while (true)
            {
                var n = await s.ReadAsync(buf);
                sb.Append(Encoding.UTF8.GetString(buf, 0, n));
                var text = sb.ToString();
                var split = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (split > 0 && int.TryParse(text.Split("Content-Length: ")[1].Split("\r\n")[0], out var len) && text.Length >= split + 4 + len)
                {
                    received.SetResult(text[(split + 4)..]);
                    break;
                }
            }

            await s.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray());
        });
        var log = Path.Combine(Directory.CreateTempSubdirectory("ipm-notify-").FullName, "events.log");
        var settings = new BackgroundSettings
        {
            Join = new EventActions { Enabled = true, Balloon = true, LogToFile = true, LogFile = log, Webhook = true, WebhookUrl = $"http://127.0.0.1:{port}/hook" },
        };
        var device = Samples.Device("10.0.0.7", "printer");
        var e = new BackgroundEvent(BackgroundEventType.Join, Samples.T, device.Key, null, "printer (10.0.0.7) joined the network.", device);
        string? balloon = null;
        var dispatcher = new NotificationDispatcher(new FakeSecrets()) { Balloon = (title, text) => balloon = title + "|" + text };
        var errors = await dispatcher.DispatchAsync(e, settings, ColumnCatalog.All, ColumnFormat.Default, CancellationToken.None);
        Assert.Empty(errors);
        Assert.Equal("IPMaster: JOIN|printer (10.0.0.7) joined the network.", balloon);
        Assert.Contains("\tJOIN\t10.0.0.7\t", await File.ReadAllTextAsync(log), StringComparison.Ordinal);
        using var json = JsonDocument.Parse(await received.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal("JOIN", json.RootElement.GetProperty("event").GetString());
        Assert.Equal("printer", json.RootElement.GetProperty("device").GetProperty("Host Name").GetString());

        Assert.Empty(await dispatcher.DispatchAsync(e with { Type = BackgroundEventType.Leave }, settings, ColumnCatalog.All, ColumnFormat.Default, CancellationToken.None));
        var smtp = await dispatcher.DispatchAsync(e, new BackgroundSettings { Join = new EventActions { Enabled = true, Email = true, EmailTo = "a@example.com" } },
            ColumnCatalog.All, ColumnFormat.Default, CancellationToken.None);
        Assert.Contains("No SMTP server configured", Assert.Single(smtp), StringComparison.Ordinal);
    }
}

public class BackgroundScanTests
{
    [Fact]
    public async Task Rounds_produce_join_and_debounced_leave_events()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        icmp.Alive.Add("10.0.0.2");
        var engine = new ScanEngine(icmp, new FakeArp(), new FakeDns());
        var settings = new ScanSettings { PingTimeoutMs = 50, PingAttempts = 1, ResolveHostNames = false, DeviceDeadlineSeconds = 0 };
        using var scanner = new BackgroundScanner(engine, (_, _, _) => Task.FromResult<ScanRequest?>(new ScanRequest { Plan = TestPlans.Plan("10.0.0.1-10.0.0.4"), Settings = settings }))
        {
            Settings = new BackgroundSettings { RoundDelayMinutes = 0, LeaveAfterMisses = 2 },
        };
        var rounds = new List<BackgroundRound>();
        var done = new TaskCompletionSource();
        scanner.RoundCompleted += (_, r) =>
        {
            lock (rounds)
            {
                rounds.Add(r);
                if (r.Number == 1)
                {
                    icmp.Alive.Remove("10.0.0.2");
                    icmp.Alive.Add("10.0.0.3");
                }

                if (r.Number == 3) done.TrySetResult();
            }
        };
        scanner.Start();
        await done.Task.WaitAsync(TimeSpan.FromSeconds(60));
        await scanner.StopAsync();
        lock (rounds)
        {
            Assert.Empty(rounds[0].Events); // baseline
            Assert.Equal([BackgroundEventType.Join], rounds[1].Events.Select(e => e.Type)); // .3 joined; .2 missed once
            Assert.Equal("10.0.0.2", Assert.Single(rounds[2].Events, e => e.Type == BackgroundEventType.Leave).Address.ToString());
            Assert.All(rounds.Take(3), r => Assert.True(r.Complete));
        }
    }

    [Fact]
    public async Task Cli_live_rewrites_the_output_after_each_round()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        var dir = Directory.CreateTempSubdirectory("ipm-live-").FullName;
        await new SettingsStore(dir).SaveAsync(new AppSettings
        {
            Scan = new ScanSettings { PingTimeoutMs = 50, PingAttempts = 1, ResolveHostNames = false },
            Background = new BackgroundSettings { RoundDelayMinutes = 0.005 },
        });
        var services = new ServiceCollection().AddIPMaster(dir);
        services.AddSingleton(new ScanProbes(icmp, new FakeArp(), new FakeDns()));
        services.AddSingleton<INetworkAdapterProvider>(new FakeAdapters());
        var sp = services.BuildServiceProvider();
        var err = new StringWriter();
        var output = Path.Combine(dir, "live.csv");
        using var cts = new CancellationTokenSource();
        var run = new CliApp(sp, new StringWriter(), err).RunAsync(["/live:" + output, "/range:10.0.0.1-10.0.0.3"], cts.Token);
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!File.Exists(output) && DateTime.UtcNow < deadline) await Task.Delay(100);
        await Task.Delay(1500); // let a second round rewrite it
        await cts.CancelAsync();
        Assert.Equal(ExitCodes.Ok, await run.WaitAsync(TimeSpan.FromSeconds(30)));
        Assert.Contains("10.0.0.2", await File.ReadAllTextAsync(output), StringComparison.Ordinal);
        var log = err.ToString();
        Assert.Contains("Round 1 completed", log, StringComparison.Ordinal);
        Assert.Contains("Round 2 completed", log, StringComparison.Ordinal);
        Assert.Contains("Background scanning stopped.", log, StringComparison.Ordinal);
    }
}

public class DuplicateMacChangeTests
{
    [Fact]
    public void One_mac_on_two_addresses_raises_no_ip_change_round_after_round()
    {
        // Real LAN case (R23): BC-24-11-F2-42-BD answered at .53 and .153; E8-6A-64-AF-E3-F3 at .200 and .201.
        static DeviceResult On(string ip, string mac) => Samples.Device(ip) with
        {
            Status = DeviceStatus.Online,
            Mac = Observation<PhysicalAddress>.Ok(PhysicalAddress.Parse(mac), Samples.T),
        };

        var round = new[] { On("10.0.0.53", "BC-24-11-F2-42-BD"), On("10.0.0.153", "BC-24-11-F2-42-BD"), On("10.0.0.200", "E8-6A-64-AF-E3-F3"), On("10.0.0.201", "E8-6A-64-AF-E3-F3") };
        var d = new ChangeDetector(2);
        d.Seed(round);
        for (var i = 0; i < 3; i++) Assert.Empty(d.ApplyRound(round, _ => true, true, Samples.T));
        // a genuine move: the MAC is now only at a new address
        var moved = d.ApplyRound([On("10.0.0.60", "BC-24-11-F2-42-BD"), On("10.0.0.200", "E8-6A-64-AF-E3-F3"), On("10.0.0.201", "E8-6A-64-AF-E3-F3")], _ => true, true, Samples.T);
        Assert.Contains(moved, e => e.Type == BackgroundEventType.IpChange && e.Message.Contains("10.0.0.53, 10.0.0.153 to 10.0.0.60", StringComparison.Ordinal));
    }
}
