using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Scanning;
using IPMaster.Core.Wifi;
using IPMaster.Infrastructure.Tools;
using IPMaster.Infrastructure.Wifi;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Wi-Fi Analyzer &amp; Optimizer (WIFI-01..08, D-097/D-099). Read-only: scans and connection data come from
/// <see cref="IWifiProvider"/>; nothing is ever changed on the adapter or on an access point. Built on the design system
/// (D-098): ToolKit layout, role classes, themed charts.
/// </summary>
internal sealed class WifiAnalyzerWindow : Window
{
    private const string LocationSettings = "ms-settings:privacy-location";
    private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);

    private sealed record NetRow(WifiBss B, bool Connected)
    {
        public string Ssid => (Connected ? "● " : "") + (B.Hidden ? "(hidden)" : B.Ssid);

        public string Bssid => WifiFormat.Bssid(B.Bssid);

        public int Signal => B.RssiDbm;

        public int Quality => B.LinkQuality;

        public string Band => WifiChannels.BandName(B.Band);

        public int Channel => B.Channel ?? 0;

        public string Width => B.WidthMhz is { } w ? $"{w} MHz" : "unknown";

        public string Standard => B.Standard;

        public string Security => B.Security;

        public string Roaming => string.Join(" ", new[] { B.Ies.RadioMeasurement ? "k" : null, B.Ies.BssTransition ? "v" : null, B.Ies.FastTransition ? "r" : null }.OfType<string>()) is { Length: > 0 } s ? s : "—";

        public string Load => B.Ies.ChannelUtilizationPercent is { } u ? $"{u:0} % busy, {B.Ies.StationCount} stations (measured by AP)" : "—";

        public string Country => B.Ies.Country ?? "—";
    }

    private sealed record ChannelRow(ChannelCandidate C, bool Best)
    {
        public string Channel => (Best ? "★ " : "") + C.Label;

        public double Score => C.Score;

        public string Allowed => C.Allowed ? (C.Preferred ? "yes" : "yes (not preferred)") : "no";

        public string Dfs => C.Dfs ? "DFS" : "";

        public int CoChannel => C.CoChannel;

        public int Overlapping => C.Overlapping;

        public string Measured => C.MeasuredUtilizationPercent is { } u ? $"{u:0} %" : "—";

        public string Evidence => string.Join("; ", C.Evidence);
    }

    private sealed record EventRow(WifiEvent E, string Impact)
    {
        public string Time => E.At.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture);

        public string Kind => E.Kind.ToString();

        public string Ssid => E.Ssid;

        public string Bssids => $"{(E.From is null ? "—" : WifiFormat.Bssid(E.From))} → {(E.To is null ? "—" : WifiFormat.Bssid(E.To))}";

        public string Channels => $"{E.FromChannel?.ToString(CultureInfo.InvariantCulture) ?? "—"} → {E.ToChannel?.ToString(CultureInfo.InvariantCulture) ?? "—"}";

        public string Signal => $"{E.RssiBefore?.ToString(CultureInfo.InvariantCulture) ?? "—"} → {E.RssiAfter?.ToString(CultureInfo.InvariantCulture) ?? "—"} dBm";

        public string Interruption => E.Interruption is { } t ? $"{t.TotalSeconds:0.#} s" : "—";

        public string Gateway => Impact;

        public string Detail => E.Detail;
    }

    private sealed record CoverageRow(CoverageSummary C)
    {
        public string Ssid => C.Ssid;

        public string Bssid => C.Bssid;

        public string Heard => $"{C.PointsHeard}/{C.Points}";

        public string Median => C.MedianRssiDbm is { } m ? $"{m} dBm" : "—";

        public string Best => C.BestRssiDbm is { } m ? $"{m} dBm" : "—";

        public string Good => $"{C.PercentAtLeast67:0} %";
    }

    private readonly IWifiProvider _wifi;
    private readonly WifiMonitor _monitor;
    private readonly WifiScanBook _book = new();
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
    private readonly Func<string, Func<CancellationToken, Task<string>>, Task> _run; // the window's ToolRunner (one operation at a time)
    private readonly TextBlock _status = ToolKit.StatusLine();
    private readonly Border _denied;
    private readonly ComboBox _adapter = ToolKit.Combo("Wireless adapter", [], width: 360);
    private List<WifiAdapter> _adapters = [];
    private WifiConnection? _connection;
    private SiteSurveyProject _survey = new();

    public WifiAnalyzerWindow(IWifiProvider wifi, IIcmpProbe icmp)
    {
        ArgumentNullException.ThrowIfNull(wifi);
        _wifi = wifi;
        _monitor = new WifiMonitor(wifi, icmp, TimeProvider.System);
        var runner = new ToolRunner(_status);
        _run = runner.RunAsync;
        Title = "Wi-Fi Analyzer & Optimizer";
        Width = 1200;
        Height = 820;
        MinWidth = Styling.Theme.ToolMinWidth;
        MinHeight = Styling.Theme.ToolMinHeight;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        _denied = Ui.Banner(WlanLayout.LocationHint, "warning", visible: false);
        var openSettings = Ui.Button("Open Location Settings", () =>
        {
            try
            {
                Process.Start(new ProcessStartInfo(LocationSettings) { UseShellExecute = true })?.Dispose();
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                _status.Text = "Could not open the settings: " + ex.Message;
            }

            return Task.CompletedTask;
        });
        _denied.Child = new StackPanel { Spacing = Styling.Theme.TightGap, Children = { new TextBlock { Text = WlanLayout.LocationHint, TextWrapping = TextWrapping.Wrap }, openSettings } };

        var scan = Ui.Button("Scan", () => LoadAsync(fresh: true), accent: true);
        var cancel = Ui.Button("Cancel", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        cancel.IsEnabled = false;
        runner.BusyChanged += (_, _) =>
        {
            scan.IsEnabled = !runner.IsBusy;
            cancel.IsEnabled = runner.IsBusy;
        };
        _adapter.SelectionChanged += async (_, _) => await LoadAsync(fresh: false);

        var tabs = new TabControl
        {
            Items =
            {
                new TabItem { Header = "Networks", Content = NetworksTab() },
                new TabItem { Header = "Channels", Content = ChannelsTab() },
                new TabItem { Header = "Live Monitoring", Content = MonitoringTab() },
                new TabItem { Header = "Roaming", Content = RoamingTab() },
                new TabItem { Header = "Site Survey", Content = SurveyTab() },
                new TabItem { Header = "Optimization", Content = OptimizationTab() },
                new TabItem { Header = "Reports", Content = ReportsTab() },
            },
        };
        var inputs = new StackPanel
        {
            Spacing = Styling.Theme.FormRowGap,
            Children =
            {
                SnmpTargetForm.Pair("Adapter", _adapter),
                new TextBlock { Classes = { "hint" }, Text = "Read-only: IPMaster never connects, disconnects or changes an access point. \"Scan\" asks the adapter for a new scan (about 4 s)." },
                _denied,
            },
        };
        Content = ToolKit.Layout(inputs, Ui.Row(scan, cancel), tabs, _status);
        Opened += async (_, _) => await LoadAdaptersAsync();
        Closing += (_, _) =>
        {
            runner.Dispose();
            _ = _monitor.StopAsync(); // the loop ends at its next await; nothing touches the window afterwards
        };
    }

    // ------------------------------------------------------------------ adapters and scans

    private Guid? AdapterId => _adapter.SelectedIndex is var i && i >= 0 && i < _adapters.Count ? _adapters[i].Id : null;

    private WifiAdapter? Adapter => _adapter.SelectedIndex is var i && i >= 0 && i < _adapters.Count ? _adapters[i] : null;

    private async Task LoadAdaptersAsync()
    {
        if (!_wifi.Capability.Available)
        {
            _status.Text = _wifi.Capability.Description;
            return;
        }

        var a = await _wifi.AdaptersAsync(CancellationToken.None);
        if (!a.HasValue)
        {
            ShowState(a.State, a.Detail);
            return;
        }

        _adapters = [.. a.Value!];
        _adapter.ItemsSource = _adapters.Select(x => $"{x.Description} ({x.State})").ToList();
        _adapter.SelectedIndex = 0; // loads the adapter's last scan (no radio activity)
    }

    private void ShowState(ObservationState state, string? detail)
    {
        _denied.IsVisible = state == ObservationState.AccessDenied;
        Styling.Theme.SetState(_status, state is ObservationState.AccessDenied or ObservationState.Failed ? "error" : state == ObservationState.Unsupported ? "warning" : null);
        _status.Text = state switch
        {
            ObservationState.AccessDenied => "Access denied by Windows location privacy (see above).",
            ObservationState.Unsupported => "Unsupported: " + detail,
            ObservationState.Empty => detail ?? "Nothing to show.",
            _ => detail ?? state.ToString(),
        };
    }

    private Task LoadAsync(bool fresh) => AdapterId is not { } id ? Task.CompletedTask : _run(fresh ? "Scanning (about 4 s)" : "Reading the adapter's last scan", async ct =>
    {
        var scanResult = await _wifi.ScanAsync(id, fresh, ct);
        var connection = await _wifi.ConnectionAsync(id, ct);
        string message = "";
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            Styling.Theme.SetState(_status, null);
            _denied.IsVisible = scanResult.State == ObservationState.AccessDenied || connection.State == ObservationState.AccessDenied;
            _connection = connection.HasValue ? connection.Value : null;
            if (scanResult.HasValue) _book.Add(scanResult.Value!);
            RefreshNetworks();
            RefreshChannels();
            if (!scanResult.HasValue)
            {
                ShowState(scanResult.State, scanResult.Detail);
                message = _status.Text ?? "";
            }
            else
            {
                message = $"{scanResult.Value!.Count} BSS(s) in this scan · {_book.Scans} scan(s) · " + (_connection is { } c
                    ? $"connected to {c.Ssid} ({WifiFormat.Bssid(c.Bssid)}), channel {c.Channel?.ToString(CultureInfo.InvariantCulture) ?? "?"}, {c.RssiDbm?.ToString(CultureInfo.InvariantCulture) ?? "?"} dBm"
                    : connection.State == ObservationState.Empty ? "not connected" : "connection: " + connection.State);
            }
        });
        return message;
    });

    private IReadOnlyList<WifiBss> Visible => _book.Current(DateTimeOffset.UtcNow, MaxAge);

    // ------------------------------------------------------------------ Networks

    private readonly ObservableCollection<NetRow> _netRows = [];
    private readonly TextBlock _connectionLine = new() { Classes = { "description" } };
    private ComboBox? _bandFilter;

    private Control NetworksTab()
    {
        var grid = Ui.Grid(("SSID", nameof(NetRow.Ssid), 190), ("BSSID", nameof(NetRow.Bssid), 135), ("Signal (dBm)", nameof(NetRow.Signal), 115), ("Quality %", nameof(NetRow.Quality), 95),
            ("Band", nameof(NetRow.Band), 85), ("Channel", nameof(NetRow.Channel), 90), ("Width", nameof(NetRow.Width), 90), ("Standard", nameof(NetRow.Standard), 160),
            ("Security", nameof(NetRow.Security), 200), ("11k/v/r", nameof(NetRow.Roaming), 85), ("Country", nameof(NetRow.Country), 90), ("Channel load", nameof(NetRow.Load), 0));
        grid.ItemsSource = _netRows;
        Avalonia.Automation.AutomationProperties.SetName(grid, "Networks");
        _bandFilter = ToolKit.Combo("Band filter", ["All bands", "2.4 GHz", "5 GHz", "6 GHz"], 0, 140);
        _bandFilter.SelectionChanged += (_, _) => RefreshNetworks();
        var top = new StackPanel { Spacing = Styling.Theme.TightGap, Children = { _connectionLine, Ui.Row(new TextBlock { Text = "Show", Classes = { "label" }, VerticalAlignment = VerticalAlignment.Center }, _bandFilter) } };
        var dock = new DockPanel();
        DockPanel.SetDock(top, Dock.Top);
        top.Margin = new Thickness(0, 4, 0, 6);
        dock.Children.Add(top);
        dock.Children.Add(grid);
        return dock;
    }

    private void RefreshNetworks()
    {
        var band = _bandFilter?.SelectedIndex switch { 1 => WifiBand.Band24, 2 => WifiBand.Band5, 3 => WifiBand.Band6, _ => (WifiBand?)null };
        _netRows.Clear();
        foreach (var b in Visible.Where(b => band is null || b.Band == band)) _netRows.Add(new NetRow(b, _connection is { } c && b.Bssid.Equals(c.Bssid)));
        _connectionLine.Text = _connection is { } k
            ? $"Connected: {k.Ssid} · {WifiFormat.Bssid(k.Bssid)} · {WifiChannels.BandName(k.Band)} channel {k.Channel?.ToString(CultureInfo.InvariantCulture) ?? "?"} · "
              + $"{k.RssiDbm?.ToString(CultureInfo.InvariantCulture) ?? "?"} dBm ({k.SignalQuality} %) · rx {k.RxRateKbps / 1000.0:0.#} / tx {k.TxRateKbps / 1000.0:0.#} Mbit/s (reported link rates) · "
              + $"{WifiStandards.PhyName(k.PhyType)} · {k.Authentication}, {k.Cipher} · gateway {Adapter?.Gateway?.ToString() ?? "unknown"}"
            : "Not connected (or the connection is hidden by Windows location privacy).";
    }

    // ------------------------------------------------------------------ Channels

    private readonly SpectrumChart _spectrum = new() { MinHeight = 160 };
    private readonly ObservableCollection<ChannelRow> _channelRows = [];
    private readonly TextBlock _planLine = new() { Classes = { "description" } };
    private ComboBox? _chBand;
    private ComboBox? _chWidth;

    private Control ChannelsTab()
    {
        _chBand = ToolKit.Combo("Band", ["2.4 GHz", "5 GHz", "6 GHz"], 0, 110);
        _chWidth = ToolKit.Combo("Planned channel width", ["20 MHz", "40 MHz", "80 MHz", "160 MHz"], 0, 110);
        _chBand.SelectionChanged += (_, _) => RefreshChannels();
        _chWidth.SelectionChanged += (_, _) => RefreshChannels();
        var grid = Ui.Grid(("Channel", nameof(ChannelRow.Channel), 190), ("Score", nameof(ChannelRow.Score), 85), ("Allowed", nameof(ChannelRow.Allowed), 165), ("DFS", nameof(ChannelRow.Dfs), 70),
            ("Co-channel", nameof(ChannelRow.CoChannel), 115), ("Overlapping", nameof(ChannelRow.Overlapping), 120), ("Measured busy", nameof(ChannelRow.Measured), 140),
            ("Evidence", nameof(ChannelRow.Evidence), 0));
        grid.ItemsSource = _channelRows;
        Avalonia.Automation.AutomationProperties.SetName(grid, "Channel scores");
        var legend = new TextBlock
        {
            Classes = { "hint" },
            Text = "Score: lower is better. Each network heard at −90 dBm or stronger adds overlap × signal weight; partial overlap counts 1.5× (radios cannot coordinate). "
                   + "Busy time is only \"measured\" when an access point announces it (BSS Load); everything else is inferred from beacons heard at this computer, "
                   + "which is not where the access point is. Fewer networks is not automatically better. ★ = best allowed channel.",
        };
        var top = new StackPanel
        {
            Spacing = Styling.Theme.TightGap, Margin = new Thickness(0, 4, 0, 6),
            Children = { Ui.Row(new TextBlock { Text = "Band", Classes = { "label" }, VerticalAlignment = VerticalAlignment.Center }, _chBand,
                new TextBlock { Text = "Width", Classes = { "label" }, VerticalAlignment = VerticalAlignment.Center }, _chWidth), _planLine },
        };
        var grid2 = new Grid { RowDefinitions = new RowDefinitions("Auto,*,Auto,*") };
        grid2.Children.Add(top);
        Grid.SetRow(_spectrum, 1);
        grid2.Children.Add(_spectrum);
        Grid.SetRow(legend, 2);
        legend.Margin = new Thickness(0, 6);
        grid2.Children.Add(legend);
        Grid.SetRow(grid, 3);
        grid2.Children.Add(grid);
        return grid2;
    }

    private void RefreshChannels()
    {
        if (_chBand is null || _chWidth is null) return;
        var band = _chBand.SelectedIndex switch { 1 => WifiBand.Band5, 2 => WifiBand.Band6, _ => WifiBand.Band24 };
        var width = band == WifiBand.Band24 ? 20 : _chWidth.SelectedIndex switch { 1 => 40, 2 => 80, 3 => 160, _ => 20 };
        var visible = Visible;
        var domain = RegulatoryDomain.For(RegulatoryDomain.Observed(visible));
        var own = _connection is { } c && c.Band == band ? visible.FirstOrDefault(b => b.Bssid.Equals(c.Bssid)) : null;
        var plan = ChannelPlanner.Plan(visible, band, width, domain, own?.Bssid, own?.FrequencyMhz ?? 0);
        _spectrum.Band = band;
        _spectrum.Networks = visible;
        _spectrum.Connected = _connection?.Bssid;
        _spectrum.InvalidateVisual();
        _channelRows.Clear();
        foreach (var x in plan.Candidates.Where(x => x.Allowed || x.CoChannel + x.Overlapping > 0).OrderBy(x => x.Score).ThenBy(x => x.Primary)) _channelRows.Add(new ChannelRow(x, x == plan.Best));
        _planLine.Text = $"Regulatory domain: {domain.Name}" + (domain.Known ? "" : " — confirm allowed channels locally") + $" · {visible.Count(b => b.Band == band)} BSS(s) in this band"
                         + (band == WifiBand.Band24 && _chWidth.SelectedIndex > 0 ? " · 2.4 GHz is planned at 20 MHz only" : "")
                         + (plan.Excluded > 0 ? $" · the connected access point ({plan.Excluded} BSS) is left out of its own score" : "")
                         + (plan.Best is { } best ? $" · best: {best.Label}" : " · no allowed channel");
    }

    // ------------------------------------------------------------------ Live monitoring

    private readonly SignalChart _signal = new() { MinHeight = 170 };
    private readonly LatencyChart _gatewayChart = new() { MinHeight = 150, Window = TimeSpan.FromMinutes(10) };
    private readonly TextBlock _liveLine = new() { Classes = { "description" } };
    private readonly ObservableCollection<EventRow> _liveEvents = [];

    private Control MonitoringTab()
    {
        var interval = ToolKit.Number(1, 1, 60, "Sampling interval in seconds", 70);
        var dnsName = ToolKit.Text("Name to resolve for DNS latency", "optional, e.g. a company host name", 260);
        Button? start = null;
        Button? stop = null;
        start = Ui.Button("Start Monitoring", () =>
        {
            if (AdapterId is not { } id)
            {
                _status.Text = "Choose an adapter first.";
                return Task.CompletedTask;
            }

            var name = dnsName.Text?.Trim() ?? "";
            var servers = Adapter?.DnsServers.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList() ?? [];
            _monitor.DnsProbe = name.Length == 0 ? null : async ct =>
            {
                var server = servers.FirstOrDefault() ?? DnsClient.SystemServers().FirstOrDefault();
                if (server is null) return (null, "no DNS server");
                var r = await DnsClient.QueryAsync(new IPEndPoint(server, 53), name, 1, new DnsQueryOptions { Timeout = TimeSpan.FromSeconds(2), Retries = 0 }, ct);
                return (r.Outcome == DnsOutcome.Reply ? r.Duration.TotalMilliseconds : null, $"{r.Status} from {server}");
            };
            try
            {
                _monitor.Start(id, TimeSpan.FromSeconds((double)(interval.Value ?? 1)));
            }
            catch (InvalidOperationException ex)
            {
                _status.Text = ex.Message;
                return Task.CompletedTask;
            }

            start!.IsEnabled = false;
            stop!.IsEnabled = true;
            _status.Text = "Monitoring the connection" + (name.Length == 0 ? " (DNS latency not measured: no name entered)." : $" and resolving {name} directly at the adapter's DNS server.");
            return Task.CompletedTask;
        }, accent: true);
        stop = Ui.Button("Stop", async () =>
        {
            stop!.IsEnabled = false;
            await _monitor.StopAsync();
            start.IsEnabled = true;
            _status.Text = "Monitoring stopped.";
        });
        stop.IsEnabled = false;
        _monitor.Sampled += _ => Dispatcher.UIThread.Post(RefreshLive);
        var events = Ui.Grid(("Time", nameof(EventRow.Time), 80), ("Event", nameof(EventRow.Kind), 120), ("SSID", nameof(EventRow.Ssid), 140), ("BSSID", nameof(EventRow.Bssids), 260),
            ("Detail", nameof(EventRow.Detail), 0));
        events.ItemsSource = _liveEvents;
        Avalonia.Automation.AutomationProperties.SetName(events, "Connection events");
        var form = new WrapPanel
        {
            ItemSpacing = Styling.Theme.ControlGap,
            Children = { SnmpTargetForm.Pair("Interval (s)", interval), SnmpTargetForm.Pair("DNS name", dnsName), start, stop },
        };
        var panel = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,Auto,*,Auto,*,Auto,*") };
        void Add(Control c, int row)
        {
            Grid.SetRow(c, row);
            panel.Children.Add(c);
        }

        form.Margin = new Thickness(0, 4, 0, 6);
        Add(form, 0);
        Add(_liveLine, 1);
        Add(new TextBlock { Text = "Signal", Classes = { "section" } }, 2);
        Add(_signal, 3);
        Add(new TextBlock { Text = "Gateway latency (lost pings as red ticks)", Classes = { "section" } }, 4);
        Add(_gatewayChart, 5);
        Add(new TextBlock { Text = "Connection events", Classes = { "section" } }, 6);
        Add(events, 7);
        return panel;
    }

    private void RefreshLive()
    {
        var samples = _monitor.History.Snapshot();
        _signal.Samples = samples.Select(s => (s.At, s.Connected?.RssiDbm)).ToList();
        _signal.InvalidateVisual();
        _gatewayChart.Samples = samples.Where(s => s.GatewayRttMs is not null || s.GatewayLost).Select(s => new MonitorSample(s.At, s.GatewayRttMs)).ToList();
        _gatewayChart.InvalidateVisual();
        var last = samples.Count > 0 ? samples[^1] : null;
        var gw = WifiMonitor.GatewayStats(samples.TakeLast(60).ToList(), new MonitoringSettings { WindowSamples = 60 });
        var intervals = samples.Select(s => s.Interval).OfType<TimeSpan>().TakeLast(60).ToList();
        var dns = samples.Select(s => s.DnsMs).OfType<double>().TakeLast(60).ToList();
        _liveLine.Text = last is null ? "No samples yet." : (last.Connected is { } c
            ? $"{c.Ssid} · {WifiFormat.Bssid(c.Bssid)} · {WifiChannels.BandName(c.Band)} ch {c.Channel?.ToString(CultureInfo.InvariantCulture) ?? "?"} · {c.RssiDbm?.ToString(CultureInfo.InvariantCulture) ?? "?"} dBm · "
              + $"rx {c.RxRateKbps / 1000.0:0.#} / tx {c.TxRateKbps / 1000.0:0.#} Mbit/s"
            : last.Connection.State == ObservationState.AccessDenied ? "Connection details denied by Windows location privacy." : "Not connected.")
            + $" · gateway {last.Gateway?.ToString() ?? "—"}: {Ms(gw.LatencyMs)}, loss {gw.LossPercent:0.#} %, jitter {Ms(gw.JitterMs)} (last {gw.Samples})"
            + $" · DNS {(dns.Count > 0 ? $"{dns.Average():0} ms avg" : last.DnsDetail ?? "not measured")}"
            + $" · measured interval {(intervals.Count > 0 ? $"{intervals.Average(t => t.TotalSeconds):0.00} s avg, max {intervals.Max(t => t.TotalSeconds):0.00} s" : "—")}";
        var roaming = _monitor.Roaming.Events;
        if (roaming.Count != _liveEvents.Count)
        {
            _liveEvents.Clear();
            foreach (var e in roaming.Reverse()) _liveEvents.Add(new EventRow(e, ""));
            RefreshRoaming();
        }
    }

    private static string Ms(double? v) => v is { } x ? $"{x:0} ms" : "—";

    // ------------------------------------------------------------------ Roaming

    private readonly ObservableCollection<EventRow> _roamRows = [];
    private readonly TextBlock _roamLine = new() { Classes = { "description" } };

    private Control RoamingTab()
    {
        var grid = Ui.Grid(("Time", nameof(EventRow.Time), 80), ("Event", nameof(EventRow.Kind), 110), ("SSID", nameof(EventRow.Ssid), 130), ("BSSID from → to", nameof(EventRow.Bssids), 260),
            ("Channel", nameof(EventRow.Channels), 90), ("Signal", nameof(EventRow.Signal), 120), ("Interruption", nameof(EventRow.Interruption), 95),
            ("Gateway pings lost (−5 s … +10 s)", nameof(EventRow.Gateway), 200), ("Detail", nameof(EventRow.Detail), 0));
        grid.ItemsSource = _roamRows;
        Avalonia.Automation.AutomationProperties.SetName(grid, "Roaming events");
        var hint = new TextBlock
        {
            Classes = { "hint" },
            Text = "Events come from Live Monitoring samples. 802.11k/v/r show what the access point advertises in its beacons; Windows does not report whether "
                   + "this computer used them for a roam. A roam faster than the sampling interval shows no interruption.",
        };
        var top = new StackPanel { Spacing = Styling.Theme.TightGap, Margin = new Thickness(0, 4, 0, 6), Children = { _roamLine, hint } };
        var dock = new DockPanel();
        DockPanel.SetDock(top, Dock.Top);
        dock.Children.Add(top);
        dock.Children.Add(grid);
        RefreshRoaming();
        return dock;
    }

    private void RefreshRoaming()
    {
        var samples = _monitor.History.Snapshot();
        var tracker = _monitor.Roaming;
        _roamRows.Clear();
        foreach (var e in tracker.Events.Reverse())
        {
            var (sent, lost) = RoamingTracker.GatewayImpact(e, samples, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
            _roamRows.Add(new EventRow(e, sent == 0 ? "not measured" : $"{lost} of {sent}"));
        }

        var span = samples.Count > 1 ? samples[^1].At - samples[0].At : TimeSpan.Zero;
        var own = _connection is { } c ? Visible.FirstOrDefault(b => b.Bssid.Equals(c.Bssid)) : null;
        _roamLine.Text = $"{tracker.Roams} roam(s), {tracker.Disconnects} disconnect(s), {tracker.PingPongs(TimeSpan.FromMinutes(2))} back-and-forth roam(s) in {span.TotalMinutes:0} min monitored"
                         + (span.TotalMinutes >= 5 ? $" · {tracker.Roams / span.TotalHours:0.#} roams/hour" : "")
                         + (own is null ? "" : $" · connected AP advertises 802.11k {(own.Ies.RadioMeasurement ? "yes" : "no")}, 802.11v {(own.Ies.BssTransition ? "yes" : "no")}, 802.11r {(own.Ies.FastTransition ? "yes" : "no")}");
    }

    // ------------------------------------------------------------------ Site survey

    private readonly SurveyCanvas _canvas = new() { MinHeight = 300, Cursor = new Avalonia.Input.Cursor(Avalonia.Input.StandardCursorType.Cross) };
    private readonly ObservableCollection<CoverageRow> _coverage = [];
    private ComboBox? _heatTarget;

    private Control SurveyTab()
    {
        _heatTarget = ToolKit.Combo("Heatmap network", ["(no heatmap)"], 0, 320);
        _heatTarget.SelectionChanged += (_, _) => RefreshSurvey();
        var load = Ui.Button("Load Floor Plan…", async () =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Floor plan image", FileTypeFilter = [new FilePickerFileType("Images") { Patterns = ["*.png", "*.jpg", "*.jpeg", "*.bmp"] }],
            });
            if (files.Count > 0 && files[0].TryGetLocalPath() is { } path) SetFloorPlan(path);
        });
        var open = Ui.Button("Open Survey…", async () =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Open survey", FileTypeFilter = [new FilePickerFileType("Survey (JSON)") { Patterns = ["*.json"] }] });
            if (files.Count == 0 || files[0].TryGetLocalPath() is not { } path) return;
            try
            {
                _survey = JsonSerializer.Deserialize<SiteSurveyProject>(await File.ReadAllTextAsync(path)) ?? new SiteSurveyProject();
                if (_survey.FloorPlanPath.Length > 0 && File.Exists(_survey.FloorPlanPath)) SetFloorPlan(_survey.FloorPlanPath);
                RefreshSurvey();
                _status.Text = $"Survey loaded: {_survey.Points.Count} point(s).";
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                _status.Text = "Cannot open the survey: " + ex.Message;
            }
        });
        var save = ToolKit.ExportButton(this, () => JsonSerializer.Serialize(_survey, Indented), "wifi-survey.json", "Save Survey…");
        var csv = ToolKit.ExportButton(this, () => SiteSurvey.Csv(_survey), "wifi-survey.csv", "Export CSV…");
        var png = Ui.Button("Export Heatmap PNG…", async () =>
        {
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Export heatmap", SuggestedFileName = "wifi-heatmap.png", DefaultExtension = "png" });
            if (file?.TryGetLocalPath() is not { } path) return;
            var size = new PixelSize(Math.Max(1, (int)_canvas.Bounds.Width), Math.Max(1, (int)_canvas.Bounds.Height));
            using var bitmap = new RenderTargetBitmap(size);
            bitmap.Render(_canvas);
            bitmap.Save(path, PngBitmapEncoderOptions.Default);
            _status.Text = "Heatmap exported (an interpolated estimate between the measured points).";
        });
        var undo = Ui.Button("Remove Last Point", () =>
        {
            if (_survey.Points.Count > 0) _survey.Points.RemoveAt(_survey.Points.Count - 1);
            RefreshSurvey();
            return Task.CompletedTask;
        });
        _canvas.PlanClicked += async (x, y) => await CaptureAsync(x, y);
        var coverage = Ui.Grid(("SSID", nameof(CoverageRow.Ssid), 180), ("BSSID", nameof(CoverageRow.Bssid), 140), ("Heard at", nameof(CoverageRow.Heard), 80),
            ("Median", nameof(CoverageRow.Median), 90), ("Best", nameof(CoverageRow.Best), 90), ("Points ≥ −67 dBm", nameof(CoverageRow.Good), 0));
        coverage.ItemsSource = _coverage;
        Avalonia.Automation.AutomationProperties.SetName(coverage, "Coverage by access point");
        var caption = new TextBlock
        {
            Classes = { "hint" },
            Text = "Click the plan where you stand to capture a measurement there (a fresh scan, about 4 s). The heatmap is an interpolated estimate (inverse "
                   + "distance weighting) between the numbered points, not a measurement; areas far from every point stay blank. Not heard = −100 dBm.",
        };
        var top = new StackPanel
        {
            Spacing = Styling.Theme.TightGap, Margin = new Thickness(0, 4, 0, 6),
            Children = { Ui.Row(load, open, save, csv, png, undo), Ui.Row(new TextBlock { Text = "Heatmap", Classes = { "label" }, VerticalAlignment = VerticalAlignment.Center }, _heatTarget), caption },
        };
        var grid = new Grid { RowDefinitions = new RowDefinitions("Auto,3*,Auto,*") };
        grid.Children.Add(top);
        Grid.SetRow(_canvas, 1);
        grid.Children.Add(_canvas);
        var covTitle = new TextBlock { Text = "Coverage by access point", Classes = { "section" } };
        Grid.SetRow(covTitle, 2);
        grid.Children.Add(covTitle);
        Grid.SetRow(coverage, 3);
        grid.Children.Add(coverage);
        return grid;
    }

    private void SetFloorPlan(string path)
    {
        try
        {
            _canvas.FloorPlan = new Bitmap(path);
            _survey.FloorPlanPath = path;
            _canvas.InvalidateVisual();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            _status.Text = "Cannot load the image: " + ex.Message;
        }
    }

    private Task CaptureAsync(double x, double y) => AdapterId is not { } id ? Task.CompletedTask : _run($"Measuring at point {_survey.Points.Count + 1} (about 4 s)", async ct =>
    {
        var scan = await _wifi.ScanAsync(id, fresh: true, ct);
        if (!scan.HasValue) return "No measurement: " + (scan.State == ObservationState.AccessDenied ? "access denied by location privacy." : scan.Detail ?? scan.State.ToString());
        var point = new SurveyPoint
        {
            X = x, Y = y, At = DateTimeOffset.Now,
            Readings = scan.Value!.Select(b => new SurveyReading { Ssid = b.Ssid, Bssid = WifiFormat.Bssid(b.Bssid), RssiDbm = b.RssiDbm, FrequencyMhz = b.FrequencyMhz }).ToList(),
        };
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            _survey.Points.Add(point);
            _book.Add(scan.Value!);
            RefreshSurvey();
        });
        return $"Point {_survey.Points.Count}: {point.Readings.Count} BSS(s) heard.";
    });

    private void RefreshSurvey()
    {
        if (_heatTarget is null) return;
        var selected = _heatTarget.SelectedItem as string;
        var ssids = _survey.Points.SelectMany(p => p.Readings).Select(r => r.Ssid).Where(s => s.Length > 0).Distinct().OrderBy(s => s, StringComparer.CurrentCultureIgnoreCase);
        var bssids = _survey.Points.SelectMany(p => p.Readings).Select(r => r.Bssid).Distinct().OrderBy(s => s, StringComparer.Ordinal);
        var items = new List<string> { "(no heatmap)" };
        items.AddRange(ssids.Select(s => "SSID: " + s));
        items.AddRange(bssids.Select(b => "BSSID: " + b));
        if (!items.SequenceEqual(_heatTarget.ItemsSource?.Cast<string>() ?? []))
        {
            _heatTarget.ItemsSource = items;
            _heatTarget.SelectedIndex = Math.Max(0, items.IndexOf(selected ?? ""));
        }

        var target = _heatTarget.SelectedItem as string ?? "";
        Func<SurveyReading, bool>? match = target.StartsWith("SSID: ", StringComparison.Ordinal) ? r => r.Ssid == target[6..]
            : target.StartsWith("BSSID: ", StringComparison.Ordinal) ? r => r.Bssid == target[7..] : null;
        _canvas.Points = _survey.Points;
        var plan = _canvas.ImageRect();
        var aspect = plan.Width > 0 ? plan.Height / plan.Width : 0.6;
        _canvas.Heatmap = match is null || _survey.Points.Count == 0 ? null : SiteSurvey.Interpolate(SiteSurvey.Values(_survey, match), 80, Math.Max(10, (int)(80 * aspect)), aspect: aspect);
        _canvas.InvalidateVisual();
        _coverage.Clear();
        foreach (var c in SiteSurvey.Coverage(_survey)) _coverage.Add(new CoverageRow(c));
    }

    // ------------------------------------------------------------------ Optimization

    private readonly StackPanel _advice = new() { Spacing = Styling.Theme.SectionGap };

    private Control OptimizationTab()
    {
        var run = Ui.Button("Analyse", () =>
        {
            RefreshAdvice();
            return Task.CompletedTask;
        }, accent: true);
        var hint = new TextBlock
        {
            Classes = { "hint" },
            Text = "Recommendations from what was observed: scans (Networks), samples and events (Live Monitoring). Each states its observations and confidence. "
                   + "IPMaster never changes access-point settings; apply a change yourself if it suits your network.",
        };
        var top = new StackPanel { Spacing = Styling.Theme.TightGap, Margin = new Thickness(0, 4, 0, 6), Children = { Ui.Row(run), hint } };
        var dock = new DockPanel();
        DockPanel.SetDock(top, Dock.Top);
        dock.Children.Add(top);
        dock.Children.Add(new ScrollViewer { Content = _advice, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled });
        return dock;
    }

    private IReadOnlyList<WifiRecommendation> Advise()
    {
        var visible = Visible;
        return WifiAdvisor.Advise(new WifiAdvisorInput(visible, _book.Scans, _connection, _monitor.History.Snapshot(), _monitor.Roaming.Events,
            RegulatoryDomain.For(RegulatoryDomain.Observed(visible))));
    }

    private void RefreshAdvice()
    {
        _advice.Children.Clear();
        foreach (var r in Advise())
        {
            var state = r.Severity switch { AdviceSeverity.Warning => "warning", AdviceSeverity.Suggestion => "info", _ => "success" };
            var body = new StackPanel { Spacing = 2 };
            body.Children.Add(new TextBlock { Text = $"{r.Topic} — {r.Severity}", Classes = { "section" } });
            body.Children.Add(new SelectableTextBlock { Text = r.Advice, TextWrapping = TextWrapping.Wrap });
            foreach (var o in r.Observations) body.Children.Add(new SelectableTextBlock { Text = "• " + o, Classes = { "hint" } });
            body.Children.Add(new TextBlock { Text = $"Confidence: {r.Confidence} ({r.ConfidenceReason})", Classes = { "hint" } });
            _advice.Children.Add(new Border { Classes = { "banner", state }, Child = body });
        }
    }

    // ------------------------------------------------------------------ Reports

    private Control ReportsTab()
    {
        var report = ToolKit.ReportBox("Wi-Fi report");
        var generate = Ui.Button("Generate Report", () =>
        {
            report.Text = Report();
            return Task.CompletedTask;
        }, accent: true);
        var csv = ToolKit.ExportButton(this, NetworksCsv, "wifi-networks.csv", "Export Networks CSV…");
        var top = Ui.Row(generate, ToolKit.CopyButton(this, () => report.Text ?? "", "Copy"), ToolKit.ExportButton(this, () => report.Text ?? "", "wifi-report.txt", "Export Report…"), csv);
        top.Margin = new Thickness(0, 4, 0, 6);
        var dock = new DockPanel();
        DockPanel.SetDock(top, Dock.Top);
        dock.Children.Add(top);
        dock.Children.Add(report);
        return dock;
    }

    private string NetworksCsv()
    {
        static string Q(string s) => s.Length > 0 && s[0] is '=' or '+' or '-' or '@' ? "'" + s : s.Contains(',', StringComparison.Ordinal) || s.Contains('"', StringComparison.Ordinal) ? "\"" + s.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : s;
        var sb = new StringBuilder("ssid,bssid,rssi_dbm,quality,frequency_mhz,band,channel,width_mhz,standard,security,k,v,r,country,channel_busy_pct_measured,stations,seen\n");
        foreach (var b in Visible)
        {
            sb.AppendLine(string.Join(',', Q(b.Ssid), WifiFormat.Bssid(b.Bssid), b.RssiDbm.ToString(CultureInfo.InvariantCulture), b.LinkQuality.ToString(CultureInfo.InvariantCulture),
                b.FrequencyMhz.ToString(CultureInfo.InvariantCulture), WifiChannels.BandName(b.Band), b.Channel?.ToString(CultureInfo.InvariantCulture) ?? "",
                b.WidthMhz?.ToString(CultureInfo.InvariantCulture) ?? "", Q(b.Standard), Q(b.Security), b.Ies.RadioMeasurement ? "1" : "0", b.Ies.BssTransition ? "1" : "0",
                b.Ies.FastTransition ? "1" : "0", b.Ies.Country ?? "", b.Ies.ChannelUtilizationPercent?.ToString("0", CultureInfo.InvariantCulture) ?? "",
                b.Ies.StationCount?.ToString(CultureInfo.InvariantCulture) ?? "", b.SeenAt.ToString("O", CultureInfo.InvariantCulture)));
        }

        return sb.ToString();
    }

    private string Report()
    {
        var sb = new StringBuilder();
        var visible = Visible;
        sb.AppendLine(CultureInfo.InvariantCulture, $"IPMaster Wi-Fi report, {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Adapter: {Adapter?.Description ?? "none"} ({Adapter?.State ?? "-"}), gateway {Adapter?.Gateway?.ToString() ?? "-"}");
        sb.AppendLine(_connection is { } c
            ? $"Connection: {c.Ssid} {WifiFormat.Bssid(c.Bssid)}, {WifiChannels.BandName(c.Band)} channel {c.Channel}, {c.RssiDbm} dBm ({c.SignalQuality} %), rx {c.RxRateKbps / 1000.0:0.#} / tx {c.TxRateKbps / 1000.0:0.#} Mbit/s, {WifiStandards.PhyName(c.PhyType)}, {c.Authentication}/{c.Cipher}"
            : "Connection: not connected or not available");
        var domain = RegulatoryDomain.For(RegulatoryDomain.Observed(visible));
        sb.AppendLine(CultureInfo.InvariantCulture, $"Scans: {_book.Scans}; BSSs seen in the last {MaxAge.TotalMinutes:0} min: {visible.Count}; regulatory domain: {domain.Name}");
        sb.AppendLine().AppendLine("Networks (signal, band, channel, width, standard, security, 802.11k/v/r, AP-measured busy):");
        foreach (var b in visible)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"  {(b.Hidden ? "(hidden)" : b.Ssid),-28} {WifiFormat.Bssid(b.Bssid)} {b.RssiDbm,4} dBm {WifiChannels.BandName(b.Band),-7} ch {b.Channel,-3} " +
                $"{(b.WidthMhz is { } w ? w + " MHz" : "width ?"),-8} {b.Standard,-20} {b.Security,-30} {(b.Ies.RadioMeasurement ? "k" : "-")}{(b.Ies.BssTransition ? "v" : "-")}{(b.Ies.FastTransition ? "r" : "-")} " +
                $"{(b.Ies.ChannelUtilizationPercent is { } u ? $"{u:0} %" : "-")}");
        }

        foreach (var band in new[] { WifiBand.Band24, WifiBand.Band5, WifiBand.Band6 })
        {
            if (!visible.Any(b => b.Band == band)) continue;
            var own = _connection is { } k && k.Band == band ? visible.FirstOrDefault(b => b.Bssid.Equals(k.Bssid)) : null;
            var plan = ChannelPlanner.Plan(visible, band, band == WifiBand.Band24 ? 20 : own?.WidthMhz ?? 20, domain, own?.Bssid, own?.FrequencyMhz ?? 0);
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Channel scores, {WifiChannels.BandName(band)} at {plan.WidthMhz} MHz (lower is better; inferred unless marked measured):");
            foreach (var x in plan.Candidates.Where(x => x.Allowed).OrderBy(x => x.Score).Take(8))
                sb.AppendLine(CultureInfo.InvariantCulture, $"  {(x == plan.Best ? "*" : " ")} {x.Label,-28} {x.Score,6:0.00}  {string.Join("; ", x.Evidence)}");
        }

        sb.AppendLine().AppendLine("Recommendations (IPMaster changes nothing on access points):");
        foreach (var r in Advise())
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"  [{r.Severity}] {r.Topic}: {r.Advice}");
            foreach (var o in r.Observations) sb.AppendLine("      - " + o);
            sb.AppendLine(CultureInfo.InvariantCulture, $"      confidence {r.Confidence}: {r.ConfidenceReason}");
        }

        var samples = _monitor.History.Snapshot();
        if (samples.Count > 0)
        {
            var gw = WifiMonitor.GatewayStats(samples, new MonitoringSettings { WindowSamples = samples.Count });
            var rssi = samples.Select(s => s.Connected?.RssiDbm).OfType<int>().ToList();
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Live monitoring: {samples.Count} samples from {samples[0].At.ToLocalTime():HH:mm:ss} to {samples[^1].At.ToLocalTime():HH:mm:ss}; " +
                $"signal {(rssi.Count > 0 ? $"min {rssi.Min()} / avg {rssi.Average():0} / max {rssi.Max()} dBm" : "-")}; gateway loss {gw.LossPercent:0.#} % of {gw.Samples}, jitter {Ms(gw.JitterMs)}");
            foreach (var e in _monitor.Roaming.Events) sb.AppendLine(CultureInfo.InvariantCulture, $"  {e.At.ToLocalTime():HH:mm:ss} {e.Kind} {e.Ssid}: {e.Detail}");
        }

        if (_survey.Points.Count > 0)
        {
            sb.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Site survey: {_survey.Points.Count} point(s); heatmaps are interpolated estimates between them.");
            foreach (var cov in SiteSurvey.Coverage(_survey)) sb.AppendLine(CultureInfo.InvariantCulture, $"  {cov.Ssid,-28} {cov.Bssid} heard at {cov.PointsHeard}/{cov.Points}, median {cov.MedianRssiDbm} dBm, ≥ −67 dBm at {cov.PercentAtLeast67:0} %");
        }

        return sb.ToString();
    }
}
