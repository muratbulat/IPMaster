using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Scanning;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Monitoring;

namespace IPMaster.Desktop.Views;

/// <summary>Response-time chart with Good/Critical reference lines (MON-04). Lost pings are drawn as red ticks.</summary>
internal sealed class LatencyChart : Styling.ThemedControl
{
    public IReadOnlyList<MonitorSample> Samples { get; set; } = [];

    public MonitoringSettings Thresholds { get; set; } = new();

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(5);

    public override void Render(DrawingContext context)
    {
        var b = Bounds;
        if (b.Width < 40 || b.Height < 40) return;
        const double left = 52, bottom = 22, top = 8, right = 8;
        var plot = new Rect(left, top, b.Width - left - right, b.Height - top - bottom);
        var text = Brush(Styling.Theme.Keys.ChartText);
        context.FillRectangle(Brush(Styling.Theme.Keys.ChartSurface), plot);
        var now = DateTimeOffset.UtcNow;
        var from = now - Window;
        var visible = Samples.Where(s => s.At >= from).ToList();
        var max = Math.Max(Thresholds.CriticalLatencyMs * 1.2, visible.Where(s => !s.Lost).Select(s => s.RttMs!.Value).DefaultIfEmpty(0).Max() * 1.1);
        double X(DateTimeOffset t) => plot.Left + (t - from).TotalSeconds / Window.TotalSeconds * plot.Width;
        double Y(double v) => plot.Bottom - Math.Min(v, max) / max * plot.Height;
        void HLine(double v, IBrush brush, string label)
        {
            var y = Y(v);
            context.DrawLine(new Pen(brush, 1, DashStyle.Dash), new Point(plot.Left, y), new Point(plot.Right, y));
            context.DrawText(new FormattedText(label, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, 11, brush), new Point(4, y - 8));
        }

        HLine(Thresholds.GoodLatencyMs, Brush(Styling.Theme.Keys.ChartGood), $"{Thresholds.GoodLatencyMs} ms");
        HLine(Thresholds.CriticalLatencyMs, Brush(Styling.Theme.Keys.ChartCritical), $"{Thresholds.CriticalLatencyMs} ms");
        context.DrawText(new FormattedText($"−{Window.TotalMinutes:0} min", CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, 11, text), new Point(plot.Left, plot.Bottom + 4));
        context.DrawText(new FormattedText("now", CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, 11, text), new Point(plot.Right - 24, plot.Bottom + 4));
        var pen = Pen(Styling.Theme.Keys.Series1, 1.5);
        Point? prev = null;
        foreach (var s in visible)
        {
            if (s.Lost)
            {
                var x = X(s.At);
                context.DrawLine(Pen(Styling.Theme.Keys.ChartCritical, 1.5), new Point(x, plot.Bottom), new Point(x, plot.Bottom - 10));
                prev = null;
                continue;
            }

            var p = new Point(X(s.At), Y(s.RttMs!.Value));
            if (prev is { } q) context.DrawLine(pen, q, p);
            prev = p;
        }
    }
}

/// <summary>Charts and Route tabs for a monitored device (MON-04/05). Owns the hop monitor of its Route tab.</summary>
internal sealed class MonitoringTabs : IDisposable
{
    public sealed record HopRow(int Ttl, string Address, string Latency, string Loss, string Quality);

    private readonly MainWindowViewModel _vm;
    private readonly AddressKeyHolder _key;
    private readonly LatencyChart _chart = new() { MinHeight = 260 };
    private readonly DataGrid _hops = Ui.Grid(("Hop", "Ttl", 50), ("Address", "Address", 170), ("Latency", "Latency", 100), ("Loss", "Loss", 90), ("Quality", "Quality", 0));
    private readonly TextBlock _routeStatus = new() { TextWrapping = TextWrapping.Wrap, Classes = { "status" } };
    private LiveMonitor? _hopMonitor;
    private IReadOnlyList<RouteHop> _route = [];

    private sealed record AddressKeyHolder(Core.Targets.AddressKey Key);

    public MonitoringTabs(MainWindowViewModel vm, DeviceResult device)
    {
        _vm = vm;
        _key = new AddressKeyHolder(device.Key);
        vm.MonitorTick += OnTick;
    }

    public TabItem ChartsTab()
    {
        var range = Form.Combo(["Last 5 minutes", "Last 30 minutes", "Last hour"], 0);
        range.SelectionChanged += (_, _) =>
        {
            _chart.Window = TimeSpan.FromMinutes(range.SelectedIndex switch { 1 => 30, 2 => 60, _ => 5 });
            Refresh();
        };
        var stats = new TextBlock { Opacity = 0.85 };
        _statsLine = stats;
        Refresh();
        return new TabItem { Header = "Charts", Content = Ui.Layout(Ui.Row(range), _chart, stats) };
    }

    private TextBlock? _statsLine;

    public TabItem RouteTab()
    {
        Button? trace = null;
        trace = Ui.Button("Trace Route", async () =>
        {
            trace!.IsEnabled = false;
            _routeStatus.Text = "Tracing…";
            try
            {
                var tracer = _vm.Services.GetService(typeof(IRouteTracer)) as IRouteTracer ?? new RouteTracer();
                _route = await tracer.TraceAsync(_key.Key.ToIPAddress(), 30, TimeSpan.FromSeconds(1), CancellationToken.None);
                _hopMonitor?.Dispose();
                _hopMonitor = new LiveMonitor(_vm.Probes.Icmp) { Settings = _vm.Settings.Monitoring };
                foreach (var h in _route.Where(h => h.Address is not null)) _hopMonitor.Start(Core.Targets.AddressKey.From(h.Address!));
                _hopMonitor.Updated += (_, _) => Avalonia.Threading.Dispatcher.UIThread.Post(RefreshHops);
                _routeStatus.Text = $"{_route.Count} hop(s). Each hop is pinged every second. Routers often rate-limit or deprioritise ICMP replies to themselves, " +
                                    "so loss on an intermediate hop that does not continue to later hops is usually not real loss.";
                RefreshHops();
            }
            catch (Exception ex) when (ex is System.Net.NetworkInformation.PingException or InvalidOperationException)
            {
                _routeStatus.Text = "Trace failed: " + ex.Message;
            }
            finally
            {
                trace!.IsEnabled = true;
            }
        }, accent: true);
        return new TabItem { Header = "Route", Content = Ui.Layout(Ui.Row(trace), _hops, _routeStatus) };
    }

    private void RefreshHops() => _hops.ItemsSource = _route.Select(h =>
    {
        if (h.Address is null) return new HopRow(h.Ttl, "*", "", "", "no reply");
        var snap = _hopMonitor?.Snapshot(Core.Targets.AddressKey.From(h.Address));
        return new HopRow(h.Ttl, h.Address.ToString(), snap?.LatencyMs is { } l ? $"{l:0} ms" : h.RttMs is { } r ? $"{r:0} ms" : "lost",
            snap is { Samples: > 0 } ? $"{snap.LossPercent:0.#} %" : "", snap is null ? "" : $"{MonitorColumns.Bullet(snap.Quality)} {snap.Quality}");
    }).ToList();

    private void OnTick(object? sender, EventArgs e) => Refresh();

    private void Refresh()
    {
        var series = _vm.Monitor.Series(_key.Key);
        _chart.Samples = series?.Last(MonitorSeries.DefaultCapacity) ?? [];
        _chart.Thresholds = _vm.Settings.Monitoring;
        _chart.InvalidateVisual();
        if (_statsLine is not null && _vm.Monitor.Snapshot(_key.Key) is { } s)
        {
            _statsLine.Text = $"Latency {(s.LatencyMs is { } l ? $"{l:0.#} ms" : "lost")} · loss {s.LossPercent:0.#} % · jitter {(s.JitterMs is { } j ? $"{j:0.#} ms" : "n/a")} · " +
                              $"{s.Quality} · {series!.Count} sample(s) kept (max 1 h)" + (_vm.Monitor.IsMonitored(_key.Key) ? "" : " · monitoring stopped");
        }
    }

    public void Dispose()
    {
        _vm.MonitorTick -= OnTick;
        _hopMonitor?.Dispose();
    }
}

/// <summary>Background scan log (BKG-03): Date/Time and Description.</summary>
internal sealed class ScanLogWindow : Window
{
    public sealed record Row(string Time, string Description);

    public ScanLogWindow(BackgroundLog log)
    {
        Title = "Background Scan Log";
        Width = 820;
        Height = 480;
        var grid = Ui.Grid(("Date/Time", "Time", 170), ("Description", "Description", 0));
        void Load() => grid.ItemsSource = log.Items.Select(i => new Row(i.At.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), i.Text)).Reverse().ToList();
        EventHandler handler = (_, _) => Avalonia.Threading.Dispatcher.UIThread.Post(Load);
        log.Changed += handler;
        Closed += (_, _) => log.Changed -= handler;
        Load();
        Content = Ui.Layout(null, grid, Ui.Row(Ui.Button("Copy", () => Ui.CopyAsync(this, string.Join(Environment.NewLine,
            ((IEnumerable<Row>?)grid.ItemsSource ?? []).Select(r => $"{r.Time}\t{r.Description}"))))));
    }
}

internal static class ContinuousDialogs
{
    /// <summary>Per-event notification preferences (BKG-03/04).</summary>
    public static async Task<BackgroundSettings?> EventsAsync(Window owner, MainWindowViewModel vm, BackgroundSettings s)
    {
        var w = Ui.Window("Background Scan Events", 760, 640);
        var tabs = new TabControl();
        var apply = new List<Func<BackgroundSettings, BackgroundSettings>>();
        foreach (var type in Enum.GetValues<BackgroundEventType>())
        {
            var a = s.For(type);
            var f = new Form();
            var enabled = f.Full(new CheckBox
            {
                Content = type switch
                {
                    BackgroundEventType.Join => "When a device joins the network",
                    BackgroundEventType.Leave => "When a device leaves the network",
                    BackgroundEventType.NewMac => "When a new MAC address is found",
                    _ => "When a device changes its IP address",
                }, IsChecked = a.Enabled, FontWeight = FontWeight.SemiBold
            });
            var balloon = f.Full(new CheckBox { Content = "Show a notification", IsChecked = a.Balloon });
            var sound = new CheckBox { Content = "Play sound", IsChecked = a.PlaySound };
            var soundFile = new TextBox { Text = a.SoundFile, PlaceholderText = "C:\\Windows\\Media\\notify.wav" };
            f.Add("", Ui.Row(sound));
            f.Add("Sound file", soundFile);
            var launch = new CheckBox { Content = "Launch application", IsChecked = a.Launch };
            var cmd = new TextBox { Text = a.LaunchCommand, PlaceholderText = "notify.cmd [event] [IP Address] [Host Name]" };
            f.Add("", launch);
            f.Add("Command line", cmd);
            var log = new CheckBox { Content = "Log event to file", IsChecked = a.LogToFile };
            var logFile = new TextBox { Text = a.LogFile };
            f.Add("", log);
            f.Add("Log file", logFile);
            var email = new CheckBox { Content = "Send an e-mail to", IsChecked = a.Email };
            var to = new TextBox { Text = a.EmailTo, PlaceholderText = "admin@example.com" };
            f.Add("", email);
            f.Add("Recipients", to);
            var hook = new CheckBox { Content = "Send webhook to URL", IsChecked = a.Webhook };
            var url = new TextBox { Text = a.WebhookUrl, PlaceholderText = "https://hooks.example.com/ipmaster" };
            f.Add("", hook);
            f.Add("Webhook URL", url);
            f.Full(Form.Hint("Command lines may use [Column Name] and [event] (JOIN, LEAVE, NEWMAC, IPCHANGE). Webhooks receive a JSON POST with event, message, timestamp and the device's columns."));
            tabs.Items.Add(new TabItem { Header = BackgroundEvent.Code(type), Content = new ScrollViewer { Content = f.Grid } });
            var t = type;
            apply.Add(cur =>
            {
                var x = new EventActions
                {
                    Enabled = enabled.IsChecked == true, Balloon = balloon.IsChecked == true, PlaySound = sound.IsChecked == true, SoundFile = soundFile.Text?.Trim() ?? "",
                    Launch = launch.IsChecked == true, LaunchCommand = cmd.Text?.Trim() ?? "", LogToFile = log.IsChecked == true, LogFile = logFile.Text?.Trim() ?? "",
                    Email = email.IsChecked == true, EmailTo = to.Text?.Trim() ?? "", Webhook = hook.IsChecked == true, WebhookUrl = url.Text?.Trim() ?? "",
                };
                return t switch
                {
                    BackgroundEventType.Join => cur with { Join = x },
                    BackgroundEventType.Leave => cur with { Leave = x },
                    BackgroundEventType.NewMac => cur with { NewMac = x },
                    _ => cur with { IpChange = x },
                };
            });
        }

        BackgroundSettings? result = null;
        var smtp = s.Smtp;
        var ok = Ui.Button("OK", () =>
        {
            var r = s with { Smtp = smtp };
            foreach (var a in apply) r = a(r);
            result = r;
            w.Close();
            return Task.CompletedTask;
        }, accent: true);
        var emailSettings = Ui.Button("E-mail Settings…", async () =>
        {
            if (await EmailAsync(w, vm, smtp) is { } x) smtp = x;
        });
        var testNotification = Ui.Button("Test Notification", () =>
        {
            vm.TestNotification();
            return Task.CompletedTask;
        });
        w.Content = Ui.Layout(null, tabs, Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; }), emailSettings, testNotification));
        await w.ShowDialog(owner);
        return result;
    }

    /// <summary>SMTP settings with Test (BKG-04). The vendor "automatic" backend does not exist here (SEC-07, D-006).</summary>
    public static async Task<SmtpSettings?> EmailAsync(Window owner, MainWindowViewModel vm, SmtpSettings s)
    {
        var w = Ui.Window("E-mail Settings", 560, 420);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var f = new Form();
        f.Full(Form.Hint("Automatic settings (a vendor e-mail backend) are not available: enter your own SMTP server."));
        var host = f.Add("SMTP server", new TextBox { Text = s.Host, PlaceholderText = "smtp.example.com" });
        var port = f.Add("Port", new NumericUpDown { Value = s.Port, Minimum = 1, Maximum = 65535, FormatString = "0", Width = 140, HorizontalAlignment = HorizontalAlignment.Left });
        var security = f.Add("Connection type", Form.Combo(["Regular (unencrypted)", "Secure to regular port (STARTTLS)", "Secure to dedicated port (TLS)"], (int)s.Security));
        var creds = new List<(Guid? Id, string Label)> { (null, "(no authentication)") };
        creds.AddRange(vm.Settings.Credentials.Select(c => ((Guid?)c.Id, c.Display)));
        var cred = f.Add("Username / password", Form.Combo(creds.Select(c => c.Label), Math.Max(0, creds.FindIndex(c => c.Id == s.CredentialId))));
        var from = f.Add("From", new TextBox { Text = s.From, PlaceholderText = "ipmaster@example.com" });
        var testTo = f.Add("Test recipient", new TextBox());
        var status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        SmtpSettings Collect() => new()
        {
            Host = host.Text?.Trim() ?? "", Port = (int)(port.Value ?? 587), Security = (SmtpSecurity)Math.Max(0, security.SelectedIndex),
            CredentialId = creds[Math.Max(0, cred.SelectedIndex)].Id, From = from.Text?.Trim() ?? "",
        };
        SmtpSettings? result = null;
        var test = Ui.Button("Test", async () =>
        {
            status.Text = "Sending…";
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(40));
                await vm.Ops.Notifier.SendMailAsync(Collect(), testTo.Text ?? "", "IPMaster test message", "This is a test message from IPMaster.", cts.Token);
                status.Text = "Test message sent.";
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                status.Text = "Failed: " + ex.Message;
            }
        });
        var ok = Ui.Button("OK", () =>
        {
            result = Collect();
            w.Close();
            return Task.CompletedTask;
        }, accent: true);
        w.Content = new StackPanel { Margin = new Thickness(16), Spacing = 10, Children = { f.Grid, status, Ui.Row(ok, test, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })) } };
        await w.ShowDialog(owner);
        return result;
    }

    public static async Task<(bool Save, string File)?> FileOutputAsync(Window owner, BackgroundSettings s)
    {
        var w = Ui.Window("File Output", 600, 220);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var save = new CheckBox { Content = "Save results to the file after each round of the background scan", IsChecked = s.SaveAfterRound };
        var file = new TextBox { Text = s.OutputFile, PlaceholderText = @"C:\Reports\lan_%yyyy%%mm%%dd%.csv" };
        (bool, string)? result = null;
        var browse = Ui.Button("…", async () =>
        {
            var f = await w.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Output file", DefaultExtension = "csv" });
            if (f?.TryGetLocalPath() is { } p) file.Text = p;
        });
        var ok = Ui.Button("OK", () =>
        {
            result = (save.IsChecked == true, file.Text?.Trim() ?? "");
            w.Close();
            return Task.CompletedTask;
        }, accent: true);
        w.Content = new StackPanel
        {
            Margin = new Thickness(16), Spacing = 10,
            Children = { save, Form.WithButton(file, browse), Form.Hint(".csv .txt .htm .xml .json .db; date tokens such as %yyyy%%mm%%dd% are expanded. Same as the /live switch."),
                Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })) },
        };
        await w.ShowDialog(owner);
        return result;
    }
}

/// <summary>Per-device history (HIS-04): non-modal timeline that keeps its device.</summary>
internal sealed class DeviceHistoryWindow : Window
{
    public sealed record Row(string Time, string Status, string Ip, string Host, string Rtt);

    public DeviceHistoryWindow(IHistoryStore store, NetworkIdentity network, string mac, string title, DateTimeOffset? from)
    {
        Title = $"History — {title}";
        Width = 760;
        Height = 520;
        var grid = Ui.Grid(("Date/Time", "Time", 170), ("Status", "Status", 90), ("IP Address", "Ip", 140), ("Host Name", "Host", 200), ("Response", "Rtt", 0));
        var list = store.Timeline(network, mac, from);
        grid.ItemsSource = list.Select(s => new Row(s.At.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), s.Online ? "online" : "offline", s.Ip, s.Host,
            s.RttMs is { } r ? (r < 1 ? "<1 ms" : $"{r:0} ms") : "")).ToList();
        var header = new TextBlock { Text = $"{mac} on {network.Name} · {list.Count} sighting(s){(from is { } f ? $" since {f.ToLocalTime():yyyy-MM-dd}" : "")}", Classes = { "status" } };
        Content = Ui.Layout(header, grid, null);
    }
}

/// <summary>Reports → Device Inventory (HIS-05).</summary>
internal sealed class InventoryWindow : Window
{
    public sealed record Row(string Mac, string Ip, string Host, string FirstSeen, string LastSeen, string Availability, string Recent, HistoryDevice Device);

    public InventoryWindow(MainWindowViewModel vm)
    {
        Title = "Device Inventory";
        Width = 1100;
        Height = 620;
        var period = Form.Combo(["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days", "All time"], 4);
        var show = Form.Combo(["All devices", "New in period", "Disappeared"], 0);
        var find = new TextBox { PlaceholderText = "Find (MAC, IP, host, vendor)", Width = 260 };
        var grid = Ui.Grid(("MAC Address", "Mac", 160), ("Last IP", "Ip", 130), ("Host Name", "Host", 200), ("First Seen", "FirstSeen", 150), ("Last Seen", "LastSeen", 150),
            ("Availability", "Availability", 130), ("Recent Response Times", "Recent", 0));
        var status = new TextBlock { Opacity = 0.8 };
        var network = vm.Ops.HistoryView.Network;
        IReadOnlyDictionary<string, HistoryDevice> all = new Dictionary<string, HistoryDevice>();
        string Vendor(string mac) => vm.Oui.Capability.Available && Core.Results.Formats.ParseMac(mac) is { } pa ? vm.Oui.Lookup(pa) ?? "" : "";
        DateTimeOffset? From() => HistoryText.From((InventoryPeriod)Math.Max(0, period.SelectedIndex), DateTimeOffset.UtcNow);
        void Apply()
        {
            show.IsEnabled = period.SelectedIndex != 4;
            var now = DateTimeOffset.UtcNow;
            var text = find.Text ?? "";
            var rows = HistoryText.Filter(all.Values, From(), (InventoryShow)(show.IsEnabled ? show.SelectedIndex : 0))
                .Where(d => text.Length == 0 || d.Mac.Contains(text, StringComparison.OrdinalIgnoreCase) || d.LastIp.Contains(text, StringComparison.OrdinalIgnoreCase)
                            || d.LastHost.Contains(text, StringComparison.OrdinalIgnoreCase) || Vendor(d.Mac).Contains(text, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(d => d.LastSeen)
                .Select(d => new Row(d.Mac, d.LastIp, d.LastHost, $"{d.FirstSeen.ToLocalTime():yyyy-MM-dd HH:mm}", HistoryText.Relative(d.LastSeen, now),
                    d.Availability is { } a ? $"{a:0.#} % ({d.Online}/{d.Eligible})" : "", HistoryText.Sparkline(d.RecentRtt), d))
                .ToList();
            grid.ItemsSource = rows;
            status.Text = network is null ? "History is off or no network has been recorded yet (Options → History)." : $"{rows.Count} of {all.Count} device(s) on {network.Name}.";
        }

        period.SelectionChanged += (_, _) => Apply();
        show.SelectionChanged += (_, _) => Apply();
        find.TextChanged += (_, _) => Apply();
        void Open()
        {
            if (grid.SelectedItem is Row r && network is not null) new DeviceHistoryWindow(vm.Ops.History, network, r.Mac, r.Host.Length > 0 ? r.Host : r.Mac, From()).Show(this);
        }

        grid.DoubleTapped += (_, _) => Open();
        grid.ContextMenu = new ContextMenu { Items = { new MenuItem { Header = "History…" } } };
        ((MenuItem)grid.ContextMenu.Items[0]!).Click += (_, _) => Open();
        Content = Ui.Layout(Ui.Row(new TextBlock { Text = "Period", VerticalAlignment = VerticalAlignment.Center }, period,
                new TextBlock { Text = "Show", VerticalAlignment = VerticalAlignment.Center }, show, find), grid, status);
        Opened += async (_, _) =>
        {
            if (network is null) await vm.Ops.RefreshHistoryAsync();
            network = vm.Ops.HistoryView.Network;
            all = network is null ? all : await Task.Run(() => vm.Ops.History.Devices(network));
            Apply();
        };
    }
}
