using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Results;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → Syslog Receiver (D-079). Listens only while started; Stop and closing the window release the ports.</summary>
internal sealed class SyslogReceiverWindow : Window
{
    private const int MaxDrainPerTick = 5000;

    private sealed record Row(SyslogMessage M)
    {
        public string Received => M.ReceivedUtc.ToLocalTime().ToString("HH:mm:ss.fff", CultureInfo.CurrentCulture);

        public string Source => M.Source;

        public string Transport => M.Transport;

        public string Facility => M.FacilityName;

        public string Severity => M.SeverityName;

        public string Host => M.Host;

        public string App => M.AppName;

        public string Message => M.Message.Length > 500 ? M.Message[..500] + "…" : M.Message;
    }

    private SyslogReceiver? _receiver;
    private readonly Queue<SyslogMessage> _history = new();
    private readonly ObservableCollection<Row> _rows = [];
    private long _evicted;
    private SyslogStats? _lastStats;

    public SyslogReceiverWindow()
    {
        Title = "Syslog Receiver";
        Width = 1200;
        Height = 800;
        MinWidth = 640;
        MinHeight = 440;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();

        var addresses = new List<(string Label, IPAddress Address)>
        {
            ("All IPv4 addresses (0.0.0.0)", IPAddress.Any), ("All IPv4 and IPv6 addresses", IPAddress.IPv6Any), ("This computer only (127.0.0.1)", IPAddress.Loopback),
        };
        foreach (var a in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
                     .SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(u => u.Address)
                     .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)).Distinct())
        {
            addresses.Add((a.ToString(), a));
        }

        var listen = ToolKit.Combo("Listen address", addresses.Select(a => a.Label), 0, 280);
        var udp = new CheckBox { Content = "UDP", IsChecked = true };
        var udpPort = ToolKit.Number(514, 1, 65535, "UDP port");
        var tcp = new CheckBox { Content = "TCP", IsChecked = true };
        var tcpPort = ToolKit.Number(514, 1, 65535, "TCP port");
        var historyLimit = ToolKit.Number(10_000, 100, 200_000, "Messages kept");
        var minSeverity = ToolKit.Combo("Minimum severity", SyslogMessage.SeverityNames.Select((n, i) => $"{i} {n}"), 7, 170);
        var hostFilter = ToolKit.Text("Source or host contains", "source / host", 170);
        var textFilter = ToolKit.Text("Message contains", "text", 220);
        var pause = new Avalonia.Controls.Primitives.ToggleButton { Content = "Pause View" };
        ToolTip.SetTip(pause, "Freezes the list; messages are still received and kept.");

        var f = new Form();
        f.Add("Listen On", listen);
        f.Add("Protocols / Ports", Ui.Row(udp, udpPort, tcp, tcpPort));
        f.Add("History", historyLimit);
        f.Full(Form.Hint("Receives only: nothing is answered, forwarded or saved unless you export. TCP accepts RFC 6587 octet counting and newline framing. "
                         + "IPMaster never changes firewall settings; Windows Firewall may block or ask about other computers' traffic. Ports below 1024 need "
                         + "administrator rights on Linux and macOS (use e.g. 1514)."));
        var error = new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };
        f.Full(error);

        var grid = new DataGrid { ItemsSource = _rows, IsReadOnly = true, AutoGenerateColumns = false, CanUserReorderColumns = true, SelectionMode = DataGridSelectionMode.Single };
        void Col(string header, string path, double width) => grid.Columns.Add(new DataGridTextColumn { Header = header, Binding = new Binding(path), Width = new DataGridLength(width) });
        Col("Received", nameof(Row.Received), 110);
        Col("Source", nameof(Row.Source), 120);
        Col("Proto", nameof(Row.Transport), 82);
        Col("Facility", nameof(Row.Facility), 90);
        Col("Severity", nameof(Row.Severity), 115);
        Col("Host", nameof(Row.Host), 130);
        Col("App", nameof(Row.App), 110);
        grid.Columns.Add(new DataGridTextColumn { Header = "Message", Binding = new Binding(nameof(Row.Message)), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        Avalonia.Automation.AutomationProperties.SetName(grid, "Messages");
        var details = ToolKit.ReportBox("Message details");
        details.Height = 130;
        grid.SelectionChanged += (_, _) =>
        {
            if (grid.SelectedItem is not Row { M: var m }) return;
            details.Text = string.Join('\n',
                $"Received {m.ReceivedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss.fff} from {m.Source} over {m.Transport}; format {m.Format}{(m.PriorityMissing ? " (no valid PRI: user.notice assumed)" : "")}",
                $"Facility {m.Facility} ({m.FacilityName}), severity {m.Severity} ({m.SeverityName})",
                $"Timestamp: {(m.Timestamp is { } t ? t.ToString(m.Format == SyslogFormat.Rfc3164 ? "yyyy-MM-dd HH:mm:ss '(sender local time)'" : "yyyy-MM-dd HH:mm:ss.FFFFFFzzz", CultureInfo.InvariantCulture) : "—")}",
                $"Host: {m.Host}  App: {m.AppName}  PID: {m.ProcId}  MsgID: {m.MsgId}",
                m.StructuredData.Length > 0 ? "Structured data: " + m.StructuredData : "Structured data: —",
                "", m.Message);
        };
        var counters = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) };
        Avalonia.Automation.AutomationProperties.SetName(counters, "Receiver counters");
        var filters = Ui.Row(minSeverity, hostFilter, textFilter, pause);
        filters.Margin = new Thickness(0, 0, 0, 6);
        var main = new DockPanel();
        DockPanel.SetDock(counters, Dock.Top);
        DockPanel.SetDock(filters, Dock.Top);
        DockPanel.SetDock(details, Dock.Bottom);
        details.Margin = new Thickness(0, 6, 0, 0);
        main.Children.Add(counters);
        main.Children.Add(filters);
        main.Children.Add(details);
        main.Children.Add(grid);

        bool Matches(SyslogMessage m)
        {
            if (m.Severity > minSeverity.SelectedIndex) return false;
            var h = hostFilter.Text?.Trim() ?? "";
            if (h.Length > 0 && !m.Source.Contains(h, StringComparison.OrdinalIgnoreCase) && !m.Host.Contains(h, StringComparison.OrdinalIgnoreCase)) return false;
            var t = textFilter.Text?.Trim() ?? "";
            return t.Length == 0 || m.Message.Contains(t, StringComparison.OrdinalIgnoreCase) || m.AppName.Contains(t, StringComparison.OrdinalIgnoreCase);
        }

        var limit = 10_000;
        void Rebuild()
        {
            _rows.Clear();
            foreach (var m in _history.Where(Matches)) _rows.Add(new Row(m));
        }

        minSeverity.SelectionChanged += (_, _) => Rebuild();
        hostFilter.TextChanged += (_, _) => Rebuild();
        textFilter.TextChanged += (_, _) => Rebuild();
        pause.IsCheckedChanged += (_, _) =>
        {
            if (pause.IsChecked != true) Rebuild();
        };

        void UpdateCounters()
        {
            var s = _receiver?.Stats ?? _lastStats; // after Stop the final counters stay visible
            var listening = _receiver is null ? "Stopped" : "Listening" + (_receiver.UdpPort > 0 ? $" UDP {_receiver.UdpPort}" : "") + (_receiver.TcpPort > 0 ? $" TCP {_receiver.TcpPort}" : "");
            counters.Text = $"{listening}  ·  received {s?.Received ?? 0:N0}  ·  kept {_history.Count:N0} (oldest removed: {_evicted:N0})  ·  shown {_rows.Count:N0}"
                            + $"  ·  dropped (queue full) {s?.Dropped ?? 0:N0}  ·  oversized {s?.Oversized ?? 0:N0}  ·  TCP connections {s?.TcpConnections ?? 0}"
                            + (s is { RejectedConnections: > 0 } ? $" (rejected {s.RejectedConnections:N0})" : "");
        }

        // batched UI updates: drain the bounded queue at most every 250 ms
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        timer.Tick += (_, _) =>
        {
            if (_receiver is null) return;
            var added = 0;
            while (added < MaxDrainPerTick && _receiver.Messages.TryRead(out var m))
            {
                added++;
                _history.Enqueue(m);
                var removed = _history.Count > limit ? _history.Dequeue() : null;
                if (removed is not null) _evicted++;
                if (pause.IsChecked == true) continue;
                if (removed is not null && _rows.Count > 0 && ReferenceEquals(_rows[0].M, removed)) _rows.RemoveAt(0);
                if (Matches(m)) _rows.Add(new Row(m));
            }

            UpdateCounters();
        };

        Button? startButton = null;
        Button? stop = null;
        stop = Ui.Button("Stop", async () =>
        {
            timer.Stop();
            if (_receiver is { } r)
            {
                _receiver = null;
                await r.DisposeAsync(); // closes sockets: the ports are free again
                _lastStats = r.Stats;
            }

            status.Text = "Stopped; the ports are released.";
            UpdateCounters();
            SetRunning(false);
        });
        startButton = Ui.Button("Start", () =>
        {
            error.Text = "";
            if (udp.IsChecked != true && tcp.IsChecked != true)
            {
                error.Text = "Enable UDP, TCP or both.";
                return Task.CompletedTask;
            }

            limit = (int)(historyLimit.Value ?? 10_000);
            var o = new SyslogListenOptions
            {
                Address = addresses[Math.Max(0, listen.SelectedIndex)].Address, EnableUdp = udp.IsChecked == true, EnableTcp = tcp.IsChecked == true,
                UdpPort = (int)(udpPort.Value ?? 514), TcpPort = (int)(tcpPort.Value ?? 514),
            };
            try
            {
                _receiver = SyslogReceiver.Start(o);
            }
            catch (SocketException ex)
            {
                error.Text = ex.SocketErrorCode switch
                {
                    SocketError.AddressAlreadyInUse => "The port is already in use by another program (for example another syslog server).",
                    SocketError.AccessDenied => "Access denied: the port needs administrator rights here (ports below 1024 on Linux/macOS), or is reserved.",
                    SocketError.AddressNotAvailable => "That address is not assigned to this computer.",
                    _ => $"{ex.SocketErrorCode}: {ex.Message}",
                };
                return Task.CompletedTask;
            }

            timer.Start();
            status.Text = "Listening.";
            UpdateCounters();
            SetRunning(true);
            return Task.CompletedTask;
        }, accent: true);
        void SetRunning(bool running)
        {
            startButton!.IsEnabled = !running;
            stop!.IsEnabled = running;
            listen.IsEnabled = udp.IsEnabled = tcp.IsEnabled = udpPort.IsEnabled = tcpPort.IsEnabled = historyLimit.IsEnabled = !running;
        }

        SetRunning(false);
        var clear = Ui.Button("Clear", () =>
        {
            _history.Clear();
            _rows.Clear();
            _evicted = 0;
            details.Text = "";
            UpdateCounters();
            return Task.CompletedTask;
        });
        var exportCsv = Ui.Button("Export CSV…", () =>
        {
            using var w = new StringWriter(CultureInfo.InvariantCulture);
            CsvExporter.WriteRow(w, ["received_utc", "source", "transport", "facility", "severity", "format", "timestamp", "host", "app", "procid", "msgid", "structured_data", "message"], ',', true);
            foreach (var m in _history.Where(Matches))
            {
                CsvExporter.WriteRow(w, [m.ReceivedUtc.ToString("O", CultureInfo.InvariantCulture), m.Source, m.Transport, m.FacilityName, m.SeverityName, m.Format.ToString(),
                    m.Timestamp?.ToString("O", CultureInfo.InvariantCulture) ?? "", m.Host, m.AppName, m.ProcId, m.MsgId, m.StructuredData, m.Message], ',', true);
            }

            return ToolKit.SaveTextAsync(this, w.ToString(), "syslog.csv");
        });
        ToolTip.SetTip(exportCsv, "Exports the kept messages that match the current filters.");
        var actions = Ui.Row(startButton, stop, clear, exportCsv);
        Content = ToolKit.Layout(f.Grid, actions, main, status);
        UpdateCounters();
        Closing += async (_, _) =>
        {
            timer.Stop();
            if (_receiver is { } r)
            {
                _receiver = null;
                await r.DisposeAsync();
            }
        };
    }
}
