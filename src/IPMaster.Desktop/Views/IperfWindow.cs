using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using IPMaster.Core.Network;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Measured interval throughput per direction; points only where iperf reported an interval (no interpolation).</summary>
internal sealed class IperfChart : Styling.ThemedControl
{
    public IperfRun? Run { get; set; }

    public double Seconds { get; set; } = 10;

    /// <summary>Text drawn over the plot: "Ready", "Stopped", "Failed: …".</summary>
    public string Caption { get; set; } = "Ready";

    public bool Failed { get; set; }

    public override void Render(DrawingContext context)
    {
        var b = Bounds;
        if (b.Width < 80 || b.Height < 50) return;
        const double left = 70, bottom = 22, top = 10, right = 12;
        var plot = new Rect(left, top, b.Width - left - right, b.Height - top - bottom);
        var text = Brush(Styling.Theme.Keys.ChartText);
        context.FillRectangle(Brush(Styling.Theme.Keys.ChartSurface), plot);
        var up = Run?.Series(true) ?? [];
        var down = Run?.Series(false) ?? [];
        var maxT = Math.Max(Seconds, up.Concat(down).Select(i => i.End).DefaultIfEmpty(0).Max());
        var peak = up.Concat(down).Select(i => i.BitsPerSecond).DefaultIfEmpty(0).Max();
        var max = Nice(Math.Max(peak * 1.1, 1e6));
        FormattedText Label(string s, IBrush brush, double size = 11) => new(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, size, brush);
        var grid = Pen(Styling.Theme.Keys.ChartGrid, 1);
        for (var k = 0; k <= 4; k++)
        {
            var y = plot.Bottom - (k / 4.0 * plot.Height);
            context.DrawLine(grid, new Point(plot.Left, y), new Point(plot.Right, y));
            var t = Label(Iperf.Rate(max * k / 4).Replace("bps", "", StringComparison.Ordinal).Trim(), text);
            context.DrawText(t, new Point(left - t.Width - 6, y - (t.Height / 2)));
        }

        var step = maxT <= 12 ? 2 : maxT <= 30 ? 5 : maxT <= 120 ? 20 : Math.Ceiling(maxT / 6 / 60) * 60;
        for (var s = 0.0; s <= maxT + 0.001; s += step)
        {
            var x = plot.Left + (s / maxT * plot.Width);
            var t = Label(s.ToString("0", CultureInfo.InvariantCulture) + (s == 0 ? "" : "s"), text);
            context.DrawText(t, new Point(Math.Min(x - (t.Width / 2), plot.Right - t.Width), plot.Bottom + 4));
        }

        var unit = Label(Iperf.Rate(max).Split(' ')[^1], text);
        context.DrawText(unit, new Point(4, plot.Top - 2));
        double X(double t) => plot.Left + (t / maxT * plot.Width);
        double Y(double v) => plot.Bottom - (v / max * plot.Height);
        void Series(IReadOnlyList<IperfInterval> s, string key)
        {
            if (s.Count == 0) return;
            var pen = Pen(key, 2);
            var geometry = new StreamGeometry();
            using (var g = geometry.Open())
            {
                g.BeginFigure(new Point(X(s[0].Start), Y(s[0].BitsPerSecond)), false);
                foreach (var i in s) g.LineTo(new Point(X(i.End), Y(i.BitsPerSecond))); // one point per measured interval end
            }

            context.DrawGeometry(null, pen, geometry);
            foreach (var i in s) context.DrawEllipse(Brush(key), null, new Point(X(i.End), Y(i.BitsPerSecond)), 2.5, 2.5);
        }

        Series(up, Styling.Theme.Keys.Series1);
        Series(down, Styling.Theme.Keys.Series2);
        if (up.Count > 0 && down.Count > 0)
        {
            var l1 = Label("■ Upload", Brush(Styling.Theme.Keys.Series1));
            var l2 = Label("■ Download", Brush(Styling.Theme.Keys.Series2));
            context.DrawText(l1, new Point(plot.Right - l1.Width - l2.Width - 16, plot.Top + 4));
            context.DrawText(l2, new Point(plot.Right - l2.Width - 6, plot.Top + 4));
        }

        if (Caption.Length > 0)
        {
            var c = Label(Caption, Failed ? Brush(Styling.Theme.Keys.Error) : text, 13);
            var at = up.Count + down.Count == 0 ? new Point(plot.Center.X - (c.Width / 2), plot.Center.Y - (c.Height / 2)) : new Point(plot.Left + 8, plot.Top + 4);
            context.DrawText(c, at);
        }
    }

    /// <summary>1, 2, 2.5 or 5 × 10^n at or above <paramref name="v"/> (so the axis labels stay short).</summary>
    internal static double Nice(double v)
    {
        var p = Math.Pow(10, Math.Floor(Math.Log10(v)));
        foreach (var m in new[] { 1, 2, 2.5, 5, 10 })
        {
            if (m * p >= v) return m * p;
        }

        return 10 * p;
    }
}

/// <summary>
/// Tools → iPerf Network Performance (D-108). Runs an installed iperf3 or iperf2 as a child process (argument lists only),
/// shows its measured intervals live and its own final report. Nothing starts without the Start action; Stop and closing
/// the window end only the process this window started.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "The engine process is stopped and disposed when the window closes.")]
internal sealed class IperfWindow : Window
{
    internal sealed record ServerTest(string Time, string Client, string Protocol, string Direction, string Throughput, string Transferred);

    private static readonly string[] Protocols = ["TCP", "UDP"];
    private static readonly string[] Directions = ["Upload", "Download", "Bidirectional"];
    private static readonly int[] QuickStreams = [1, 2, 4, 8, 16, 32, 64];

    private readonly MainWindowViewModel? _vm;
    private readonly IIperfService _service;
    private readonly INetworkAdapterProvider? _adapters;
    private readonly List<IperfEngine> _engines = [];
    private readonly ComboBox _engine = ToolKit.Combo("Engine", [], -1, 460);
    private readonly TextBlock _engineNote = new() { TextWrapping = TextWrapping.Wrap, Classes = { Styling.Theme.Classes.Hint } };
    private readonly RadioButton _client = new() { Content = "Client", GroupName = "iperfMode", IsChecked = true };
    private readonly RadioButton _server = new() { Content = "Server", GroupName = "iperfMode" };
    private readonly TextBox _host = ToolKit.Text("Server", "host name, IPv4 or IPv6 address", 300);
    private readonly NumericUpDown _port = ToolKit.Number(5201, 1, 65535, "Port", 110);
    private readonly ComboBox _protocol = ToolKit.Combo("Protocol", Protocols, 0, 110);
    private readonly ComboBox _direction = ToolKit.Combo("Direction", Directions, 0, 150);
    private readonly NumericUpDown _seconds = ToolKit.Number(10, 1, 86_400, "Duration in seconds", 110);
    private readonly NumericUpDown _streams = ToolKit.Number(4, 1, Iperf.MaxStreams, "Parallel streams", 110);
    private readonly ComboBox _preset = ToolKit.Combo("Preset", Iperf.Presets.Select(p => p.Name), 0, 120);
    private readonly TextBox _udpRate = ToolKit.Text("UDP target rate per stream", "100M", 110, "100M");
    private readonly Control _udpRow;
    private Control[]? _udpPairs;
    private readonly TextBox _window = ToolKit.Text("Window size", "OS default, e.g. 4M", 130);
    private readonly NumericUpDown _omit = ToolKit.Number(0, 0, 600, "Omit seconds", 110);
    private readonly NumericUpDown _interval = ToolKit.Number(1, 1, 60, "Report interval in seconds", 110);
    private readonly ComboBox _bind = new() { Width = 360 };
    private readonly TextBox _congestion = ToolKit.Text("TCP congestion control", "e.g. bbr, cubic", 130);
    private readonly CheckBox _zeroCopy = new() { Content = "Zero-copy (-Z)" };
    private readonly Control[] _linuxOnly;
    private readonly CheckBox _serverUdp = new() { Content = "UDP server (iperf2)" };
    private readonly ComboBox _serverBind = new() { Width = 360 };
    private readonly NumericUpDown _serverPort = ToolKit.Number(5201, 1, 65535, "Server port", 110);
    private readonly StackPanel _clientPanel;
    private readonly StackPanel _serverPanel;
    private readonly Button _start;
    private readonly Button _stop;
    private readonly TextBlock _state = new() { VerticalAlignment = VerticalAlignment.Center, FontWeight = FontWeight.SemiBold };
    private readonly TextBlock _error = new() { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _current = new() { FontSize = 34, FontWeight = FontWeight.SemiBold, HorizontalAlignment = HorizontalAlignment.Center };
    private readonly TextBlock _currentLabel = new() { HorizontalAlignment = HorizontalAlignment.Center, Classes = { Styling.Theme.Classes.Label } };
    private readonly IperfChart _chart = new() { MinHeight = 140 };
    private readonly Dictionary<string, (TextBlock Label, TextBlock Value)> _metrics = [];
    private readonly ObservableCollection<ServerTest> _serverTests = [];
    private readonly DataGrid _serverGrid;
    private readonly Grid _clientResults;
    private Control[] _clientExports = [];
    private readonly StringBuilder _stderr = new();
    private readonly List<string> _raw = [];
    private readonly StringBuilder _buffer = new();
    private IIperfProcess? _process;
    private IperfRun _run = new();
    private IperfOptions _options = new();
    private IperfEngine? _runEngine;
    private DateTimeOffset _startedAt;
    private bool _stopRequested;
    private bool _timedOut;

    public IperfWindow(MainWindowViewModel? vm, IIperfService service, INetworkAdapterProvider? adapters)
    {
        _vm = vm;
        _service = service;
        _adapters = adapters;
        Title = "iPerf Network Performance";
        Width = 980;
        Height = 820;
        MinWidth = 760;
        MinHeight = 760; // inputs, live value, chart and metrics without overlap
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        // ---- engine ----
        var browse = Ui.Button("Browse…", BrowseAsync);
        ToolTip.SetTip(browse, "Choose an iperf3 or iperf2 executable. Nothing is downloaded.");
        _engine.SelectionChanged += (_, _) => EngineChanged();

        // ---- client ----
        var quick = new WrapPanel();
        foreach (var n in QuickStreams)
        {
            var b = new Button { Content = n.ToString(CultureInfo.InvariantCulture), Margin = new Thickness(0, 0, 4, 0), Padding = new Thickness(8, 2) };
            AutomationProperties.SetName(b, $"{n} streams");
            b.Click += (_, _) => _streams.Value = n;
            quick.Children.Add(b);
        }

        _preset.SelectionChanged += (_, _) =>
        {
            if (_preset.SelectedIndex is >= 0 and var i && i < Iperf.Presets.Count)
            {
                _streams.Value = Iperf.Presets[i].Streams;
                _seconds.Value = Iperf.Presets[i].Seconds;
            }
        };
        ToolTip.SetTip(_preset, "Suggests streams and duration. A preset does not limit TCP and does not guarantee the link speed.");
        _protocol.SelectionChanged += (_, _) =>
        {
            foreach (var c in _udpPairs ?? []) c.IsVisible = _protocol.SelectedIndex == 1;
        };
        var f = new Form();
        f.Add("Server", Ui.Row(_host, new TextBlock { Text = "Port", VerticalAlignment = VerticalAlignment.Center }, _port));
        f.Add("Protocol", Ui.Row(_protocol, new TextBlock { Text = "Direction", VerticalAlignment = VerticalAlignment.Center }, _direction,
            new TextBlock { Text = "Duration (s)", VerticalAlignment = VerticalAlignment.Center }, _seconds));
        f.Add("Streams", Ui.Row(_streams, quick, new TextBlock { Text = "Preset", VerticalAlignment = VerticalAlignment.Center }, _preset));
        var udpPair = f.AddPair("UDP rate", Ui.Row(_udpRate, new TextBlock { Text = "per stream (K, M, G suffix)", VerticalAlignment = VerticalAlignment.Center, Classes = { Styling.Theme.Classes.Hint } }));
        _udpRow = new Panel();
        _udpPairs = udpPair;
        foreach (var c in udpPair) c.IsVisible = false;
        var adv = new Form();
        adv.Add("Window", _window);
        adv.Add("Omit / Interval (s)", Ui.Row(_omit, _interval));
        adv.Add("Source address", _bind);
        var cc = adv.AddPair("Congestion", _congestion);
        _linuxOnly = [.. cc, adv.Full(_zeroCopy)];
        adv.Full(Form.Hint("A source address selects the local address; the operating system still chooses the route."));
        ToolTip.SetTip(_window, "Socket buffer / TCP window (-w). Suffix K, M or G (1024-based).");
        ToolTip.SetTip(_omit, "Seconds left out of the results at the start (TCP slow start), iperf3 only.");
        var advanced = new Expander { Header = "Advanced", Content = adv.Grid, HorizontalAlignment = HorizontalAlignment.Stretch };
        _clientPanel = new StackPanel { Spacing = Styling.Theme.SectionGap, Children = { f.Grid, advanced } };

        // ---- server ----
        var sf = new Form();
        sf.Add("Listen on", Ui.Row(_serverBind, new TextBlock { Text = "Port", VerticalAlignment = VerticalAlignment.Center }, _serverPort));
        sf.Full(_serverUdp);
        sf.Full(new TextBlock { Text = "All interfaces: the server accepts tests on every address of this computer. No firewall rule is created.", TextWrapping = TextWrapping.Wrap, Classes = { Styling.Theme.Classes.Hint } });
        _serverPanel = new StackPanel { Spacing = Styling.Theme.SectionGap, IsVisible = false, Children = { sf.Grid } };
        _client.IsCheckedChanged += (_, _) => ModeChanged();

        _start = Ui.Button("Start Test", StartAsync, accent: true);
        _stop = Ui.Button("Stop", () =>
        {
            StopProcess(user: true);
            return Task.CompletedTask;
        });
        _stop.IsEnabled = false;
        ToolTip.SetTip(_stop, "Ends the iperf process started by this window.");

        var top = new StackPanel
        {
            Spacing = Styling.Theme.SectionGap,
            Children =
            {
                Ui.Row(new TextBlock { Text = "Engine", VerticalAlignment = VerticalAlignment.Center }, _engine, browse),
                _engineNote,
                Ui.Row(new TextBlock { Text = "Mode", VerticalAlignment = VerticalAlignment.Center }, _client, _server),
                _clientPanel, _serverPanel, _error,
            },
        };

        // ---- results ----
        _clientResults = new Grid { ColumnDefinitions = new ColumnDefinitions("*,*,*,*"), RowDefinitions = new RowDefinitions("Auto,Auto,Auto,Auto"), ColumnSpacing = 12, RowSpacing = 2 };
        var names = new[] { "Average", "Peak", "Transferred", "Retransmits", "Sender", "Receiver", "Streams", "Duration" };
        for (var i = 0; i < names.Length; i++)
        {
            var label = new TextBlock { Text = names[i], Classes = { Styling.Theme.Classes.Label } };
            var value = new TextBlock { Text = "—", FontSize = 16, FontWeight = FontWeight.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis };
            Grid.SetColumn(label, i % 4);
            Grid.SetRow(label, i / 4 * 2);
            Grid.SetColumn(value, i % 4);
            Grid.SetRow(value, (i / 4 * 2) + 1);
            _clientResults.Children.Add(label);
            _clientResults.Children.Add(value);
            _metrics[names[i]] = (label, value);
        }

        _serverGrid = new DataGrid { ItemsSource = _serverTests, IsReadOnly = true, AutoGenerateColumns = false, CanUserSortColumns = true, CanUserResizeColumns = true, MinHeight = 120, IsVisible = false };
        AutomationProperties.SetName(_serverGrid, "Tests received by the server");
        void Col(string h, string p, DataGridLength w) => _serverGrid.Columns.Add(new DataGridTextColumn { Header = h, Binding = new Binding(p), Width = w, MinWidth = 60 });
        Col("Time", nameof(ServerTest.Time), new DataGridLength(90));
        Col("Client", nameof(ServerTest.Client), new DataGridLength(1, DataGridLengthUnitType.Star));
        Col("Protocol", nameof(ServerTest.Protocol), new DataGridLength(95));
        Col("Direction", nameof(ServerTest.Direction), new DataGridLength(110));
        Col("Throughput", nameof(ServerTest.Throughput), new DataGridLength(120));
        Col("Transferred", nameof(ServerTest.Transferred), new DataGridLength(110));

        var copy = ToolKit.CopyButton(this, () => _runEngine is null ? "" : Iperf.Summary(Info(), _run), "Copy Summary");
        var json = Ui.Button("Export JSON…", () => _runEngine is null ? Task.CompletedTask : ToolKit.SaveTextAsync(this, Iperf.Json(Info(), _run, _raw), $"iperf-{_startedAt:yyyyMMdd-HHmmss}.json"));
        var csv = Ui.Button("Export CSV…", () => _runEngine is null ? Task.CompletedTask : ToolKit.SaveTextAsync(this, Iperf.IntervalsCsv(_run), $"iperf-{_startedAt:yyyyMMdd-HHmmss}.csv"));
        var details = Ui.Button("Details…", ShowDetailsAsync);
        ToolTip.SetTip(details, "Engine command and error output.");
        var actions = Ui.Row(_start, _stop, _state);
        _clientExports = [copy, json, csv];
        var exports = Ui.Row(copy, json, csv, details);

        var main = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,*,Auto,Auto"), RowSpacing = 4 };
        void Put(Control c, int r)
        {
            Grid.SetRow(c, r);
            main.Children.Add(c);
        }

        Put(_currentLabel, 0);
        Put(_current, 1);
        Put(_chart, 2);
        Put(_serverGrid, 2);
        Put(new Border { Padding = new Thickness(0, Styling.Theme.SectionGap, 0, 0), Child = _clientResults }, 3);
        Put(new Border { Padding = new Thickness(0, Styling.Theme.SectionGap, 0, 0), Child = exports }, 4);
        Content = ToolKit.Layout(top, actions, main, ToolKit.StatusLine());

        FillBind();
        SetState(IperfState.Ready, "");
        ShowRun();
        Opened += async (_, _) => await DetectAsync();
        Closing += (_, _) => StopProcess(user: true); // never leave a client or server running
        Closed += (_, _) => _process?.Dispose();
    }

    internal IperfState State { get; private set; }

    internal IperfRun Run => _run;

    internal IReadOnlyList<ServerTest> ServerTests => _serverTests;

    internal void SetInputs(string host, int streams, IperfDirection direction, IperfProtocol protocol = IperfProtocol.Tcp, int seconds = 10)
    {
        _host.Text = host;
        _streams.Value = streams;
        _direction.SelectedIndex = (int)direction;
        _protocol.SelectedIndex = (int)protocol;
        _seconds.Value = seconds;
    }

    internal void UseServerMode() => _server.IsChecked = true;

    internal void SetEnginesForTest(IReadOnlyList<IperfEngine> list) => SetEngines(list);

    // ---------------- engine ----------------
    private async Task DetectAsync()
    {
        _engineNote.Text = "Detecting iperf…";
        var list = await Task.Run(() => _service.DetectAsync(_vm?.Settings.Tools.IperfExecutable ?? "", CancellationToken.None));
        SetEngines(list);
    }

    private void SetEngines(IReadOnlyList<IperfEngine> list)
    {
        _engines.Clear();
        _engines.AddRange(list);
        _engine.ItemsSource = _engines.Select(e => $"{e.Name} {e.VersionText} — {e.Path}").ToList();
        // Windows: prefer iperf2 (supported there by its project); elsewhere iperf3
        var preferred = OperatingSystem.IsWindows() ? _engines.FindIndex(e => e.Kind == IperfEngineKind.Iperf2) : _engines.FindIndex(e => e.Kind == IperfEngineKind.Iperf3);
        _engine.SelectedIndex = _engines.Count == 0 ? -1 : Math.Max(0, preferred);
        if (_engines.Count == 0)
        {
            _engineNote.Text = "No iperf3 or iperf2 found. Install one, then choose its executable with Browse.";
            Styling.Theme.SetState(_engineNote, Styling.Theme.Classes.Warning);
        }

        EngineChanged();
    }

    private IperfEngine? Engine => _engine.SelectedIndex >= 0 && _engine.SelectedIndex < _engines.Count ? _engines[_engine.SelectedIndex] : null;

    private void EngineChanged()
    {
        var e = Engine;
        if (e is null)
        {
            UpdateButtons();
            return;
        }

        Styling.Theme.SetState(_engineNote, null);
        var notes = new List<string>
        {
            e.LiveIntervals ? "Live intervals." : "Results at the end of the test (iperf3 3.17 or later shows them live).",
            e.Bidirectional ? "Bidirectional." : "No bidirectional mode.",
            e.MultiThreaded ? "Multi-threaded streams." : "Single-threaded streams (use iperf3 3.16 or later for high-speed tests).",
        };
        if (e.Kind == IperfEngineKind.Iperf3 && OperatingSystem.IsWindows()) notes.Insert(0, "iperf3 is not supported by ESnet on Windows; results can be lower than the link.");
        _engineNote.Text = string.Join(" ", notes);
        foreach (var port in new[] { _port, _serverPort })
        {
            if (port.Value is 5201 or 5001) port.Value = e.DefaultPort;
        }
        foreach (var c in _linuxOnly) c.IsVisible = e.CongestionControl;
        _omit.IsEnabled = e.Kind == IperfEngineKind.Iperf3;
        _serverUdp.IsVisible = e.Kind == IperfEngineKind.Iperf2;
        if (!e.Bidirectional && _direction.SelectedIndex == 2) _direction.SelectedIndex = 0;
        UpdateButtons();
    }

    private async Task BrowseAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Choose the iperf Executable", AllowMultiple = false });
        if (files.Count == 0 || files[0].TryGetLocalPath() is not { } path) return;
        var e = await _service.ProbeAsync(path, CancellationToken.None);
        if (e is null)
        {
            _error.Text = $"'{Path.GetFileName(path)}' is not iperf2 or iperf3 (it does not report an iperf version).";
            return;
        }

        _error.Text = "";
        if (_vm is not null) await _vm.UpdateSettingsAsync(s => s with { Tools = s.Tools with { IperfExecutable = path } });
        SetEngines([e, .. _engines.Where(x => x.Path != e.Path)]);
    }

    private void FillBind()
    {
        var items = new List<(string Text, string Address)> { ("Automatic (operating system)", "") };
        try
        {
            foreach (var a in _adapters?.GetAdapters() ?? [])
            {
                if (AdapterClassifier.Classify(a).Kind == AdapterKind.Virtual) continue; // hide virtual adapters
                var speed = a.SpeedBitsPerSecond > 0 ? " — " + Iperf.Rate(a.SpeedBitsPerSecond) : "";
                foreach (var addr in a.Addresses.Where(x => !x.IsLinkLocal)) items.Add(($"{a.Name}: {addr.Address}{speed}", addr.Address.ToString()));
            }
        }
        catch (System.Net.NetworkInformation.NetworkInformationException)
        {
        }

        foreach (var c in new[] { _bind, _serverBind })
        {
            c.ItemsSource = items.Select(i => i == items[0] && c == _serverBind ? ("All interfaces", "") : i).Select(i => i.Item1).ToList();
            c.Tag = items.Select(i => i.Address).ToList();
            c.SelectedIndex = 0;
        }

        AutomationProperties.SetName(_bind, "Source address");
        AutomationProperties.SetName(_serverBind, "Listen address");
    }

    private static string Address(ComboBox c) => c.Tag is List<string> l && c.SelectedIndex > 0 && c.SelectedIndex < l.Count ? l[c.SelectedIndex] : "";

    private void ModeChanged()
    {
        var client = _client.IsChecked == true;
        _clientPanel.IsVisible = client;
        _serverPanel.IsVisible = !client;
        _start.Content = client ? "Start Test" : "Start Server";
        _chart.IsVisible = client;
        _clientResults.IsVisible = client;
        _serverGrid.IsVisible = !client;
        _current.IsVisible = client;
        _currentLabel.IsVisible = client;
        foreach (var c in _clientExports) c.IsVisible = client;
    }
    // ---------------- run ----------------
    private IperfOptions ReadOptions(out string? error)
    {
        error = null;
        long? window = null;
        var w = (_window.Text ?? "").Trim();
        if (w.Length > 0)
        {
            window = ParseBytes(w);
            if (window is null) error = "Window: enter a size such as 512K or 4M.";
        }

        var udp = Iperf.ParseRate(_udpRate.Text ?? "");
        if (_protocol.SelectedIndex == 1 && udp is null) error ??= "UDP rate: enter a rate such as 100M or 2G (per stream).";
        return new IperfOptions
        {
            Server = (_host.Text ?? "").Trim(), Port = (int)((_client.IsChecked == true ? _port : _serverPort).Value ?? 5201), Protocol = (IperfProtocol)Math.Max(0, _protocol.SelectedIndex),
            Direction = (IperfDirection)Math.Max(0, _direction.SelectedIndex), Seconds = (int)(_seconds.Value ?? 10), Streams = (int)(_streams.Value ?? 1),
            UdpBitsPerStream = udp ?? 0, WindowBytes = window, OmitSeconds = (int)(_omit.Value ?? 0), IntervalSeconds = (int)(_interval.Value ?? 1),
            BindAddress = Address(_client.IsChecked == true ? _bind : _serverBind), Congestion = (_congestion.Text ?? "").Trim(), ZeroCopy = _zeroCopy.IsChecked == true,
        };
    }

    /// <summary>"4M" → 4 MiB (iperf's -w uses 1024-based K/M/G).</summary>
    internal static long? ParseBytes(string s)
    {
        var m = System.Text.RegularExpressions.Regex.Match(s.Trim(), @"^(\d+(?:\.\d+)?)\s*([kKmMgG]?)[bB]?$", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
        if (!m.Success || !double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var v)) return null;
        v *= m.Groups[2].Value.ToUpperInvariant() switch
        {
            "K" => 1024,
            "M" => 1024 * 1024,
            "G" => 1024.0 * 1024 * 1024,
            _ => 1,
        };
        return v is >= 1 and < 1e12 ? (long)v : null;
    }

    private async Task StartAsync()
    {
        if (_process is not null || Engine is not { } engine) return;
        var server = _client.IsChecked != true;
        var o = ReadOptions(out var parseError);
        var errors = Iperf.Validate(engine, o, server).ToList();
        if (parseError is not null) errors.Insert(0, parseError);
        _error.Text = string.Join(Environment.NewLine, errors);
        if (errors.Count > 0) return;
        if (!server && Iperf.NeedsRateWarning(o)
            && !await Dialogs.MessageAsync(this, "Start Test", $"This test can fill the link to {o.Server} and slow other traffic on it.\n\n{o.Streams} stream(s), {o.Seconds} s, {o.Protocol.ToString().ToUpperInvariant()}"
                + (o.Protocol == IperfProtocol.Udp ? $", {Iperf.Rate((double)o.UdpBitsPerStream * o.Streams)} in total" : "") + ".\n\nStart the test?", true))
        {
            return;
        }

        await RunAsync(engine, o, server);
    }

    internal async Task RunAsync(IperfEngine engine, IperfOptions o, bool server)
    {
        _options = o;
        _runEngine = engine;
        _run = new IperfRun();
        _raw.Clear();
        _buffer.Clear();
        _stderr.Clear();
        _stopRequested = false;
        _timedOut = false;
        _startedAt = DateTimeOffset.Now;
        if (server) _serverTests.Clear();
        _chart.Seconds = o.Seconds + o.OmitSeconds;
        SetState(IperfState.Preparing, "");
        var args = server ? Iperf.ServerArguments(engine, o.Port, o.BindAddress, _serverUdp.IsChecked == true) : Iperf.ClientArguments(engine, o);
        _stderr.Append("> ").Append(Path.GetFileName(engine.Path)).Append(' ').AppendLine(string.Join(' ', args));
        try
        {
            _process = _service.Start(engine, args, chunk => Dispatcher.UIThread.Post(() => OnStdout(chunk, server)), err => Dispatcher.UIThread.Post(() => _stderr.Append(err)));
        }
        catch (InvalidOperationException ex)
        {
            SetState(IperfState.Failed, ex.Message);
            return;
        }

        SetState(server ? IperfState.Running : IperfState.Connecting, server ? $"Listening on {(o.BindAddress.Length > 0 ? o.BindAddress : "all interfaces")}, port {o.Port}." : "");
        using var watchdog = new CancellationTokenSource();
        if (!server)
        {
            // the engine has its own connect timeout; this only ends a test that hangs after its duration
            _ = Task.Delay(TimeSpan.FromSeconds(o.Seconds + o.OmitSeconds + 60), watchdog.Token).ContinueWith(t =>
            {
                if (t.IsCompletedSuccessfully)
                {
                    _timedOut = true;
                    _process?.Stop();
                }
            }, TaskScheduler.Default);
        }

        int code;
        try
        {
            code = await _process.Completion;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            code = -1;
            _stderr.AppendLine(ex.Message);
        }
        finally
        {
            await watchdog.CancelAsync();
        }

        await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Background); // pending output first
        if (!server) Flush();
        _process.Dispose();
        _process = null;
        Finish(code, server);
    }

    private void OnStdout(string chunk, bool server)
    {
        if (_runEngine is null) return;
        _buffer.Append(chunk);
        if (_buffer.Length > 16 * 1024 * 1024) _buffer.Clear(); // a report that never closes: dropped, not parsed (bounded)
        if (_runEngine.Kind == IperfEngineKind.Iperf3)
        {
            var (objects, rest) = Iperf.SplitJson(_buffer.ToString());
            _buffer.Clear().Append(rest);
            foreach (var o in objects)
            {
                if (_raw.Count < 100_000) _raw.Add(o);
                if (server)
                {
                    var r = new IperfRun();
                    if (Iperf.ApplyJson(r, o) && r.Started) AddServerTest(r);
                }
                else
                {
                    Iperf.ApplyJson(_run, o);
                }
            }
        }
        else
        {
            var text = _buffer.ToString();
            var last = text.LastIndexOf('\n');
            if (last < 0) return;
            _buffer.Clear().Append(text[(last + 1)..]);
            foreach (var line in text[..last].Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) Iperf2Line(line, server);
        }

        if (!server && _run.Started && State == IperfState.Connecting) SetState(IperfState.Running, "");
        ShowRun();
    }

    private void Iperf2Line(string line, bool server)
    {
        if (_raw.Count < 100_000) _raw.Add(line);
        if (server)
        {
            var r = new IperfRun();
            if (Iperf.ApplyIperf2Csv(r, line, 1, 1, upload: false) && r.Ended) AddServerTest(r);
            else if (!Iperf.ApplyIperf2Csv(new IperfRun(), line, 1, 1, false)) _stderr.AppendLine(line);
            return;
        }

        if (!Iperf.ApplyIperf2Csv(_run, line, _options.Streams, _options.IntervalSeconds, _options.Direction != IperfDirection.Download)) _stderr.AppendLine(line); // e.g. "connect failed"
    }

    private void Flush()
    {
        if (_buffer.Length == 0 || _runEngine is null) return;
        var rest = _buffer.ToString();
        _buffer.Clear();
        if (_runEngine.Kind == IperfEngineKind.Iperf2) Iperf2Line(rest, false);
        else _stderr.AppendLine(rest.Length > 2000 ? rest[..2000] + "…" : rest); // incomplete JSON: kept for Details only
    }

    private void AddServerTest(IperfRun r)
    {
        var c = r.Connections.FirstOrDefault();
        var res = r.Results.FirstOrDefault();
        _serverTests.Insert(0, new ServerTest(DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture), c is null ? "—" : $"{c.RemoteHost}:{c.RemotePort}",
            r.Protocol.Length > 0 ? r.Protocol : "—", r.Reverse is { } rev ? rev ? "Server sends" : "Client sends" : "—",
            Iperf.Rate(res?.ReceiverBitsPerSecond ?? res?.SenderBitsPerSecond), Iperf.Bytes(res?.ReceiverBytes ?? res?.SenderBytes)));
        while (_serverTests.Count > 500) _serverTests.RemoveAt(_serverTests.Count - 1);
        SetState(IperfState.Running, $"Last test from {(c is null ? "a client" : c.RemoteHost)}. {_serverTests.Count} test(s).");
    }

    /// <summary>The outcome from what the engine reported, not from its exit code alone.</summary>
    private void Finish(int code, bool server)
    {
        var errText = LastErrorLine();
        if (server)
        {
            SetState(_stopRequested ? IperfState.Stopped : IperfState.Failed, _stopRequested ? "Server stopped." : $"The server ended: {(errText.Length > 0 ? errText : $"exit {code}")}");
            return;
        }

        if (_timedOut) SetState(IperfState.Failed, "Timed out. The engine did not finish.");
        else if (_stopRequested) SetState(IperfState.Stopped, $"Stopped. {_run.Intervals.Count} interval(s) kept.");
        else if (_run.Error.Length > 0) SetState(IperfState.Failed, Short(_run.Error));
        else if (_run.Ended && _run.Results.Count > 0) SetState(IperfState.Completed, "");
        else SetState(IperfState.Failed, errText.Length > 0 ? errText : $"Incomplete result (exit {code}).");
        ShowRun();
    }

    private string LastErrorLine() =>
        _stderr.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault(l => !l.StartsWith('>') && l.Any(char.IsLetter)) is { } l ? Short(l) : "";

    private static string Short(string s) => s.Length > 200 ? s[..200] + "…" : s;

    internal void StopProcess(bool user)
    {
        if (_process is null) return;
        _stopRequested = user;
        SetState(IperfState.Stopping, "");
        _process.Stop();
    }

    // ---------------- display ----------------
    private void SetState(IperfState s, string detail)
    {
        State = s;
        _state.Text = s + (detail.Length > 0 ? $": {detail}" : "");
        Styling.Theme.SetState(_state, s switch
        {
            IperfState.Completed => Styling.Theme.Classes.Success,
            IperfState.Failed => Styling.Theme.Classes.Error,
            IperfState.Stopped => Styling.Theme.Classes.Warning,
            IperfState.Preparing or IperfState.Connecting or IperfState.Running or IperfState.Stopping => Styling.Theme.Classes.Info,
            _ => null,
        });
        _chart.Caption = s switch
        {
            IperfState.Ready => "Ready",
            IperfState.Connecting or IperfState.Preparing => "Connecting…",
            IperfState.Stopped => "Stopped",
            IperfState.Failed => "Failed" + (detail.Length > 0 ? ": " + detail : ""),
            IperfState.Running when _runEngine is { LiveIntervals: false } => "Running. Results at the end.",
            _ => "",
        };
        _chart.Failed = s == IperfState.Failed;
        _chart.InvalidateVisual();
        UpdateButtons();
    }

    private void UpdateButtons()
    {
        var busy = _process is not null;
        _start.IsEnabled = !busy && Engine is not null;
        _stop.IsEnabled = busy;
        _engine.IsEnabled = _client.IsEnabled = _server.IsEnabled = _clientPanel.IsEnabled = _serverPanel.IsEnabled = !busy;
    }

    private void ShowRun()
    {
        _chart.Run = _run;
        _chart.InvalidateVisual();
        var udp = _options.Protocol == IperfProtocol.Udp;
        var bidir = _run.HasDirection(true) && _run.HasDirection(false);
        var main = _run.HasDirection(true) || !_run.HasDirection(false); // upload unless only download exists
        var lastUp = _run.Series(true).LastOrDefault();
        var lastDown = _run.Series(false).LastOrDefault();
        _currentLabel.Text = State is IperfState.Running or IperfState.Connecting ? "LIVE THROUGHPUT" : "THROUGHPUT";
        _current.Text = bidir ? $"↑ {Iperf.Rate(lastUp?.BitsPerSecond)}   ↓ {Iperf.Rate(lastDown?.BitsPerSecond)}"
            : (main ? lastUp : lastDown) is { } last ? Iperf.Rate(last.BitsPerSecond) : "—";
        if (State is IperfState.Completed or IperfState.Stopped && !bidir) _current.Text = Iperf.Rate(_run.Average(main)) is var avg && avg != "N/A" ? avg : _current.Text;
        string Pair(Func<bool, string> f) => bidir ? $"↑ {f(true)}  ↓ {f(false)}" : f(main);
        void Set(string key, string value, string? label = null)
        {
            _metrics[key].Value.Text = value;
            ToolTip.SetTip(_metrics[key].Value, value);
            if (label is not null) _metrics[key].Label.Text = label;
        }

        var any = _run.Intervals.Count > 0 || _run.Results.Count > 0;
        Set("Average", any ? Pair(u => Iperf.Rate(_run.Average(u))) : "—");
        Set("Peak", any ? Pair(u => Iperf.Rate(_run.Peak(u))) : "—");
        Set("Transferred", any ? Pair(u => Iperf.Bytes(_run.Transferred(u))) : "—");
        if (udp)
        {
            Set("Retransmits", any ? Pair(u => _run.Result(u)?.JitterMs is { } j ? $"{j:0.###} ms" : "N/A") : "—", "Jitter");
            Set("Sender", any ? Pair(u => _run.Result(u) is { LostPackets: { } lp, Packets: { } pk } r ? $"{r.LostPercent ?? (pk > 0 ? 100.0 * lp / pk : 0):0.##} % ({lp}/{pk})" : "N/A") : "—", "Packet Loss");
        }
        else
        {
            Set("Retransmits", any ? Pair(u => _run.Result(u)?.Retransmits?.ToString(CultureInfo.InvariantCulture) ?? (_run.Series(u).Any(i => i.Retransmits is not null) ? _run.Series(u).Sum(i => i.Retransmits ?? 0).ToString(CultureInfo.InvariantCulture) : "N/A")) : "—", "Retransmits");
            Set("Sender", any ? Pair(u => Iperf.Rate(_run.Result(u)?.SenderBitsPerSecond)) : "—", "Sender");
        }

        Set("Receiver", any ? Pair(u => Iperf.Rate(_run.Result(u)?.ReceiverBitsPerSecond)) : "—");
        Set("Streams", _runEngine is null ? "—" : (_run.Streams ?? _options.Streams).ToString(CultureInfo.InvariantCulture));
        var elapsed = _run.Intervals.Select(i => i.End).DefaultIfEmpty(0).Max();
        Set("Duration", _runEngine is null ? "—" : $"{(_run.Results.Count > 0 ? _run.Results.Max(r => r.Seconds) : elapsed):0.#} of {_options.Seconds} s");
    }

    private Iperf.ReportInfo Info() => new(_startedAt, _runEngine!, _options, State, _state.Text ?? "");

    private async Task ShowDetailsAsync()
    {
        var d = ToolKit.NewToolWindow("iPerf Details", 760, 460);
        var box = ToolKit.ReportBox("Engine output");
        box.Text = _stderr.Length > 0 ? _stderr.ToString() : "No engine output yet.";
        var close = Ui.Button("Close", () =>
        {
            d.Close();
            return Task.CompletedTask;
        });
        close.IsCancel = true;
        d.Content = ToolKit.Layout(new Control(), Ui.Row(ToolKit.CopyButton(d, () => box.Text ?? ""), close), box, ToolKit.StatusLine());
        await d.ShowDialog(this);
    }
}
