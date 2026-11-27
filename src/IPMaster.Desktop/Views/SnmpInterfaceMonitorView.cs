using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Results;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>In/out bit/s over time; gaps where no rate exists (first reading, reset, restart, failed poll).</summary>
internal sealed class TrafficChart : Styling.ThemedControl
{
    public IReadOnlyList<InterfaceRate> Rates { get; set; } = [];

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(30);

    public override void Render(DrawingContext context)
    {
        var b = Bounds;
        if (b.Width < 60 || b.Height < 40) return;
        const double left = 78, bottom = 20, top = 8, right = 8;
        var plot = new Rect(left, top, b.Width - left - right, b.Height - top - bottom);
        var text = Brush(Styling.Theme.Keys.ChartText);
        context.FillRectangle(Brush(Styling.Theme.Keys.ChartSurface), plot);
        var now = DateTimeOffset.UtcNow;
        var from = now - Window;
        var visible = Rates.Where(r => r.At >= from).ToList();
        var max = Math.Max(1000, visible.SelectMany(r => new[] { r.InBitsPerSecond ?? 0, r.OutBitsPerSecond ?? 0 }).DefaultIfEmpty(0).Max() * 1.1);
        double X(DateTimeOffset t) => plot.Left + (t - from).TotalSeconds / Window.TotalSeconds * plot.Width;
        double Y(double v) => plot.Bottom - v / max * plot.Height;
        FormattedText Label(string s, IBrush brush) => new(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, 11, brush);
        context.DrawText(Label(InterfaceRates.FormatBits(max), text), new Point(4, plot.Top));
        context.DrawText(Label("0", text), new Point(4, plot.Bottom - 12));
        context.DrawText(Label($"−{Window.TotalMinutes:0} min", text), new Point(plot.Left, plot.Bottom + 4));
        context.DrawText(Label("in", Brush(Styling.Theme.Keys.Series1)), new Point(plot.Right - 60, plot.Bottom + 4));
        context.DrawText(Label("out", Brush(Styling.Theme.Keys.Series2)), new Point(plot.Right - 30, plot.Bottom + 4));
        void Series(Func<InterfaceRate, double?> value, IBrush brush)
        {
            var pen = new Pen(brush, 1.5);
            Point? prev = null;
            foreach (var r in visible)
            {
                if (value(r) is not { } v)
                {
                    prev = null; // a gap: never bridge a reset or a failed poll
                    continue;
                }

                var p = new Point(X(r.At), Y(v));
                if (prev is { } q) context.DrawLine(pen, q, p);
                else context.DrawEllipse(brush, null, p, 1.5, 1.5);
                prev = p;
            }
        }

        Series(r => r.InBitsPerSecond, Brush(Styling.Theme.Keys.Series1));
        Series(r => r.OutBitsPerSecond, Brush(Styling.Theme.Keys.Series2));
    }
}

/// <summary>
/// Tools → SNMP Interface Monitor (D-091): IF-MIB interfaces, utilisation, errors and discards of selected interfaces,
/// polled read-only at a chosen interval. Rates use the measured interval (agent sysUpTime); counter resets and agent
/// restarts leave a gap instead of a spike.
/// </summary>
internal sealed class SnmpInterfaceMonitorView : UserControl, IDisposable
{
    private Action? _dispose;

    private const int MaxMonitored = 64;
    private const int MaxHistory = 3600;

    private sealed record IfRow(SnmpInterface I)
    {
        public int Index => I.Index;

        public string Name => I.Label;

        public string Description => I.Description;

        public string Alias => I.Alias;

        public string Speed => I.SpeedBitsPerSecond > 0 ? InterfaceRates.FormatBits(I.SpeedBitsPerSecond).Replace("/s", "", StringComparison.Ordinal) : "";

        public string Status => $"{I.AdminStatus}/{I.OperStatus}";

        public string Counters => I.HighCapacity ? "64-bit" : "32-bit";
    }

    private sealed record StatRow(SnmpInterface I, InterfaceRate? R, InterfaceCounters? C)
    {
        public string Name => I.Label + (I.Alias.Length > 0 ? $" ({I.Alias})" : "");

        public string Oper => C?.OperStatus ?? "";

        public string In => InterfaceRates.FormatBits(R?.InBitsPerSecond);

        public string Out => InterfaceRates.FormatBits(R?.OutBitsPerSecond);

        public string InUtil => R?.InUtilisation is { } u ? $"{u:0.0} %" : "—";

        public string OutUtil => R?.OutUtilisation is { } u ? $"{u:0.0} %" : "—";

        public string Errors => R is { InErrorsPerSecond: { } a, OutErrorsPerSecond: { } b } ? $"{a:0.##} / {b:0.##}" : "—";

        public string Discards => R is { InDiscardsPerSecond: { } a, OutDiscardsPerSecond: { } b } ? $"{a:0.##} / {b:0.##}" : "—";

        public string Interval => R is { Elapsed.TotalSeconds: > 0 } r ? $"{r.Elapsed.TotalSeconds:0.#} s" : "";

        public string Note => R is null ? "" : R.Status is RateStatus.Ok ? "" : R.Note;
    }

    private readonly Dictionary<int, InterfaceCounters> _last = [];
    private readonly Dictionary<int, List<InterfaceRate>> _history = [];
    private Action? _stopPoll;

    public SnmpInterfaceMonitorView(string? target = null)
    {
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var agent = new SnmpTargetForm(target);
        var interval = ToolKit.Number(10, 1, 3600, "Interval in seconds", 70);
        var timeout = ToolKit.Number(3, 1, 60, "Timeout in seconds", 60);
        var interfaces = new ObservableCollection<IfRow>();
        var stats = new ObservableCollection<StatRow>();
        IReadOnlyList<SnmpInterface> monitored = [];
        Func<CancellationToken, Task<(SnmpTarget? Target, string? Error)>>? resolve = null;

        var ifGrid = Ui.Grid(("#", nameof(IfRow.Index), 50), ("Name", nameof(IfRow.Name), 150), ("Description", nameof(IfRow.Description), 0),
            ("Alias", nameof(IfRow.Alias), 180), ("Speed", nameof(IfRow.Speed), 100), ("Admin/Oper", nameof(IfRow.Status), 110), ("Counters", nameof(IfRow.Counters), 80));
        ifGrid.ItemsSource = interfaces;
        Avalonia.Automation.AutomationProperties.SetName(ifGrid, "Interfaces");
        var statGrid = Ui.Grid(("Interface", nameof(StatRow.Name), 220), ("Oper", nameof(StatRow.Oper), 85), ("In", nameof(StatRow.In), 110), ("Out", nameof(StatRow.Out), 110),
            ("In %", nameof(StatRow.InUtil), 85), ("Out %", nameof(StatRow.OutUtil), 85), ("Errors in/out per s", nameof(StatRow.Errors), 140),
            ("Discards in/out per s", nameof(StatRow.Discards), 170), ("Interval", nameof(StatRow.Interval), 90), ("Note", nameof(StatRow.Note), 0));
        statGrid.ItemsSource = stats;
        statGrid.SelectionMode = DataGridSelectionMode.Single;
        Avalonia.Automation.AutomationProperties.SetName(statGrid, "Interface statistics");
        var chart = new TrafficChart { Height = 190 };
        void ShowChart()
        {
            chart.Rates = statGrid.SelectedItem is StatRow r && _history.TryGetValue(r.I.Index, out var h) ? h.ToList() : [];
            chart.InvalidateVisual();
        }

        statGrid.SelectionChanged += (_, _) => ShowChart();

        var discover = Ui.Button("Discover Interfaces", async () =>
        {
            Styling.Theme.SetState(status, null);
            if (agent.Validate() is { } missing)
            {
                status.Text = missing;
                return;
            }

            resolve = agent.Snapshot();
            var wait = TimeSpan.FromSeconds((double)(timeout.Value ?? 3));
            var r = resolve;
            await runner.RunAsync("Walking IF-MIB", async ct =>
            {
                var (t, error) = await r(ct);
                if (t is null) return error!;
                try
                {
                    var list = await SnmpInterfaceMonitor.DiscoverAsync(t, wait, ct);
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        interfaces.Clear();
                        foreach (var i in list) interfaces.Add(new IfRow(i));
                    });
                    return $"{list.Count} interface(s). Select the ones to monitor (Ctrl/Shift for several, at most {MaxMonitored}) and press Start.";
                }
                catch (Exception ex) when (ex is SnmpException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
                {
                    return SnmpInterfaceMonitor.Explain(ex, t, wait);
                }
            });
        }, accent: true);

        Button? start = null;
        Button? stop = null;
        stop = Ui.Button("Stop", () =>
        {
            _stopPoll?.Invoke();
            return Task.CompletedTask;
        });
        start = Ui.Button("Start Monitoring", () =>
        {
            var selected = ifGrid.SelectedItems.OfType<IfRow>().Select(r => r.I).Take(MaxMonitored).ToList();
            if (selected.Count == 0 || resolve is null)
            {
                status.Text = "Discover the interfaces and select at least one.";
                return Task.CompletedTask;
            }

            monitored = selected;
            _last.Clear(); // the loop is not running here
            _history.Clear();
            stats.Clear();
            foreach (var i in monitored) stats.Add(new StatRow(i, null, null));
            var every = TimeSpan.FromSeconds((double)(interval.Value ?? 10));
            var wait = TimeSpan.FromSeconds((double)(timeout.Value ?? 3));
            var r = resolve;
            var cts = new CancellationTokenSource();
            _stopPoll = cts.Cancel;
            var ct = cts.Token;
            start!.IsEnabled = false;
            stop!.IsEnabled = true;
            discover.IsEnabled = false;
            _ = Task.Run(() => PollLoopAsync(r, monitored, every, wait, stats, statGrid, ShowChart, status, ct)).ContinueWith(_ => Dispatcher.UIThread.Post(() =>
            {
                _stopPoll = null;
                cts.Dispose();
                start.IsEnabled = true;
                stop.IsEnabled = false;
                discover.IsEnabled = true;
                status.Text = "Monitoring stopped.";
            }), TaskScheduler.Default);
            return Task.CompletedTask;
        });
        stop.IsEnabled = false;

        var exportCsv = Ui.Button("Export CSV…", () =>
        {
            using var w = new StringWriter(CultureInfo.InvariantCulture);
            CsvExporter.WriteRow(w, ["interface_index", "interface", "time_utc", "status", "interval_s", "in_bps", "out_bps", "in_util_pct", "out_util_pct",
                "in_errors_ps", "out_errors_ps", "in_discards_ps", "out_discards_ps", "note"], ',', true);
            foreach (var i in monitored)
            {
                foreach (var x in _history.GetValueOrDefault(i.Index) ?? [])
                {
                    static string N(double? v) => v?.ToString("0.###", CultureInfo.InvariantCulture) ?? "";
                    CsvExporter.WriteRow(w, [i.Index.ToString(CultureInfo.InvariantCulture), i.Label, x.At.ToString("O", CultureInfo.InvariantCulture), x.Status.ToString(),
                        N(x.Elapsed.TotalSeconds), N(x.InBitsPerSecond), N(x.OutBitsPerSecond), N(x.InUtilisation), N(x.OutUtilisation), N(x.InErrorsPerSecond),
                        N(x.OutErrorsPerSecond), N(x.InDiscardsPerSecond), N(x.OutDiscardsPerSecond), x.Note], ',', true);
                }
            }

            return ToolKit.SaveTextAsync(this, w.ToString(), "interface-statistics.csv");
        });

        var options = new WrapPanel { Children = { SnmpTargetForm.Pair("Interval (s)", interval), SnmpTargetForm.Pair("Timeout (s)", timeout) } };
        var actions = Ui.Row(discover, start, stop, exportCsv);
        var hint = Ui.Explained("Read-only: GET and walks, never SET.",
            "Read-only (GET and walks; never SET). Rates use the agent's sysUpTime between readings, so a slow poll does not distort them; a counter reset, "
                   + "an implausible 32-bit wrap or an agent restart leaves a gap and a note instead of a spike. 64-bit counters are used where the agent has them.");
        var split = new Grid { RowDefinitions = new RowDefinitions("*,6,*,Auto") };
        split.Children.Add(ifGrid);
        var splitter = new GridSplitter { ResizeDirection = GridResizeDirection.Rows };
        Grid.SetRow(splitter, 1);
        split.Children.Add(splitter);
        Grid.SetRow(statGrid, 2);
        split.Children.Add(statGrid);
        Grid.SetRow(chart, 3);
        chart.Margin = new Thickness(0, 6, 0, 0);
        split.Children.Add(chart);
        Content = ToolKit.Layout(new StackPanel { Spacing = 4, Children = { agent.Row, options, hint } }, actions, split, status);
        _dispose = () =>
        {
            runner.Dispose();
            _stopPoll?.Invoke();
        };
    }

    private async Task PollLoopAsync(Func<CancellationToken, Task<(SnmpTarget? Target, string? Error)>> resolve, IReadOnlyList<SnmpInterface> interfaces, TimeSpan every,
        TimeSpan timeout, ObservableCollection<StatRow> stats, DataGrid grid, Action showChart, TextBlock status, CancellationToken ct)
    {
        var (target, error) = await resolve(ct);
        if (target is null)
        {
            Dispatcher.UIThread.Post(() => status.Text = error);
            return;
        }

        var failed = 0;
        var polls = 0;
        using var timer = new PeriodicTimer(every); // a poll longer than the interval skips ticks instead of queueing them
        do
        {
            IReadOnlyList<InterfaceCounters> readings;
            try
            {
                readings = await SnmpInterfaceMonitor.PollAsync(target, interfaces, timeout, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is SnmpException or OperationCanceledException or System.Net.Sockets.SocketException)
            {
                failed++;
                var msg = SnmpInterfaceMonitor.Explain(ex, target, timeout);
                foreach (var i in interfaces) _last.Remove(i.Index); // the next reading starts a new interval: never bridge a gap
                Dispatcher.UIThread.Post(() => status.Text = $"Poll failed: {msg} {failed} failed of {polls + failed}; retrying at the next interval.");
                continue;
            }

            polls++;
            var rows = new List<StatRow>();
            foreach (var c in readings)
            {
                var rate = InterfaceRates.Compute(_last.GetValueOrDefault(c.Index), c); // _last: this loop only
                _last[c.Index] = c;
                rows.Add(new StatRow(interfaces.First(i => i.Index == c.Index), rate.Status == RateStatus.First ? null : rate, c));
            }

            Dispatcher.UIThread.Post(() =>
            {
                foreach (var r in rows.Where(r => r.R is not null))
                {
                    // history is touched on the UI thread only (chart and export read it there)
                    var h = _history.TryGetValue(r.I.Index, out var list) ? list : _history[r.I.Index] = [];
                    h.Add(r.R!);
                    if (h.Count > MaxHistory) h.RemoveAt(0);
                }

                var selected = (grid.SelectedItem as StatRow)?.I.Index;
                stats.Clear();
                foreach (var r in rows) stats.Add(r);
                if (selected is not null) grid.SelectedItem = stats.FirstOrDefault(r => r.I.Index == selected);
                else if (stats.Count > 0) grid.SelectedIndex = 0;
                showChart();
                status.Text = $"Polling {interfaces.Count} interface(s) every {every.TotalSeconds:0.#} s · {polls} poll(s)" + (failed > 0 ? $", {failed} failed" : "")
                              + $" · last {DateTime.Now:HH:mm:ss}";
            });
        }
        while (await NextAsync(timer, ct));
    }

    private static async Task<bool> NextAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try
        {
            return await timer.WaitForNextTickAsync(ct);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>Cancels the running operation (the window closed).</summary>
    public void Dispose() => _dispose?.Invoke();
}
