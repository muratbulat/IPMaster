using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → TCP Connection Tester (D-074).</summary>
internal sealed class TcpTesterWindow : Window
{
    public sealed record Row(string Target, string Ip, int Successes, int Failures, int Consecutive, string LastSuccess, string LastFailure, string LastResult,
        string Average, string Min, string Max, TcpTargetStats Stats);

    private const int MaxLogLines = 2000;
    private static readonly CultureInfo Cur = CultureInfo.CurrentCulture;

    public TcpTesterWindow(string? target = null)
    {
        Title = "TCP Connection Tester";
        Width = 1100;
        Height = 760;
        MinWidth = 640;
        MinHeight = 440;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var stats = new Dictionary<string, TcpTargetStats>(StringComparer.OrdinalIgnoreCase);
        var pending = new ConcurrentQueue<TcpAttempt>();
        var log = new LinkedList<string>();
        var skippedCount = 0;

        var targets = ToolKit.Text("Targets", "hosts or addresses, separated by commas or new lines", text: target ?? "");
        targets.AcceptsReturn = true;
        targets.Height = 64;
        targets.TextWrapping = TextWrapping.Wrap;
        var ports = ToolKit.Text("Ports", "443 or 80, 443, 8000-8010", 260, "443");
        var sources = new List<string> { "Automatic (the OS chooses the route and source)" };
        try
        {
            sources.AddRange(NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(u => $"{u.Address} ({n.Name})")));
        }
        catch (NetworkInformationException)
        {
            // only Automatic
        }

        var source = ToolKit.Combo("Source address", sources, 0, 360);
        var timeout = ToolKit.Number(3000, 100, 60000, "Timeout in milliseconds");
        timeout.Increment = 100;
        var concurrency = ToolKit.Number(16, 1, 256, "Concurrency");
        var mode = ToolKit.Combo("Mode", ["Single pass", "Continuous"], 0, 160);
        var interval = ToolKit.Number(5, 1, 3600, "Interval in seconds");
        var dns = ToolKit.Combo("DNS refresh", ["Resolve before every attempt", "Resolve once per run"], 0, 240);
        var f = new Form();
        f.Add("Targets", targets);
        f.Add("Ports", ports);
        f.Add("Source Address", source);
        f.Add("Timeout (ms) / Concurrency", Ui.Row(timeout, concurrency));
        f.Add("Mode / Interval (s)", Ui.Row(mode, interval));
        f.Add("DNS", dns);
        f.Full(Form.Hint("Each attempt opens a TCP connection and closes it at once; no data is sent. Failures are connection failures, not packet loss. "
                         + "A source address binds the local side only; the OS routing table still decides the path. On Windows a refused port is retried by the OS for about 2 s, so a shorter timeout can show it as a timeout."));
        var error = new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };
        f.Full(error);

        var grid = Ui.Grid(("Target", "Target", 200), ("Connected IP", "Ip", 170), ("OK", "Successes", 60), ("Failed", "Failures", 80), ("Consecutive Failures", "Consecutive", 175),
            ("Last Success", "LastSuccess", 120), ("Last Failure", "LastFailure", 120), ("Last Result", "LastResult", 220), ("Avg ms", "Average", 80), ("Min ms", "Min", 80), ("Max ms", "Max", 80));
        Avalonia.Automation.AutomationProperties.SetName(grid, "Targets summary");
        var chart = new ConnectChart();
        var logBox = ToolKit.ReportBox("Attempt log");
        var tabs = new TabControl
        {
            Classes = { "compact" },
            Items =
            {
                new TabItem { Header = "Summary", Content = new Grid { RowDefinitions = new RowDefinitions("*,180"), Children = { grid, chart } } },
                new TabItem { Header = "Attempts", Content = logBox },
            },
        };
        Grid.SetRow(chart, 1);
        grid.SelectionChanged += (_, _) => chart.Stats = (grid.SelectedItem as Row)?.Stats;

        string Ms(double? v) => v is { } x ? x.ToString("0.0", Cur) : "";
        string Time(DateTimeOffset? t) => t is { } x ? x.ToLocalTime().ToString("HH:mm:ss", Cur) : "";
        void Flush()
        {
            if (pending.IsEmpty) return;
            while (pending.TryDequeue(out var a))
            {
                if (!stats.TryGetValue(a.Target.Key, out var s)) stats[a.Target.Key] = s = new TcpTargetStats(a.Target);
                s.Add(a);
                log.AddLast(string.Create(Cur, $"{a.At.ToLocalTime():HH:mm:ss.fff}  {a.Target.Key,-30} {TcpTestPlan.Describe(a.Outcome),-26} ip {a.ConnectedTo ?? "-"}  local {a.LocalEndpoint ?? "-"}  dns {Ms(a.DnsDuration?.TotalMilliseconds)} ms  connect {Ms(a.ConnectDuration?.TotalMilliseconds)} ms  {a.SocketError} {a.Detail}"));
                while (log.Count > MaxLogLines) log.RemoveFirst();
            }

            var selected = (grid.SelectedItem as Row)?.Target;
            var rows = stats.Values.Select(s => new Row(s.Target.Key, s.Last?.ConnectedTo ?? "", s.Successes, s.Failures, s.ConsecutiveFailures, Time(s.LastSuccess), Time(s.LastFailure),
                s.Last is { } l ? TcpTestPlan.Describe(l.Outcome) + (l.SocketError is { } e ? $" ({e})" : "") : "", Ms(s.AverageMs), Ms(s.MinMs), Ms(s.MaxMs), s)).ToList();
            grid.ItemsSource = rows;
            grid.SelectedItem = rows.FirstOrDefault(r => r.Target == selected) ?? rows.FirstOrDefault();
            chart.Stats = (grid.SelectedItem as Row)?.Stats;
            chart.InvalidateVisual();
            logBox.Text = string.Join('\n', log);
        }

        var timer = new DispatcherTimer(TimeSpan.FromMilliseconds(250), DispatcherPriority.Background, (_, _) => Flush());
        timer.Start();

        var start = Ui.Button("Start", async () =>
        {
            error.Text = "";
            if (!TcpTestPlan.TryBuild(targets.Text, ports.Text, out var plan, out var e))
            {
                error.Text = e;
                return;
            }

            IPAddress? src = null;
            if (source.SelectedIndex > 0 && source.SelectedItem is string s) src = IPAddress.Parse(s[..s.IndexOf(' ', StringComparison.Ordinal)]);
            var options = new TcpRunOptions
            {
                Source = src, Timeout = TimeSpan.FromMilliseconds((double)(timeout.Value ?? 3000)), Concurrency = (int)(concurrency.Value ?? 16),
                Continuous = mode.SelectedIndex == 1, Interval = TimeSpan.FromSeconds((double)(interval.Value ?? 5)),
                DnsRefresh = dns.SelectedIndex == 1 ? DnsRefresh.OncePerRun : DnsRefresh.EveryAttempt,
            };
            await runner.RunAsync(options.Continuous ? $"Testing {plan.Count} target(s) every {options.Interval.TotalSeconds:0} s" : $"Testing {plan.Count} target(s)", async ct =>
            {
                await new TcpConnectionTester().RunAsync(plan, options, pending.Enqueue, _ => Interlocked.Increment(ref skippedCount), ct);
                return "Stopped.";
            });
            Flush(); // UI thread: the statistics are only touched here
            var skippedText = skippedCount > 0 ? string.Create(Cur, $"; {skippedCount} round(s) skipped because the previous attempt was still running.") : ".";
            status.Text = string.Create(Cur, $"Stopped. {stats.Values.Sum(x => x.Successes)} connected, {stats.Values.Sum(x => x.Failures)} failed{skippedText}");
        }, accent: true);
        var stop = Ui.Button("Stop", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        stop.IsEnabled = false;
        runner.BusyChanged += (_, _) =>
        {
            start.IsEnabled = !runner.IsBusy;
            stop.IsEnabled = runner.IsBusy;
        };
        var clear = Ui.Button("Clear", () =>
        {
            stats.Clear();
            log.Clear();
            pending.Clear();
            skippedCount = 0;
            grid.ItemsSource = null;
            chart.Stats = null;
            chart.InvalidateVisual();
            logBox.Text = "";
            return Task.CompletedTask;
        });
        string Csv()
        {
            var sb = new StringBuilder();
            Core.Results.CsvExporter.WriteRow(new StringWriter(sb), ["Time", "Target", "Port", "Outcome", "Connected IP", "Local endpoint", "DNS ms", "Connect ms", "Socket error", "Detail"], ',', true);
            foreach (var a in stats.Values.SelectMany(s => s.History).OrderBy(a => a.At))
            {
                var w = new StringWriter(sb);
                Core.Results.CsvExporter.WriteRow(w, [a.At.ToString("o", CultureInfo.InvariantCulture), a.Target.Host, a.Target.Port.ToString(CultureInfo.InvariantCulture), a.Outcome.ToString(),
                    a.ConnectedTo ?? "", a.LocalEndpoint ?? "", a.DnsDuration?.TotalMilliseconds.ToString("0.0", CultureInfo.InvariantCulture) ?? "",
                    a.ConnectDuration?.TotalMilliseconds.ToString("0.0", CultureInfo.InvariantCulture) ?? "", a.SocketError ?? "", a.Detail], ',', true);
            }

            return sb.ToString();
        }

        var actions = Ui.Row(start, stop, clear, ToolKit.CopyButton(this, () => logBox.Text ?? "", "Copy Log"), ToolKit.ExportButton(this, Csv, "tcp-attempts.csv", "Export CSV…"));
        Content = ToolKit.Layout(f.Grid, actions, tabs, status);
        Closed += (_, _) =>
        {
            timer.Stop();
            runner.Dispose();
        };
    }

    /// <summary>Connection time of the selected target's recent attempts; failures as markers on the top edge.</summary>
    private sealed class ConnectChart : Styling.ThemedControl
    {
        public TcpTargetStats? Stats { get; set; }

        public override void Render(DrawingContext context)
        {
            var b = Bounds;
            var fg = Brush(Styling.Theme.Keys.ChartText);
            var accent = Brush(Styling.Theme.Keys.Series1);
            context.DrawRectangle(null, Pen(Styling.Theme.Keys.Border), new Rect(b.Size).Deflate(0.5));
            var history = Stats?.History ?? [];
            var typeface = new Typeface(FontFamily.Default);
            void Text(string s, Point p) => context.DrawText(new FormattedText(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, typeface, 11, fg), p);
            if (history.Count == 0)
            {
                Text("Select a target to see its connection times (✕ = connection failure).", new Point(8, 8));
                return;
            }

            var max = Math.Max(1, history.Where(a => a.ConnectDuration is not null).Select(a => a.ConnectDuration!.Value.TotalMilliseconds).DefaultIfEmpty(1).Max());
            var plot = new Rect(40, 20, Math.Max(10, b.Width - 50), Math.Max(10, b.Height - 34));
            Text(max.ToString("0", CultureInfo.CurrentCulture) + " ms", new Point(4, plot.Top - 2));
            Text("0", new Point(4, plot.Bottom - 12));
            Text($"{Stats!.Target.Key}: connection time of the last {history.Count} attempts; ✕ = connection failure", new Point(plot.Left, 2));
            var step = plot.Width / Math.Max(1, history.Count - 1);
            Point? prev = null;
            var line = new Pen(accent, 1.5);
            var fail = Pen(Styling.Theme.Keys.ChartCritical, 1.5);
            for (var i = 0; i < history.Count; i++)
            {
                var a = history[i];
                var x = plot.Left + (i * step);
                if (a.Outcome == TcpOutcome.Connected && a.ConnectDuration is { } d)
                {
                    var p = new Point(x, plot.Bottom - (d.TotalMilliseconds / max * plot.Height));
                    if (prev is { } q) context.DrawLine(line, q, p);
                    context.DrawEllipse(accent, null, p, 2, 2);
                    prev = p;
                }
                else
                {
                    context.DrawLine(fail, new Point(x - 3, plot.Top - 3), new Point(x + 3, plot.Top + 3));
                    context.DrawLine(fail, new Point(x - 3, plot.Top + 3), new Point(x + 3, plot.Top - 3));
                    prev = null;
                }
            }
        }
    }
}
